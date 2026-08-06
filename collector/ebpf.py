import os
import time
import pwd
import threading
from typing import Dict, Any
from lotl_edr.collector.base import BaseCollector
from lotl_edr.utils.logger import setup_logger

logger = setup_logger("collector.ebpf")

BCC_AVAILABLE = False
try:
    from bcc import BPF
    import ctypes
    BCC_AVAILABLE = True
except ImportError:
    pass

EBPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <uapi/linux/limits.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    char exe[128];
    char details[256];
    u32 event_type;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid;
    data.gid = uid_gid >> 32;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.exe, sizeof(data.exe), args->filename);

    data.event_type = 1;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 2;

    struct sockaddr_in addr_in = {};
    bpf_probe_read_user(&addr_in, sizeof(addr_in), (void *)args->uservaddr);

    if (addr_in.sin_family == AF_INET) {
        u32 ip = addr_in.sin_addr.s_addr;
        u16 port = addr_in.sin_port;

        unsigned char bytes[4];
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;

        u16 port_hs = ((port >> 8) & 0xFF) | ((port & 0xFF) << 8);

        data.details[0] = bytes[0];
        data.details[1] = bytes[1];
        data.details[2] = bytes[2];
        data.details[3] = bytes[3];
        data.details[4] = (port_hs >> 8) & 0xFF;
        data.details[5] = port_hs & 0xFF;
    }

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

int kprobe__do_unlinkat(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 4;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

class EBPFCollector(BaseCollector):
    def __init__(self, config: Dict[str, Any], callback=None):
        super().__init__("ebpf", config, callback)
        self.thread = None
        self.bpf = None
        # FIX: unlike NetworkCollector (which dedupes via seen_connections),
        # the eBPF sys_enter_connect probe fires on every connect() syscall
        # with no dedup at all. Some processes retry connect() multiple
        # times on the same socket (non-blocking EINPROGRESS, DNS/NTP
        # lookups), which without dedup fires several near-identical
        # events in the same second -- each adding risk and inflating a
        # chain's confidence score purely from noise, not real activity.
        self._seen_connections = set()

    def start(self) -> None:
        self.running = True
        if BCC_AVAILABLE and os.geteuid() == 0:
            try:
                logger.info("Initializing BCC eBPF engine...")
                self.bpf = BPF(text=EBPF_PROGRAM)

                def print_event(cpu, data, size):
                    event = self.bpf["events"].event(data)
                    self._process_ebpf_event(event)

                self.bpf["events"].open_perf_buffer(print_event, page_cnt=self.config.get("perf_page_cnt", 64))

                self.thread = threading.Thread(target=self._ebpf_loop, daemon=True)
                self.thread.start()
                logger.info("eBPF Collector started in kernel space.")
            except Exception as e:
                logger.error(f"Failed to load eBPF program: {e}. Falling back to simulation mode.")
                self.bpf = None
                self._start_simulation()
        else:
            if not BCC_AVAILABLE:
                logger.warning("BCC Python library not installed. Falling back to eBPF simulation mode.")
            elif os.geteuid() != 0:
                logger.warning("Agent not running as root. Root privileges are required for eBPF. Falling back to simulation mode.")
            self._start_simulation()

    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        logger.info("eBPF Collector stopped.")

    def _ebpf_loop(self) -> None:
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error polling eBPF buffer: {e}")
                time.sleep(1)

    def _resolve_username(self, uid) -> str:
        """
        FIX: same as AuditdCollector's earlier fix -- was synthesizing
        placeholders like "user_1001" instead of resolving the real
        account name. Any containment action triggered by an eBPF-
        sourced event (e.g. A20 lateral movement, A07 reverse shell)
        would otherwise silently target a nonexistent username.
        """
        try:
            return pwd.getpwuid(int(uid)).pw_name
        except (ValueError, TypeError, KeyError):
            return f"uid_{uid}"

    def _process_ebpf_event(self, event) -> None:
        # FIX: filter out kernel-thread/init noise (pid<=2, no comm).
        # Real eBPF traces every syscall system-wide unfiltered, which
        # includes systemd/init's own routine connect/unlink activity
        # (pid=1/2, empty exe). None of the 40 YAML rules match this
        # noise, but it inflates raw event counts and clutters the CLI
        # monitor with meaningless entries.
        if event.pid <= 2:
            return

        event_type_map = {
            1: "process_exec", 2: "network_connect", 3: "ptrace",
            4: "file_delete", 5: "privilege_change"
        }

        ev_type = event_type_map.get(event.event_type, "unknown")

        exe_str = event.exe.decode("utf-8", errors="ignore").strip()
        comm_str = event.comm.decode("utf-8", errors="ignore").strip()
        # FIX: connect/unlink probes never populate data.exe (only the
        # execve probe does) -- fall back to comm (always populated by
        # bpf_get_current_comm in all three probes) so cmdline isn't
        # blank for network_connect/file_delete events.
        display_cmd = exe_str or comm_str

        raw_event = {
            "event_type": ev_type,
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "gid": event.gid,
            "username": self._resolve_username(event.uid),
            "exe": exe_str,
            "cmdline": display_cmd,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "ebpf_hooked": True
        }

        if event.event_type == 2:
            details = bytes(event.details)
            if len(details) >= 6:
                ip = f"{details[0]}.{details[1]}.{details[2]}.{details[3]}"
                port = (details[4] << 8) | details[5]
                raw_event["dst_ip"] = ip
                raw_event["dst_port"] = port
                raw_event["cmdline"] = f"connect: Outbound connection to {ip}:{port}"

                # FIX: dedup repeated connect() calls to the same
                # pid+dst_ip+dst_port within this collector's lifetime.
                dedup_key = (event.pid, ip, port)
                if dedup_key in self._seen_connections:
                    return
                self._seen_connections.add(dedup_key)
                if len(self._seen_connections) > 5000:
                    self._seen_connections.clear()

        self.emit(raw_event)

    def _start_simulation(self) -> None:
        self.thread = threading.Thread(target=self._run_simulation_loop, daemon=True)
        self.thread.start()
        logger.info("eBPF Collector started in simulation mode.")

    def _run_simulation_loop(self) -> None:
        # FIX: this used to automatically build 3 hardcoded fake events
        # (whoami / nc reverse-shell / pkexec) and emit them below on
        # EVERY fallback to simulation mode -- including every daemon
        # restart, once it was discovered that BCC 0.29.1 (Ubuntu 24.04's
        # packaged version) cannot compile against kernel 7.0.0's
        # updated `struct filename` layout. This meant every restart
        # silently wrote a fabricated CRITICAL incident into the real
        # GRC evidence ledger. sim_events is now empty -- the collector
        # still "runs" for architectural completeness, but no longer
        # manufactures false evidence. Real eBPF coverage on this kernel
        # is a known, documented limitation (kernel/BCC incompatibility).
        logger.warning(
            "eBPF running in simulation mode (real BCC compilation failed) -- "
            "no synthetic events will be injected. See known limitations."
        )
        sim_events = []

        for ev in sim_events:
            if not self.running:
                break
            time.sleep(1)
            self.emit(ev)

        while self.running:
            time.sleep(1)

    def _get_iso_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
