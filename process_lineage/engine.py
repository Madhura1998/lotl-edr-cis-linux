import time
from typing import Dict, List, Any, Optional

class ProcessNode:
    def __init__(self, pid: int, ppid: int, exe: str, cmdline: str):
        self.pid: int = pid
        self.ppid: int = ppid
        self.exe: str = exe
        self.cmdline: str = cmdline
        self.status: str = "active"
        self.created_at: float = time.time()
        self.exit_time: Optional[float] = None
        self.children: List[int] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid, "ppid": self.ppid, "exe": self.exe, "cmdline": self.cmdline,
            "status": self.status, "created_at": self.created_at, "exit_time": self.exit_time,
            "children": list(self.children)
        }

class ProcessLineageEngine:
    def __init__(self):
        self.nodes: Dict[int, ProcessNode] = {}

    def add_process(self, pid: int, ppid: int, exe: str, cmdline: str) -> None:
        if pid in self.nodes and self.nodes[pid].status == "active":
            logger_node = self.nodes[pid]
            logger_node.status = "exited"
            logger_node.exit_time = time.time()

        node = ProcessNode(pid, ppid, exe, cmdline)
        self.nodes[pid] = node

        if ppid not in [0, 1, -1] and ppid in self.nodes:
            parent = self.nodes[ppid]
            if pid not in parent.children:
                parent.children.append(pid)

    def terminate_process(self, pid: int) -> None:
        if pid in self.nodes:
            node = self.nodes[pid]
            node.status = "exited"
            node.exit_time = time.time()

    def get_ancestors(self, pid: int) -> List[Dict[str, Any]]:
        ancestors = []
        curr_pid = pid
        visited = set()

        while curr_pid in self.nodes:
            if curr_pid in visited:
                break
            visited.add(curr_pid)

            node = self.nodes[curr_pid]
            if curr_pid != pid:
                ancestors.append(node.to_dict())

            curr_pid = node.ppid
            if curr_pid in [0, 1, -1]:
                break

        return ancestors

    def get_descendants(self, pid: int, include_exited: bool = True) -> List[int]:
        descendants = []
        queue = [pid]
        visited = set()

        while queue:
            curr_pid = queue.pop(0)
            if curr_pid in visited:
                continue
            visited.add(curr_pid)

            if curr_pid in self.nodes:
                node = self.nodes[curr_pid]
                for child_pid in node.children:
                    if child_pid in self.nodes:
                        child = self.nodes[child_pid]
                        if include_exited or child.status == "active":
                            descendants.append(child_pid)
                            queue.append(child_pid)
        return descendants

    def get_process_tree_graph(self, root_pid: int) -> Optional[Dict[str, Any]]:
        if root_pid not in self.nodes:
            return None

        node = self.nodes[root_pid]
        children_trees = []
        for child_pid in node.children:
            child_tree = self.get_process_tree_graph(child_pid)
            if child_tree:
                children_trees.append(child_tree)

        return {
            "pid": node.pid, "ppid": node.ppid, "exe": node.exe, "cmdline": node.cmdline,
            "status": node.status, "children": children_trees
        }

    def prune_old_nodes(self, max_age_sec: float = 300.0) -> None:
        now = time.time()
        to_delete = []

        for pid, node in self.nodes.items():
            if node.status == "exited" and node.exit_time and (now - node.exit_time > max_age_sec):
                active_descendants = self.get_descendants(pid, include_exited=False)
                if not active_descendants:
                    to_delete.append(pid)

        for pid in to_delete:
            node = self.nodes.pop(pid, None)
            if node and node.ppid in self.nodes:
                parent = self.nodes[node.ppid]
                if pid in parent.children:
                    parent.children.remove(pid)
