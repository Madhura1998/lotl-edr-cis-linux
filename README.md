Real-Time LotL Detection and Containment on CIS-Hardened Linux

A behavior-based Linux security framework for detecting, correlating, containing, and documenting Living-off-the-Land (LotL) attacks on a CIS-hardened Ubuntu Linux system.

The framework combines multi-source Linux telemetry, eBPF-based runtime monitoring, YAML-driven detection rules, attack-chain correlation, risk and confidence scoring, automated containment, forensic evidence collection, CIS configuration-drift monitoring, and real-time GRC evidence generation.

Overview

Living-off-the-Land (LotL) attacks abuse legitimate operating-system utilities such as `bash`, `curl`, `wget`, `python3`, `cron`, and `ssh` to perform malicious activities. Because these utilities are also routinely used by legitimate administrators, malicious activity can resemble normal administrative behavior and may be difficult to identify using traditional signature-based approaches.
This project implements a behavior-based detection and automated containment framework for a CIS Level 1 hardened Ubuntu 24.04 LTS environment.

Key Capabilities
- Multi-source Linux security telemetry collection
- eBPF-based runtime monitoring
- auditd monitoring
- Authentication and privilege-event monitoring
- Process and network visibility
- Event normalization
- YAML-based behavioral detection rules
- MITRE ATT\&CK mapping
- Session-aware event correlation
- Multi-stage attack-chain detection
- Risk and confidence scoring
- Automated containment
- Forensic evidence collection
- SHA-256 hash-chained GRC evidence
- NIST SP 800-53 mapping
- SOX ITGC mapping
- CIS Level 1 configuration-drift monitoring
- Real-time CLI monitoring
- Web-based SOC dashboard
- MTTD, MTTC, and processing-latency measurement

 Architecture


                CIS-Hardened Ubuntu Host

                            |

      +----------+----------+----------+----------+

       |          |          |          |          |

  
   auditd    auth.log    /proc       eBPF     Network


     |          |          |          |          |

     +----------+----------+----------+----------+

                            |

                   +--------v--------+

                  | Event Normalizer|

                   +--------+--------+

                            |

                   +--------v--------+

                   |   Rule Engine   |

                   |  YAML Detection |

                    +--------+--------+

                             |

                    +--------v--------+

                   | Session State   |

                   | + Correlator    |

                   +--------+--------+

                            |
                   +--------v--------+

                    | Risk \& Confidence|

                   |     Scoring      |

                    +--------+--------+

                             |

            +----------------+----------------+

            |                |                |

            v                v                v

      Containment        Forensics       GRC Evidence
        Engine            Engine            Engine

            |                |                |

            +----------------+----------------+

                             |

                    +--------v--------+

                    |   CIS Drift      |

                    |   Detection      |

                    +--------+--------+

                             |

                    +--------v--------+

                    | SOC Dashboard / |

                    | CLI Monitoring  |

                    +-----------------+


Telemetry Collection

The framework collects telemetry from five complementary sources.

1. auditd: 
Linux audit events are collected to provide visibility into process execution, file access, and other security-relevant system activity.

2. Authentication Logs: 
Authentication and privilege-related events are collected from Linux authentication logs, including SSH and sudo activity.

3. /proc : 
The /proc filesystem is used to obtain process-level information such as:
Running processes

Command lines

Process ownership

Process relationships

Session information

Active terminals

4. eBPF: 
The eBPF collector provides kernel-level runtime visibility using BCC-based tracing.
The framework monitors activities including:
execve
connect
File deletion activity

5. Network:
Network telemetry is collected from Linux socket information and associated with processes to provide visibility into suspicious outbound and inbound activity.

Event Normalization:
Events collected from different telemetry sources are converted into a common normalized event structure.
Normalization allows events from auditd, authentication logs, /proc, eBPF, and network monitoring to be processed consistently by the detection and correlation components.

Detection Engine

Detection rules are stored as YAML files under:
rule\_engine/rules/
The rules are organized into two categories.
Attack Rules
The repository contains attack-oriented rules covering activities such as:
SSH brute force
Payload download
Shell and payload execution
Reverse shells
Privilege escalation
Cron persistence
Startup persistence
Credential-file access
Data exfiltration
Log deletion
Security-tool disabling
Lateral movement
Encoding and obfuscation
Data staging
Rapid attack chains
Bulk file operations

Suspicious / Reconnaissance Rules"
The repository also contains rules for behaviors including:
User enumeration
Process discovery
Network enumeration
Port scanning
Sensitive-file searching
External downloads
Privilege escalation attempts
Encoding and obfuscation
Service discovery
Archive and compression activity
Environment inspection
Command-history inspection
Permission probing
Low-volume SSH brute force
Reconnaissance bursts
High-frequency file operations

The rule engine is designed around modular YAML rules rather than large hard-coded conditional blocks, allowing additional detection logic to be added more easily.

MITRE ATT\&CK Mapping
Detected behaviors are associated with relevant MITRE ATT\&CK techniques.
This allows individual security events and correlated attack chains to be interpreted in the context of known adversarial behavior.

Attack-Chain Correlation
LotL attacks are often composed of several individually legitimate commands.
The framework therefore correlates related events into attack chains instead of treating every event independently.

Correlation can use attributes such as:
Session ID
Process ID
Parent process ID
Username
IP address
Terminal / TTY

This enables multi-stage attack behavior to be identified even when individual commands appear legitimate in isolation.

Risk and Confidence Scoring
The framework applies risk and confidence scoring to correlated attack chains. 
The risk engine uses time-based decay so that older events gradually become less influential when new suspicious activity is not observed
The confidence engine considers factors including:

Telemetry-source diversity
MITRE ATT\&CK techniques
Existing risk score
Attack-chain length
Detection-rule severity

CIS configuration drift:

The confidence score ranges from 0 to 100.
Automated Containment
Containment actions are triggered when a correlated attack chain reaches predefined confidence thresholds.

High-Confidence Attack
For high-confidence attacks, the framework can perform containment actions such as:


Terminating suspicious processes
Blocking malicious network communication
Quarantining suspicious executable files

Critical Attack
For critical attacks, the framework can additionally perform actions such as:
Locking the affected user account
Terminating active sessions

Collecting additional forensic evidence
An administrative allowlist is used before destructive account or session containment actions.
Forensic Evidence Collection
For critical containment events, the framework collects forensic information to support investigation.

Collected artifacts can include:
Process information
Process tree
Open files
Network sockets
Firewall state
Memory mappings
Process environment
Cron configuration
Attack timeline

The evidence is packaged for subsequent forensic analysis.

GRC Evidence Generation
The GRC evidence engine generates a tamper-evident evidence ledger.
The ledger uses SHA-256 hash chaining, where each record contains a reference to the previous record's hash.
This allows modifications to existing evidence records to be detected.

Security events are mapped to:
MITRE ATT\&CK techniques
NIST SP 800-53 controls
SOX ITGC domains

This connects technical security events with governance, risk, compliance, and audit requirements.

CIS Configuration Drift Monitoring
The framework continuously compares the system configuration against a predefined CIS Level 1 baseline.
The implemented checks cover security areas including:
Process hardening
System administration
Firewall configuration
Logging
auditd
SSH
PAM
Cron
Network settings
User and account security

The drift detector provides continuous visibility into configuration changes that may affect the hardened security posture.

Dashboard
The project includes a web-based SOC dashboard providing visibility into:
Security status
Live alerts
Attack chains
Containment actions
CIS compliance
Configuration drift
CPU and memory usage
Security metrics

A CLI live-monitoring component is also included for real-time detection visibility.

Testing
The framework was evaluated using controlled LotL attack scenarios including:

SSH brute-force activity
Privilege escalation
Persistence
Payload download and execution
Command obfuscation
Credential and sensitive-file access
Log tampering
Data staging and exfiltration
Multi-stage attack chains

Testing was performed alongside background workloads including web traffic, concurrent SSH sessions, scheduled tasks, and CPU/memory workloads.

