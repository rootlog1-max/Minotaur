# 🐂 Minotaur — The Twin Credential Tester

**Battle-tested with 32+ million tasks**  
**Maximum observed RAM usage: 8GB**

Minotaur is a high-performance credential testing tool built for large-scale security assessments.  
It is designed with efficiency, stability, and resilience in mind to ensure:

> **No one credential left behind** 🔐

Fast, resource-aware, and engineered to survive long-running operations.

---

## 🚀 Features

- **Multi-Protocol Support**  
  Supports SSH, FTP, and Telnet (easily extensible to additional protocols)

- **Smart Resource Management**  
  RAM-aware batching for massive credential combinations

- **Auto-Resume**  
  Seamlessly continue scans from the last saved state

- **Smart Blacklisting**  
  Automatically skips unstable or problematic hosts

- **High Performance**  
  Proven with 32 million+ credential tasks

- **Persistent Workers**  
  Efficient per-host connection pooling

- **Command Execution**  
  Execute custom commands after successful authentication

---

## 📦 Installation

### Prerequisites
- Go **1.19+**
- `proto.go` (required for protocol implementation)

### Build from Source
```bash
git clone https://github.com/rootlog1-max/Minotaur.git
cd minotaur
go build -o minotaur minotaur.go proto.go
```

---

## 🎯 Quick Start

### Basic Usage
```bash
./minotaur -t targets.txt -u users.txt -p passwords.txt --ssh
```

### Single Credential Test
```bash
./minotaur -T 192.168.1.1 -U admin -P password123 --ssh
```

### CIDR / Range Scanning
```bash
./minotaur -T 192.168.1.0/24 -u users.txt -p passwords.txt --ssh
./minotaur -T 192.168.1.1-100 -u users.txt -p passwords.txt --ssh
```

---

## ⚙️ Comprehensive Usage

### Required Parameters

**File-based inputs**
```text
-t FILE     Targets file (one per line)
-u FILE     Usernames file (one per line)
-p FILE     Passwords file (one per line)
```

**OR single values**
```text
-T TARGET     Single target (IP / CIDR / range)
-U USERNAME   Single username
-P PASSWORD   Single password
```

---

### Protocol Selection  
*(At least one protocol must be enabled)*

```text
--ssh       SSH protocol (default port: 22)
--ftp       FTP protocol (default port: 21)
--telnet    Telnet protocol (default port: 23)
```

---

## 🧠 Advanced Configuration

### Threading & Concurrency
```text
--threads=100        Maximum persistent workers (default: 50)
--max-per-host=5     Maximum concurrent tasks per host (default: 2)
```

### Timing & Retry Control
```text
--delay=3.0          Base delay between tasks (seconds)
--delay-retry=5.0    Retry delay for failed attempts
--retries=3          Maximum retries per credential
--timeout=5.0        Connection timeout (seconds)
```

### Smart Blacklist Configuration
```text
--consecutive-fn=4   Max consecutive false negatives before blacklisting
--total-fn=10        Max total false negatives before blacklisting
```

### Resource Management
```text
--ram=2GB            RAM limit (KB / MB / GB, 0 = unlimited)
--exponential        Enable exponential backoff for retries
```

### Output & Resume
```text
-o results.csv
--no-resume
--force-resume
```

### Debugging & Automation
```text
--debug
--command="whoami"
--script=wrapper.sh
--mute
```

---

## 🔌 Custom Ports

### Single Protocol
```bash
./minotaur -t targets.txt -u users.txt -p passwords.txt --ssh --port=2222
```

### Multi-Protocol (shared port)
```bash
./minotaur -t targets.txt -u users.txt -p passwords.txt --ssh --ftp --port=2222
```

---

## 📊 Examples

### Example 1 — Large-Scale SSH Testing
```bash
./minotaur   -t target-list.txt   -u common-users.txt   -p rockyou.txt   --ssh   --threads=200   --max-per-host=3   --ram=4GB   --script=./proxy-rotator.py   -o ssh-results.csv
```

### Example 2 — ML-Enhanced Credential Testing
```bash
./minotaur   -T 10.0.0.0/24   --ssh   --script=./ml-predictor.py   --debug   -o ml-results.csv
```

### Example 3 — Multi-Protocol Scan
```bash
./minotaur   -t targets.txt   -u users.txt   -p passwords.txt   --ssh --ftp --telnet   --threads=150   --max-per-host=2   --ram=2GB   --exponential   -o multi-protocol-results.csv
```

---

## 🔧 File Formats

### Targets (`targets.txt`)
```text
192.168.1.1
192.168.1.100
10.0.0.5
domain.com
```

### Usernames (`users.txt`)
```text
admin
root
user
administrator
guest
```

### Passwords (`passwords.txt`)
```text
password
123456
admin
password123
letmein
```

---

## 📈 Output Format

Results are stored in CSV format with the following columns:
```text
timestamp        ISO 8601 timestamp
target           Target host or IP
username         Username tested
password         Password tested
protocol         ssh / ftp / telnet
port             Port number
status           success / auth-failed / timeout / error
latency          Connection latency (seconds)
error            Error message (if any)
command_output   Output from --command (if used)
```

---

## 🛡️ Smart Features

### Auto-Resume
- Progress saved automatically to `progress.json`
- Resume interrupted scans using the same command
- Configuration hash ensures consistency
- Use `--no-resume` to start fresh

### Resource-Aware Batching
- Dynamically splits tasks based on RAM limit
- Prevents memory exhaustion
- Use `--ram=0` for unlimited (legacy) mode

### Smart Blacklisting
- Tracks consecutive and total false negatives
- Automatically blacklists unstable hosts
- Blacklist resets on successful authentication

---

## 🐛 Debugging

Enable debug mode:
```bash
./minotaur -t targets.txt -u users.txt -p passwords.txt --ssh --debug
```

Memory usage reports are displayed at the end of each run.

---

## ⚠️ Important Notes

- Use `--ram` for scans exceeding 6 million combinations
- Workers are dedicated per host (no task stealing)
- `proto.go` is required for actual protocol testing
- Use `Ctrl+C` to gracefully stop and save progress
- Resume is allowed even with different configurations

---

## 🆘 Troubleshooting

**"No protocol enabled"**  
→ Specify at least one protocol: `--ssh`, `--ftp`, or `--telnet`

**RAM limit exceeded**  
→ Increase `--ram` or reduce credential combinations

**Config hash mismatch**  
→ Use `--force-resume` or `--no-resume`

**File not found**  
→ Ensure all input files exist and are readable

---

## 📝 License & Disclaimer

Authorized use only.

This tool is intended **exclusively for authorized security testing**.  
The author is not responsible for misuse or any damage caused by this tool.

---

## 🔗 Dependencies

- `proto.go` — Protocol implementation
- Go standard library

---

**Minotaur — No one credential left behind 🔐**
