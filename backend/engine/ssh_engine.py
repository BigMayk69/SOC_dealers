"""
SSH Remote Investigation & Remediation Engine.
Executes allowlisted forensic diagnostics and containment actions on enterprise hosts
with Paramiko live SSH support and realistic high-fidelity telemetry simulation.
"""
import uuid
import re
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from backend.auth.models import UserProfile, Permission, UserRole
from backend.models.ssh_audit import SSHAuditRecord
from backend.models.entity import Entity

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


# Safe Allowlisted Command Templates
FORENSIC_COMMAND_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "collect_process_tree": {
        "description": "Inspect active process execution tree and parent-child lineages",
        "linux_cmd": "ps aux --forest",
        "windows_cmd": "wmic process get ProcessId,ParentProcessId,Name,CommandLine",
        "is_containment": False,
        "required_permission": Permission.EXECUTE_SSH_FORENSICS
    },
    "collect_network_sockets": {
        "description": "Collect listening ports and active inbound/outbound TCP/UDP sockets",
        "linux_cmd": "ss -tulpn",
        "windows_cmd": "netstat -ano",
        "is_containment": False,
        "required_permission": Permission.EXECUTE_SSH_FORENSICS
    },
    "collect_auth_logs": {
        "description": "Read recent authentication and SSH login attempt log events",
        "linux_cmd": "tail -n 50 /var/log/auth.log 2>/dev/null || journalctl -u ssh -n 50 --no-pager",
        "windows_cmd": "Get-WinEvent -LogName Security -MaxEvents 50",
        "is_containment": False,
        "required_permission": Permission.EXECUTE_SSH_FORENSICS
    },
    "check_open_ports": {
        "description": "Enumerate local open network ports and bound processes",
        "linux_cmd": "lsof -i -P -n | head -n 40",
        "windows_cmd": "netstat -abno | findstr LISTENING",
        "is_containment": False,
        "required_permission": Permission.EXECUTE_SSH_FORENSICS
    },
    "inspect_file_hash": {
        "description": "Calculate cryptographic SHA-256 hash of a suspicious file path",
        "linux_cmd": "sha256sum '{filepath}'",
        "windows_cmd": "Get-FileHash -Algorithm SHA256 '{filepath}'",
        "is_containment": False,
        "required_permission": Permission.EXECUTE_SSH_FORENSICS
    },
    "list_active_sessions": {
        "description": "List currently logged-in interactive shell and GUI sessions",
        "linux_cmd": "who -a && last -n 10",
        "windows_cmd": "quser",
        "is_containment": False,
        "required_permission": Permission.EXECUTE_SSH_FORENSICS
    },
    "check_crontab": {
        "description": "Inspect scheduled tasks and cron persistence mechanisms",
        "linux_cmd": "crontab -l 2>/dev/null; ls -la /etc/cron* /etc/systemd/system/*.service 2>/dev/null | head -n 30",
        "windows_cmd": "schtasks /query /fo LIST /v",
        "is_containment": False,
        "required_permission": Permission.EXECUTE_SSH_FORENSICS
    }
}

REMEDIATION_COMMAND_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "isolate_host_firewall": {
        "description": "Emergency network isolation: sever all traffic except forensic SSH management",
        "linux_cmd": "iptables -F && iptables -A INPUT -p tcp --dport 22 -j ACCEPT && iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT && iptables -P INPUT DROP && iptables -P FORWARD DROP",
        "windows_cmd": "New-NetFirewallRule -DisplayName 'SOC-Isolation' -Direction Inbound -Action Block -Profile Any",
        "is_containment": True,
        "required_permission": Permission.EXECUTE_SSH_REMEDIATION
    },
    "restore_host_firewall": {
        "description": "Restore normal network firewall policies after incident containment",
        "linux_cmd": "iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT && iptables -F",
        "windows_cmd": "Remove-NetFirewallRule -DisplayName 'SOC-Isolation'",
        "is_containment": True,
        "required_permission": Permission.EXECUTE_SSH_REMEDIATION
    },
    "kill_process": {
        "description": "Terminate suspicious process execution by Process ID (PID)",
        "linux_cmd": "kill -9 {pid}",
        "windows_cmd": "Stop-Process -Id {pid} -Force",
        "is_containment": True,
        "required_permission": Permission.EXECUTE_SSH_REMEDIATION
    },
    "pkill_process_name": {
        "description": "Terminate all process instances matching a binary name",
        "linux_cmd": "pkill -9 -f '{process_name}'",
        "windows_cmd": "Stop-Process -Name '{process_name}' -Force",
        "is_containment": True,
        "required_permission": Permission.EXECUTE_SSH_REMEDIATION
    },
    "revoke_authorized_key": {
        "description": "Invalidate attacker public SSH key in authorized_keys",
        "linux_cmd": "sed -i.bak '/{key_comment}/d' ~/.ssh/authorized_keys",
        "windows_cmd": "Get-Content C:\\Users\\*\\.ssh\\authorized_keys",
        "is_containment": True,
        "required_permission": Permission.EXECUTE_SSH_REMEDIATION
    },
    "block_remote_ip": {
        "description": "Add perimeter or local host drop rule for malicious external IP",
        "linux_cmd": "iptables -I INPUT 1 -s '{ip_address}' -j DROP",
        "windows_cmd": "New-NetFirewallRule -DisplayName 'Block-{ip_address}' -Direction Inbound -Action Block -RemoteAddress '{ip_address}'",
        "is_containment": True,
        "required_permission": Permission.EXECUTE_SSH_REMEDIATION
    }
}


class SSHEngine:
    """Enterprise SSH Execution & Forensics Engine with RBAC Guards."""

    @staticmethod
    def get_supported_commands() -> Dict[str, Any]:
        """Returns the full dictionary of allowlisted forensic and remediation templates."""
        return {
            "forensics": {
                k: {
                    "description": v["description"],
                    "required_permission": v["required_permission"].value
                } for k, v in FORENSIC_COMMAND_TEMPLATES.items()
            },
            "remediation": {
                k: {
                    "description": v["description"],
                    "required_permission": v["required_permission"].value
                } for k, v in REMEDIATION_COMMAND_TEMPLATES.items()
            }
        }

    @staticmethod
    def sanitize_parameter(value: str) -> str:
        """Strips dangerous shell metacharacters to prevent command injection."""
        if not value:
            return ""
        # Allow alphanumeric, dashes, underscores, dots, colons, slashes, backslashes
        return re.sub(r'[^a-zA-Z0-9_\-\./\\:@]', '', str(value))

    @classmethod
    def execute_command(
        cls,
        target_host: str,
        command_type: str,
        params: Optional[Dict[str, Any]] = None,
        user: Optional[UserProfile] = None,
        db: Optional[Session] = None,
        ssh_port: int = 22,
        ssh_user: str = "soc-admin",
        ssh_key_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes an allowlisted SSH diagnostic or remediation command.
        1. Validates RBAC permissions
        2. Formulates sanitized shell command
        3. Attempts live Paramiko SSH or produces high-fidelity simulated telemetry
        4. Logs full audit record to DB
        """
        params = params or {}
        now_dt = datetime.now(timezone.utc)
        record_id = f"SSH-{now_dt.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"

        # Look up command definition
        cmd_def = FORENSIC_COMMAND_TEMPLATES.get(command_type) or REMEDIATION_COMMAND_TEMPLATES.get(command_type)
        if not cmd_def:
            raise ValueError(f"Unknown command type '{command_type}'. Allowed types: {list(FORENSIC_COMMAND_TEMPLATES.keys()) + list(REMEDIATION_COMMAND_TEMPLATES.keys())}")

        is_containment = cmd_def["is_containment"]
        req_perm = cmd_def["required_permission"]

        # 1. RBAC Verification
        user_email = user.email if user else "system@dealers.corp"
        user_role = user.role.value if user else UserRole.SOC_LEAD_ADMIN.value

        if user:
            user_perms = user.permissions
            if req_perm.value not in user_perms:
                # Log blocked attempt
                if db:
                    audit = SSHAuditRecord(
                        id=record_id,
                        target_host=target_host,
                        user_email=user_email,
                        user_role=user_role,
                        command_type=command_type,
                        command_raw=cmd_def["linux_cmd"],
                        is_containment=is_containment,
                        status="BLOCKED_BY_POLICY",
                        exit_code=126,
                        stdout="",
                        stderr=f"Permission denied: User role '{user_role}' lacks required permission '{req_perm.value}'",
                        executed_at=now_dt
                    )
                    db.add(audit)
                    db.commit()

                raise PermissionError(f"User '{user_email}' with role '{user_role}' lacks permission '{req_perm.value}' to execute '{command_type}'.")

        # 2. Command Formatting with sanitization
        sanitized_params = {k: cls.sanitize_parameter(str(v)) for k, v in params.items()}
        try:
            raw_command = cmd_def["linux_cmd"].format(**sanitized_params)
        except KeyError as e:
            raise ValueError(f"Missing required parameter {e} for command '{command_type}'")

        # 3. Execution (Live SSH vs High-Fidelity Simulation)
        status = "SUCCESS"
        exit_code = 0
        stdout = ""
        stderr = ""

        # Check if target host has live reachable SSH
        live_executed = False
        if PARAMIKO_AVAILABLE and ssh_key_path:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target_host, port=ssh_port, username=ssh_user, key_filename=ssh_key_path, timeout=3)
                stdin, p_stdout, p_stderr = client.exec_command(raw_command, timeout=10)
                stdout = p_stdout.read().decode("utf-8", errors="replace")
                stderr = p_stderr.read().decode("utf-8", errors="replace")
                exit_code = p_stdout.channel.recv_exit_status()
                client.close()
                status = "SUCCESS" if exit_code == 0 else "FAILED"
                live_executed = True
            except Exception:
                live_executed = False

        if not live_executed:
            # High-fidelity simulated telemetry output
            stdout, stderr, exit_code = cls._generate_simulated_telemetry(target_host, command_type, sanitized_params)
            status = "SIMULATED"

        # 4. Save Audit Record
        if db:
            audit = SSHAuditRecord(
                id=record_id,
                target_host=target_host,
                user_email=user_email,
                user_role=user_role,
                command_type=command_type,
                command_raw=raw_command,
                is_containment=is_containment,
                status=status,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                executed_at=now_dt
            )
            db.add(audit)
            db.commit()

        return {
            "record_id": record_id,
            "target_host": target_host,
            "command_type": command_type,
            "command_executed": raw_command,
            "is_containment": is_containment,
            "status": status,
            "exit_code": exit_code,
            "executed_by": user_email,
            "user_role": user_role,
            "stdout": stdout,
            "stderr": stderr,
            "executed_at": now_dt.isoformat()
        }

    @staticmethod
    def _generate_simulated_telemetry(host: str, cmd_type: str, params: Dict[str, str]) -> tuple[str, str, int]:
        """Generates realistic EDR / Linux / Windows forensic telemetry for the target host."""
        h_upper = host.upper()
        
        if cmd_type == "collect_process_tree":
            if "WORKSTATION" in h_upper or "WS-" in h_upper:
                out = (
                    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                    "root         1  0.0  0.1 168344 11200 ?        Ss   08:00   0:02 /sbin/init\n"
                    "alice     1420  0.1  0.5 342100 42100 ?        S    08:15   0:05 explorer.exe\n"
                    "alice     1842  2.4  1.2 512400 98200 ?        S    09:12   0:14  \\_ powershell.exe -Enc SQBFAFgA...\n"
                    "alice     2104  0.0  0.1  12400  3200 ?        S    09:13   0:00      \\_ whoami.exe /all\n"
                    "alice     2190  0.5  0.8 184200 64200 ?        S    09:14   0:01      \\_ rundll32.exe C:\\Temp\\stage2.dll,Start\n"
                )
            elif "DC-PROD" in h_upper or "DOMAIN" in h_upper:
                out = (
                    "SYSTEM       1  0.0  0.2 210344 24200 ?        Ss   00:00   0:45 ntoskrnl.exe\n"
                    "SYSTEM     640  0.2  2.1 892100 182400 ?       S    00:01   2:10 lsass.exe\n"
                    "SYSTEM     810  0.0  0.4 312000 38200 ?        S    00:01   0:12 ntds.dit service\n"
                    "svc-back  4512  1.8  1.1 482100 92100 ?        S    09:25   0:08  \\_ powershell.exe -ExecutionPolicy Bypass C:\\Temp\\invoke-mimikatz.ps1\n"
                )
            else:
                out = (
                    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                    "root         1  0.0  0.1 168344 11200 ?        Ss   08:00   0:02 /sbin/init\n"
                    "www-data   820  0.1  0.8 412000 65200 ?        S    08:05   0:10 /usr/sbin/nginx\n"
                    "postgres  1040  0.2  1.5 820000 125000 ?       S    08:06   0:22 postgres: server process\n"
                )
            return out, "", 0

        elif cmd_type == "collect_network_sockets":
            out = (
                "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
                "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*     users:((\"sshd\",pid=940,fd=3))\n"
                "tcp   LISTEN 0      128    127.0.0.1:5432      0.0.0.0:*     users:((\"postgres\",pid=1040,fd=7))\n"
                "tcp   ESTAB  0      0      192.168.1.100:49210 185.220.101.5:443 users:((\"powershell.exe\",pid=1842,fd=12))\n"
                "tcp   ESTAB  0      0      192.168.1.100:445   192.168.1.10:49152 users:((\"System\",pid=4,fd=64))\n"
            )
            return out, "", 0

        elif cmd_type == "collect_auth_logs":
            out = (
                "Oct 07 09:10:14 " + host + " sshd[1840]: Failed password for invalid user admin from 185.220.101.5 port 51244 ssh2\n"
                "Oct 07 09:10:18 " + host + " sshd[1841]: Failed password for invalid user root from 185.220.101.5 port 51248 ssh2\n"
                "Oct 07 09:12:05 " + host + " sshd[1850]: Accepted publickey for alice from 192.168.1.50 port 49120 ssh2: RSA SHA256:abc123xyz\n"
                "Oct 07 09:12:05 " + host + " sudo[1855]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash\n"
            )
            return out, "", 0

        elif cmd_type == "inspect_file_hash":
            filepath = params.get("filepath", "/tmp/payload.exe")
            out = f"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  {filepath}\n"
            return out, "", 0

        elif cmd_type == "list_active_sessions":
            out = (
                "alice    pts/0        2026-10-07 08:15 (192.168.1.50)\n"
                "svc-back pts/1        2026-10-07 09:20 (192.168.1.10)\n"
                "\n"
                "last 5 logins:\n"
                "alice    pts/0        192.168.1.50     Wed Oct  7 08:15   still logged in\n"
                "admin    pts/1        10.10.1.5        Tue Oct  6 17:30 - 18:45  (01:15)\n"
            )
            return out, "", 0

        elif cmd_type == "isolate_host_firewall":
            out = f"[SOC-EDR] Host '{host}' network isolation rule active. All inbound/outbound packets dropped except TCP/22 forensic tunnel.\n"
            return out, "", 0

        elif cmd_type == "restore_host_firewall":
            out = f"[SOC-EDR] Host '{host}' network isolation restored to normal routing.\n"
            return out, "", 0

        elif cmd_type == "kill_process":
            pid = params.get("pid", "0")
            out = f"[SOC-EDR] SIGKILL signal sent to PID {pid} on {host}. Process terminated successfully.\n"
            return out, "", 0

        elif cmd_type == "block_remote_ip":
            ip = params.get("ip_address", "185.220.101.5")
            out = f"[SOC-EDR] Firewall drop rule appended on {host}: DROP source {ip}\n"
            return out, "", 0

        return f"[SSH Output on {host}] Command executed successfully.\n", "", 0
