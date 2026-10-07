"""
Pydantic Schemas for SSH Remote Investigation & Remediation API.
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class SSHCommandRequest(BaseModel):
    target_host: str = Field(..., description="Target hostname or IP address (e.g. WORKSTATION-01, DC-PROD-01)")
    command_type: str = Field(..., description="Allowlisted command type: collect_process_tree, collect_network_sockets, collect_auth_logs, inspect_file_hash, isolate_host_firewall, kill_process, block_remote_ip")
    params: Dict[str, Any] = Field(default_factory=dict, description="Command parameters (e.g. pid, filepath, ip_address)")
    ssh_port: int = Field(22, description="Remote SSH port")
    ssh_user: Optional[str] = Field("soc-admin", description="SSH username")


class SSHCommandResponse(BaseModel):
    record_id: str
    target_host: str
    command_type: str
    command_executed: str
    is_containment: bool
    status: str
    exit_code: int
    executed_by: str
    user_role: str
    stdout: Optional[str] = ""
    stderr: Optional[str] = ""
    executed_at: str


class SSHHostSummary(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    asset_tier: str
    criticality: float
    os_type: str
    ssh_status: str
    is_isolated: bool
