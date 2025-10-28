from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class SecurityGroupRule:
    protocol: str
    from_port: int
    to_port: int
    cidr_ip: str
    description: str = ""

@dataclass
class SecurityGroup:
    id: str
    name: str
    description: str
    vpc_id: str
    inbound_rules: List[SecurityGroupRule]
    outbound_rules: List[SecurityGroupRule]

@dataclass
class CloudResource:
    resource_id: str
    resource_type: str
    name: str
    public_ip: Optional[str]
    private_ip: Optional[str]
    security_groups: List[SecurityGroup]
    tags: Dict[str, str]
    vpc_id: str

@dataclass
class ExposureFinding:
    resource: CloudResource
    exposed_port: int
    protocol: str
    cidr_range: str
    security_group: SecurityGroup  # Fixed: was probably 'security_grou'
    service_name: str
    risk_level: str
