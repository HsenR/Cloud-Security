from dataclasses import dataclass
from typing import List, Optional, Dict 

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
    resource_type: str # e.g EC2, elb, rds
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
    security_grou: SecurityGroup
    service_name: str # e.g SSH, HTTPm PostgreSQL
    risk_level: str # e.g low, medium, high