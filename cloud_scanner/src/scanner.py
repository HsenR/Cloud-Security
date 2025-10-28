import json
from typing import List, Dict
from src.models import CloudResource, SecurityGroup, SecurityGroupRule, ExposureFinding
from src.aws_client import AWSClient

class CloudSecurityScanner:
    def __init__(self, region: str = 'us-east-1', vpc_id: str = None):
        self.aws = AWSClient(region)
        self.vpc_id = vpc_id
        self.inventory: List[CloudResource] = []
        self.findings: List[ExposureFinding] = []
        
        self.HIGH_RISK_PORTS = {
            22: 'SSH', 3389: 'RDP', 1433: 'MSSQL', 
            1434: 'MSSQL Browser', 3306: 'MySQL', 
            5432: 'PostgreSQL', 1521: 'Oracle', 
            27017: 'MongoDB', 6379: 'Redis'
        }
        self.MEDIUM_RISK_PORTS = {
            21: 'FTP', 23: 'Telnet', 161: 'SNMP', 
            389: 'LDAP', 445: 'SMB', 143: 'IMAP'
        }
    
    def build_inventory(self) -> None:
        print("🔍 Building cloud resource inventory...")
        
        sg_data = self.aws.get_all_security_groups(self.vpc_id)
        security_groups = self._parse_security_groups(sg_data)
        
        self._discover_ec2_instances(security_groups)
        self._discover_load_balancers(security_groups)
        self._discover_rds_instances(security_groups)
        
        print(f"✅ Inventory built: {len(self.inventory)} resources discovered")
    
    def _parse_security_groups(self, sg_data: List[Dict]) -> Dict[str, SecurityGroup]:
        security_groups = {}
        
        for sg in sg_data:
            inbound_rules = []
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    inbound_rules.append(SecurityGroupRule(
                        protocol=rule.get('IpProtocol', '-1'),
                        from_port=rule.get('FromPort', 0),
                        to_port=rule.get('ToPort', 65535),
                        cidr_ip=ip_range.get('CidrIp', ''),
                        description=ip_range.get('Description', '')
                    ))
            
            outbound_rules = []
            for rule in sg.get('IpPermissionsEgress', []):
                for ip_range in rule.get('IpRanges', []):
                    outbound_rules.append(SecurityGroupRule(
                        protocol=rule.get('IpProtocol', '-1'),
                        from_port=rule.get('FromPort', 0),
                        to_port=rule.get('ToPort', 65535),
                        cidr_ip=ip_range.get('CidrIp', ''),
                        description=ip_range.get('Description', '')
                    ))
            
            security_groups[sg['GroupId']] = SecurityGroup(
                id=sg['GroupId'],
                name=sg.get('GroupName', ''),
                description=sg.get('Description', ''),
                vpc_id=sg['VpcId'],
                inbound_rules=inbound_rules,
                outbound_rules=outbound_rules
            )
        
        return security_groups
    
    def _discover_ec2_instances(self, security_groups: Dict[str, SecurityGroup]) -> None:
        instances = self.aws.get_ec2_instances(self.vpc_id)
        
        for instance in instances:
            instance_sgs = []
            for sg in instance.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                if sg_id in security_groups:
                    instance_sgs.append(security_groups[sg_id])
            
            public_ip = instance.get('PublicIpAddress')
            private_ip = instance.get('PrivateIpAddress')
            
            tags = {}
            for tag in instance.get('Tags', []):
                tags[tag['Key']] = tag['Value']
            
            name = tags.get('Name', instance['InstanceId'])
            
            resource = CloudResource(
                resource_id=instance['InstanceId'],
                resource_type='ec2',
                name=name,
                public_ip=public_ip,
                private_ip=private_ip,
                security_groups=instance_sgs,
                tags=tags,
                vpc_id=instance['VpcId']
            )
            
            self.inventory.append(resource)
    
    def _discover_load_balancers(self, security_groups: Dict[str, SecurityGroup]) -> None:
        load_balancers = self.aws.get_load_balancers(self.vpc_id)
        
        for lb in load_balancers:
            lb_sgs = []
            for sg_id in lb.get('SecurityGroups', []):
                if sg_id in security_groups:
                    lb_sgs.append(security_groups[sg_id])
            
            public_ip = lb['DNSName'] if lb['Scheme'] == 'internet-facing' else None
            
            resource = CloudResource(
                resource_id=lb['LoadBalancerArn'],
                resource_type='elb',
                name=lb.get('LoadBalancerName', lb['LoadBalancerArn']),
                public_ip=public_ip,
                private_ip=None,
                security_groups=lb_sgs,
                tags={},
                vpc_id=lb['VpcId']
            )
            
            self.inventory.append(resource)
    
    def _discover_rds_instances(self, security_groups: Dict[str, SecurityGroup]) -> None:
        rds_instances = self.aws.get_rds_instances()
        
        for rds in rds_instances:
            rds_sgs = []
            for sg in rds.get('VpcSecurityGroups', []):
                sg_id = sg['VpcSecurityGroupId']
                if sg_id in security_groups:
                    rds_sgs.append(security_groups[sg_id])
            
            public_ip = rds['Endpoint']['Address'] if rds.get('PubliclyAccessible') else None
            
            resource = CloudResource(
                resource_id=rds['DBInstanceIdentifier'],
                resource_type='rds',
                name=rds['DBInstanceIdentifier'],
                public_ip=public_ip,
                private_ip=None,
                security_groups=rds_sgs,
                tags={},
                vpc_id=rds['DBSubnetGroup']['VpcId'] if rds.get('DBSubnetGroup') else 'unknown'
            )
            
            self.inventory.append(resource)
    
    def analyze_exposures(self) -> None:
        print("🔎 Analyzing for theoretical exposures...")
        
        for resource in self.inventory:
            for sg in resource.security_groups:
                for rule in sg.inbound_rules:
                    if rule.cidr_ip == '0.0.0.0/0':
                        port = rule.from_port
                        service_name = self._get_service_name(port)
                        risk_level = self._assess_risk_level(port)
                        
                        finding = ExposureFinding(
                            resource=resource,
                            exposed_port=port,
                            protocol=rule.protocol,
                            cidr_range=rule.cidr_ip,
                            security_group=sg,
                            service_name=service_name,
                            risk_level=risk_level
                        )
                        
                        self.findings.append(finding)
        
        print(f"✅ Analysis complete: {len(self.findings)} potential exposures found")
    
    def _get_service_name(self, port: int) -> str:
        return self.HIGH_RISK_PORTS.get(port) or self.MEDIUM_RISK_PORTS.get(port) or f"Port {port}"
    
    def _assess_risk_level(self, port: int) -> str:
        if port in self.HIGH_RISK_PORTS:
            return 'HIGH'
        elif port in self.MEDIUM_RISK_PORTS:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_report(self) -> Dict:
        report = {
            'summary': {
                'total_resources': len(self.inventory),
                'total_findings': len(self.findings),
                'high_risk_findings': len([f for f in self.findings if f.risk_level == 'HIGH']),
                'medium_risk_findings': len([f for f in self.findings if f.risk_level == 'MEDIUM']),
                'low_risk_findings': len([f for f in self.findings if f.risk_level == 'LOW'])
            },
            'inventory': [
                {
                    'resource_id': r.resource_id,
                    'type': r.resource_type,
                    'name': r.name,
                    'public_ip': r.public_ip,
                    'security_groups': [sg.id for sg in r.security_groups]
                } for r in self.inventory
            ],
            'findings': [
                {
                    'resource_id': f.resource.resource_id,
                    'resource_type': f.resource.resource_type,
                    'resource_name': f.resource.name,
                    'public_ip': f.resource.public_ip,
                    'exposed_port': f.exposed_port,
                    'service': f.service_name,
                    'protocol': f.protocol,
                    'security_group': f.security_group.id,
                    'risk_level': f.risk_level,
                    'cidr_range': f.cidr_range
                } for f in self.findings
            ]
        }
        
        return report
    
    def print_summary(self) -> None:
        report = self.generate_report()
        
        print("\n" + "="*60)
        print("📊 PHASE 1: THEORETICAL EXPOSURE REPORT")
        print("="*60)
        
        print(f"\n📦 Resource Inventory:")
        print(f"   EC2 Instances: {len([r for r in self.inventory if r.resource_type == 'ec2'])}")
        print(f"   Load Balancers: {len([r for r in self.inventory if r.resource_type == 'elb'])}")
        print(f"   RDS Instances: {len([r for r in self.inventory if r.resource_type == 'rds'])}")
        
        print(f"\n⚠️  Exposure Findings:")
        print(f"   HIGH Risk: {report['summary']['high_risk_findings']}")
        print(f"   MEDIUM Risk: {report['summary']['medium_risk_findings']}")
        print(f"   LOW Risk: {report['summary']['low_risk_findings']}")
        
        if self.findings:
            print(f"\n🔴 HIGH RISK EXPOSURES:")
            for finding in [f for f in self.findings if f.risk_level == 'HIGH']:
                print(f"   • {finding.resource.name} ({finding.resource.resource_id})")
                print(f"     Port {finding.exposed_port} ({finding.service_name}) exposed to {finding.cidr_range}")
                print(f"     Security Group: {finding.security_group.id}")
