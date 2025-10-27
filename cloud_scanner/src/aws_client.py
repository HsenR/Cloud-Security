import boto3
import os
from typing import List, Dict, any
from botocore.exceptions import ClientError

class AWSCLlient:
    def __init__(self, region_name= 'eu-north-1'):
        self.region = region_name
        self.ec2 = boto3.client('ec2', region_name=region_name)
        self.elbv2 = boto3.client('elbc2', region_name=region_name)
        self.rds = boto3.client('rds', region_name=region_name)

    def get_all_security_groups(self, vpc_id: str=None) -> List[Dict]:
        """Fetch all security groups in the specified VPC or all VPCs if none specified."""
        try:
            params = {}
            if vpc_id:
                params['Filters'] = [{'Name': 'vpc-id', 'Values': [vpc_id]}]
            
            response = self.ec2.describe_security_groups(**params)
            return response['SecurityGroups']
        except ClientError as e:
            print(f"Error fetching security groups: {e}")
            return []

    def get_ec2_instace(self, vpc_id: str= None) -> List[Dict]:
        """Fetch aall EC2 instances"""
        try:
            params = {'MaxResults': 100}
            if vpc_id:
                params['Filters'] = [{'Name': 'vpc-id', 'Values': [vpc_id]}]

            instances = []
            paginator = self.ec2.get_paginator('describe_instances')
            for page in paginator.paginate(**params):
                for reservation in page['Reservations']:
                    instances.extend(reservation['Instances'])
            return instances
        except ClientError as e:
            print(f"Error fetching EC2 instances: {e}")
            return []

    def get_load_balancers(self, vpc_id: str= None ) -> List[Dict]:
        """"Fetch all Application/Network Load Balancers"""   
        try:
            response = self.elbv2.describe_load_balancers()
            load_balancers = response['LoadBalancers']

            if vpc_id:
                load_balancers = [lb for lb in load_balancers if lb['VpcId'] == vpc_id]
            
            return load_balancers
        except ClientError as e:
            print(f"Error fetching Load Balancers: {e}")
            return []

    def get_rds_instances(self, vpc_id: str= None) -> List[Dict]:
        """"Fetch all RDS instances"""
        try:
            response = self.rds.describe_db_instances()
            instaces = response['DBInstances']

            if vpc_id:
                #RDS instaces Don't have direct VPC ID in response, we'll filter later  
                instances = instances
            return instaces
        except ClientError as e:
            print(f"Error fetching RDS instances: {e}")
            return []  