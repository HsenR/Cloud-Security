# src/utils/config.py

import os

AWS_REGION = os.getenv("AWS_REGION", "eu-north-1")
REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")
VPC_ID = os.getenv("VPC_ID", None)
