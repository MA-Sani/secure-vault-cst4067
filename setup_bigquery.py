"""
setup_bigquery.py
Run this ONCE to create the BigQuery dataset and access_events table.

Usage:
    python setup_bigquery.py
"""

import os
from dotenv import load_dotenv
from bigquery_logger import BigQueryLogger

load_dotenv()

project_id = os.getenv('GCP_PROJECT_ID')
if not project_id:
    raise ValueError("GCP_PROJECT_ID not set in .env")

logger = BigQueryLogger(project_id)
logger.create_table_if_missing()
print("BigQuery setup complete.")
