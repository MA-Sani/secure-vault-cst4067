"""
bigquery_logger.py
Streams every file access event to BigQuery in real time.
Also provides three analytics queries used on the /analytics page.

Table: <project>.file_vault_audit.access_events
Schema: event_id, timestamp, user_uid, user_department,
        file_id, action, decision, deny_reason, policy_id
"""

import uuid
from datetime import datetime, timezone

from google.cloud import bigquery


class BigQueryLogger:

    DATASET = 'file_vault_audit'
    TABLE   = 'access_events'

    def __init__(self, project_id: str):
        self.project_id = project_id
        self.table_ref  = f"{project_id}.{self.DATASET}.{self.TABLE}"
        self.enabled    = False
        try:
            self.client  = bigquery.Client(project=project_id)
            self.enabled = True
        except Exception as exc:
            print(f"[BigQueryLogger] Disabled — could not initialise client: {exc}")

    # ──────────────────────────────────────────────
    # Event logging
    # ──────────────────────────────────────────────

    def log_event(
        self,
        user_uid: str,
        user_department: str,
        file_id: str,
        action: str,
        decision: str,          # 'ALLOW' or 'DENY'
        deny_reason: str = '',
        policy_id: str  = '',
    ) -> None:
        """Stream one access event row to BigQuery."""
        if not self.enabled:
            return

        row = {
            'event_id':        str(uuid.uuid4()),
            'timestamp':       datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f'),
            'user_uid':        user_uid,
            'user_department': user_department,
            'file_id':         file_id,
            'action':          action,
            'decision':        decision,
            'deny_reason':     deny_reason,
            'policy_id':       policy_id,
        }

        try:
            errors = self.client.insert_rows_json(self.table_ref, [row])
            if errors:
                print(f"[BigQueryLogger] Insert errors: {errors}")
        except Exception as exc:
            print(f"[BigQueryLogger] log_event failed: {exc}")

    # ──────────────────────────────────────────────
    # Analytics queries
    # ──────────────────────────────────────────────

    def get_analytics(self) -> dict:
        """
        Run three analytics queries and return results as lists of dicts.
        Raises on BigQuery errors — caller should catch and handle.
        """
        queries = {

            # Which users have been denied the most?
            'denials_per_user': f"""
                SELECT
                    user_uid,
                    user_department,
                    COUNT(*) AS total_denials
                FROM `{self.table_ref}`
                WHERE decision = 'DENY'
                GROUP BY user_uid, user_department
                ORDER BY total_denials DESC
                LIMIT 10
            """,

            # Access volume broken down by department
            'access_by_department': f"""
                SELECT
                    user_department,
                    COUNT(*) AS total_events,
                    COUNTIF(decision = 'ALLOW') AS allowed,
                    COUNTIF(decision = 'DENY')  AS denied
                FROM `{self.table_ref}`
                GROUP BY user_department
                ORDER BY total_events DESC
            """,

            # Anomaly flag: users with 3+ denials in the last 24 hours
            'anomalous_users': f"""
                SELECT
                    user_uid,
                    user_department,
                    COUNT(*) AS denial_count
                FROM `{self.table_ref}`
                WHERE decision = 'DENY'
                  AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
                GROUP BY user_uid, user_department
                HAVING denial_count >= 3
                ORDER BY denial_count DESC
            """,
        }

        results = {}
        for key, sql in queries.items():
            rows = self.client.query(sql).result()
            results[key] = [dict(row) for row in rows]

        return results

    # ──────────────────────────────────────────────
    # One-time table setup
    # ──────────────────────────────────────────────

    def create_table_if_missing(self) -> None:
        """
        Idempotent: create the dataset and table if they don't exist.
        Called from setup_bigquery.py — not needed at runtime.
        """
        dataset_id = f"{self.project_id}.{self.DATASET}"
        dataset = bigquery.Dataset(dataset_id)
        dataset.location = 'US'
        try:
            self.client.create_dataset(dataset, timeout=30)
            print(f"Created dataset: {dataset_id}")
        except Exception:
            print(f"Dataset already exists: {dataset_id}")

        schema = [
            bigquery.SchemaField('event_id',        'STRING',    mode='REQUIRED'),
            bigquery.SchemaField('timestamp',        'TIMESTAMP', mode='REQUIRED'),
            bigquery.SchemaField('user_uid',         'STRING',    mode='REQUIRED'),
            bigquery.SchemaField('user_department',  'STRING',    mode='NULLABLE'),
            bigquery.SchemaField('file_id',          'STRING',    mode='REQUIRED'),
            bigquery.SchemaField('action',           'STRING',    mode='REQUIRED'),
            bigquery.SchemaField('decision',         'STRING',    mode='REQUIRED'),
            bigquery.SchemaField('deny_reason',      'STRING',    mode='NULLABLE'),
            bigquery.SchemaField('policy_id',        'STRING',    mode='NULLABLE'),
        ]

        table_id = f"{dataset_id}.{self.TABLE}"
        table    = bigquery.Table(table_id, schema=schema)
        try:
            self.client.create_table(table)
            print(f"Created table: {table_id}")
        except Exception:
            print(f"Table already exists: {table_id}")
