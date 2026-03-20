"""IAM Access Advisor integration — service last accessed data."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime

import boto3

from ..config import BOTO_CONFIG

logger = logging.getLogger(__name__)


@dataclass
class ServiceAccess:
    """A service accessed by a role per Access Advisor."""

    service_name: str
    service_namespace: str
    last_accessed: datetime | None
    total_entities: int = 0


def get_last_accessed(
    role_arn: str,
    region: str | None = None,
) -> list[ServiceAccess]:
    """Fetch IAM service last accessed details for a role.

    Returns list of services the role has accessed, per IAM Access Advisor.
    """
    client = boto3.client("iam", region_name=region, config=BOTO_CONFIG)

    # Start the job
    response = client.generate_service_last_accessed_details(
        Arn=role_arn,
        Granularity="SERVICE_LEVEL",
    )
    job_id = response["JobId"]
    logger.info("Started Access Advisor job %s for %s", job_id, role_arn)

    # Poll until complete (120s timeout)
    timeout_secs = 120
    start_time = time.monotonic()
    while True:
        result = client.get_service_last_accessed_details(JobId=job_id)
        status = result["JobStatus"]
        if status == "COMPLETED":
            break
        elif status == "FAILED":
            error = result.get("Error", {}).get("Message", "Unknown error")
            logger.error("Access Advisor job failed: %s", error)
            return []
        if time.monotonic() - start_time > timeout_secs:
            logger.error(
                "Access Advisor job %s timed out after %ds", job_id, timeout_secs
            )
            raise TimeoutError(
                f"Access Advisor job did not complete within {timeout_secs}s"
            )
        time.sleep(1)

    # Paginate results (API returns up to 100 services per page)
    all_services_raw = list(result.get("ServicesLastAccessed", []))
    while result.get("IsTruncated"):
        result = client.get_service_last_accessed_details(
            JobId=job_id, Marker=result["Marker"]
        )
        all_services_raw.extend(result.get("ServicesLastAccessed", []))

    # Parse results
    services = []
    for svc in all_services_raw:
        last_auth = svc.get("LastAuthenticated")
        if last_auth and not isinstance(last_auth, datetime):
            try:
                last_auth = datetime.fromisoformat(str(last_auth))
            except (ValueError, TypeError):
                last_auth = None

        services.append(
            ServiceAccess(
                service_name=svc.get("ServiceName", ""),
                service_namespace=svc.get("ServiceNamespace", ""),
                last_accessed=last_auth if last_auth else None,
                total_entities=svc.get("TotalAuthenticatedEntities", 0),
            )
        )

    accessed = [s for s in services if s.last_accessed is not None]
    logger.info(
        "Access Advisor: %d services accessed (of %d total)",
        len(accessed),
        len(services),
    )
    return accessed
