"""
Auto-remediation Lambda.

Triggered by EventBridge whenever CloudTrail records a change to an S3 bucket's
public access settings, bucket policy or ACL. If the bucket is no longer fully
protected, it turns S3 Block Public Access back on and emails an alert via SNS.
"""
import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
# Name of this function's own IAM role, used to ignore changes it makes itself
OWN_ROLE_MARKER = os.environ.get("OWN_ROLE_MARKER", "lambda-remediation")

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def is_fully_blocked(bucket):
    """True if all four Block Public Access settings are already on."""
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as error:
        if error.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False  # the settings were deleted entirely
        raise
    return all(config.get(setting) for setting in FULL_BLOCK)


def notify(bucket, actor, event_name, detail):
    """Email an alert through SNS. A failed alert must never stop the fix."""
    if not SNS_TOPIC_ARN:
        return
    message = "\n".join([
        "Automatic security remediation was performed.",
        "",
        f"Bucket:        {bucket}",
        f"Change:        {event_name}",
        f"Changed by:    {actor}",
        f"Source IP:     {detail.get('sourceIPAddress', 'unknown')}",
        f"Event time:    {detail.get('eventTime', 'unknown')}",
        f"Fixed at:      {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "Action taken: S3 Block Public Access was turned back on (all four settings).",
        "Next step: check CloudTrail Event history to confirm whether this change was expected.",
    ])
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[Security] Public access auto-blocked on {bucket}"[:100],
            Message=message,
        )
    except ClientError as error:
        logger.error("Could not send SNS alert: %s", error)


def lambda_handler(event, context):
    detail = event.get("detail") or {}
    event_name = detail.get("eventName", "unknown")
    identity = detail.get("userIdentity") or {}
    actor = identity.get("arn") or identity.get("type") or "unknown"
    bucket = (detail.get("requestParameters") or {}).get("bucketName")

    logger.info("Security event %s on bucket %s by %s", event_name, bucket, actor)

    # 1. Loop guard: our own fix is also a "public access changed" event
    if OWN_ROLE_MARKER in actor:
        logger.info("Change was made by this remediation function itself, skipping.")
        return {"action": "skipped", "reason": "self-triggered"}

    if not bucket:
        logger.warning("Bucket name not found in event, skipping.")
        return {"action": "skipped", "reason": "no bucket in event"}

    # 2. The API call was rejected, so nothing actually changed
    if detail.get("errorCode"):
        logger.info("The change failed (%s), nothing to fix.", detail["errorCode"])
        return {"action": "skipped", "reason": "change failed"}

    # 3. Already safe (for example Terraform turning protection ON)
    if is_fully_blocked(bucket):
        logger.info("Bucket %s is already fully protected, nothing to fix.", bucket)
        return {"action": "skipped", "reason": "already blocked"}

    # 4. Fix it
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=FULL_BLOCK)
    logger.info(
        "Remediation successful! Public access re-blocked on %s (changed by %s via %s)",
        bucket, actor, event_name,
    )
    notify(bucket, actor, event_name, detail)

    return {"action": "remediated", "bucket": bucket, "body": json.dumps(f"Remediation applied to {bucket}")}
