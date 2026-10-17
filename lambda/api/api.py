"""
File API Lambda behind API Gateway (HTTP API) with a Cognito JWT authorizer.

Every request is already authenticated by API Gateway. Each user can only see
their own folder (users/<their Cognito ID>/). The browser never receives AWS
keys: uploads and downloads use S3 links that expire after 5 minutes.

Routes:
  GET    /files                 list my files
  POST   /upload-url            get a short-lived upload form for one file
  GET    /download-url?name=    get a short-lived download link
  DELETE /files?name=           delete one of my files
  GET    /status                live security status of the storage bucket
"""
import base64
import json
import os
import re
import time
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

REGION = os.environ.get("AWS_REGION", "us-east-1")
BUCKET = os.environ.get("DATA_BUCKET", "")
REMEDIATOR_LOG_GROUP = os.environ.get("REMEDIATOR_LOG_GROUP", "")
MAX_UPLOAD_BYTES = int(float(os.environ.get("MAX_UPLOAD_MB", "10")) * 1024 * 1024)
LINK_EXPIRY_SECONDS = 300

s3 = boto3.client(
    "s3",
    region_name=REGION,
    config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
)
logs = boto3.client("logs", region_name=REGION)

UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._ ()\-]")
FIX_PATTERN = re.compile(r"re-blocked on (\S+) \(changed by (\S+)")


# --------------------------------------------------------------------------- helpers
def respond(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(body, default=str),
    }


def user_prefix(event):
    """The caller's private folder, based on their verified Cognito ID."""
    claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
    return f"users/{claims['sub']}/"


def clean_name(name):
    """Strip any folder parts and unsafe characters, so nobody can escape their folder."""
    name = (name or "").replace("\\", "/").split("/")[-1].strip()
    name = UNSAFE_CHARS.sub("_", name)[:200]
    return "" if name in ("", ".", "..") else name


def read_body(event):
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    return json.loads(raw)


def query(event, key):
    return (event.get("queryStringParameters") or {}).get(key)


# --------------------------------------------------------------------------- routes
def list_files(prefix):
    files = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            files.append({
                "name": obj["Key"][len(prefix):],
                "size": obj["Size"],
                "lastModified": obj["LastModified"].isoformat(),
            })
    files.sort(key=lambda f: f["lastModified"], reverse=True)
    return respond(200, {"files": files})


def upload_url(prefix, body):
    name = clean_name(body.get("name"))
    size = body.get("size")
    content_type = str(body.get("type") or "application/octet-stream")[:100]

    if not name:
        return respond(400, {"error": "Invalid file name."})
    if not isinstance(size, int) or size <= 0:
        return respond(400, {"error": "Invalid file size."})
    if size > MAX_UPLOAD_BYTES:
        return respond(400, {"error": f"File is too large. The limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."})

    # S3 itself rejects the upload if it is bigger than the limit or a different file type
    post = s3.generate_presigned_post(
        Bucket=BUCKET,
        Key=prefix + name,
        Fields={"Content-Type": content_type},
        Conditions=[
            {"Content-Type": content_type},
            ["content-length-range", 1, MAX_UPLOAD_BYTES],
        ],
        ExpiresIn=LINK_EXPIRY_SECONDS,
    )
    return respond(200, {"url": post["url"], "fields": post["fields"], "name": name})


def download_url(prefix, name):
    name = clean_name(name)
    if not name:
        return respond(400, {"error": "Invalid file name."})
    key = prefix + name
    try:
        s3.head_object(Bucket=BUCKET, Key=key)
    except ClientError as error:
        if error.response["Error"]["Code"] in ("404", "NoSuchKey", "NotFound"):
            return respond(404, {"error": "File not found."})
        raise
    url = s3.generate_presigned_url(
        "get_object",
        Params={
            "Bucket": BUCKET,
            "Key": key,
            "ResponseContentDisposition": f'attachment; filename="{name}"',
        },
        ExpiresIn=LINK_EXPIRY_SECONDS,
    )
    return respond(200, {"url": url, "expiresIn": LINK_EXPIRY_SECONDS})


def delete_file(prefix, name):
    name = clean_name(name)
    if not name:
        return respond(400, {"error": "Invalid file name."})
    s3.delete_object(Bucket=BUCKET, Key=prefix + name)
    return respond(200, {"deleted": name})


def security_checks():
    checks = []

    try:
        config = s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"]
        on = sum(1 for value in config.values() if value)
        ok = on == 4
        detail = "All 4 settings on" if ok else f"Only {on} of 4 settings on"
    except ClientError as error:
        ok, detail = False, "Settings missing" if "NoSuchPublicAccessBlock" in str(error) else "Could not read"
    checks.append({"id": "public-access", "label": "Block Public Access", "ok": ok, "detail": detail})

    try:
        rules = s3.get_bucket_encryption(Bucket=BUCKET)["ServerSideEncryptionConfiguration"]["Rules"]
        algorithm = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        checks.append({"id": "encryption", "label": "Encryption at rest", "ok": True, "detail": algorithm})
    except (ClientError, KeyError, IndexError):
        checks.append({"id": "encryption", "label": "Encryption at rest", "ok": False, "detail": "Not configured"})

    try:
        status = s3.get_bucket_versioning(Bucket=BUCKET).get("Status", "Off")
    except ClientError:
        status = "Unknown"
    checks.append({"id": "versioning", "label": "Versioning", "ok": status == "Enabled", "detail": status})

    try:
        policy = s3.get_bucket_policy(Bucket=BUCKET)["Policy"]
        https_only = "aws:SecureTransport" in policy
    except ClientError:
        https_only = False
    checks.append({
        "id": "https-only",
        "label": "HTTPS-only access",
        "ok": https_only,
        "detail": "Plain HTTP is denied" if https_only else "Not enforced",
    })
    return checks


def recent_fixes(limit=5):
    """Latest auto-fixes, read from the remediation Lambda's own logs."""
    if not REMEDIATOR_LOG_GROUP:
        return []
    fixes = []
    try:
        streams = logs.describe_log_streams(
            logGroupName=REMEDIATOR_LOG_GROUP, orderBy="LastEventTime", descending=True, limit=5
        ).get("logStreams", [])
        for stream in streams:
            events = logs.get_log_events(
                logGroupName=REMEDIATOR_LOG_GROUP,
                logStreamName=stream["logStreamName"],
                startFromHead=False,
                limit=200,
            ).get("events", [])
            for item in events:
                match = FIX_PATTERN.search(item.get("message", ""))
                if match:
                    fixes.append({
                        "time": datetime.fromtimestamp(item["timestamp"] / 1000, tz=timezone.utc).isoformat(),
                        "bucket": match.group(1),
                        "actor": match.group(2).split("/")[-1],
                    })
    except ClientError as error:
        if error.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    fixes.sort(key=lambda f: f["time"], reverse=True)
    return fixes[:limit]


def status():
    return respond(200, {
        "bucket": BUCKET,
        "checks": security_checks(),
        "recentFixes": recent_fixes(),
        "checkedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })


# --------------------------------------------------------------------------- entry point
def handler(event, context):
    route = event.get("routeKey", "")
    started = time.time()
    try:
        prefix = user_prefix(event)
        if route == "GET /files":
            result = list_files(prefix)
        elif route == "POST /upload-url":
            result = upload_url(prefix, read_body(event))
        elif route == "GET /download-url":
            result = download_url(prefix, query(event, "name"))
        elif route == "DELETE /files":
            result = delete_file(prefix, query(event, "name"))
        elif route == "GET /status":
            result = status()
        else:
            result = respond(404, {"error": "Unknown route."})
    except (ValueError, json.JSONDecodeError):
        result = respond(400, {"error": "Invalid request."})
    except Exception as error:  # never leak internals to the browser
        print(f"ERROR on {route}: {error!r}")
        result = respond(500, {"error": "Something went wrong. Check the API Lambda logs."})

    print(json.dumps({"route": route, "status": result["statusCode"], "ms": round((time.time() - started) * 1000)}))
    return result
