"""
Unit tests for both Lambda functions, run against a fake AWS (moto).
Run with:  pip install -r tests/requirements.txt && pytest -q
"""
import importlib
import json
import os
import sys

import boto3
import pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lambda", "remediator"))
sys.path.insert(0, os.path.join(ROOT, "lambda", "api"))

BUCKET = "test-data-bucket"
OFF = {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
SELF_ARN = "arn:aws:sts::123456789012:assumed-role/secure-cloud-storage-lambda-remediation/secure-cloud-storage-s3-remediator"
HUMAN_ARN = "arn:aws:iam::123456789012:user/terraform-admin"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("DATA_BUCKET", BUCKET)
    monkeypatch.setenv("OWN_ROLE_MARKER", "secure-cloud-storage-lambda-remediation")
    monkeypatch.setenv("REMEDIATOR_LOG_GROUP", "/aws/lambda/secure-cloud-storage-s3-remediator")
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET)
        yield s3


def s3_event(actor, event_name="PutBucketPublicAccessBlock", error=None):
    detail = {
        "eventName": event_name,
        "requestParameters": {"bucketName": BUCKET},
        "userIdentity": {"arn": actor},
        "sourceIPAddress": "203.0.113.5",
        "eventTime": "2026-10-17T06:00:00Z",
    }
    if error:
        detail["errorCode"] = error
    return {"detail": detail}


def load(module_name):
    module = importlib.import_module(module_name)
    return importlib.reload(module)  # re-create boto3 clients inside the mock


def all_blocked(s3):
    return all(s3.get_public_access_block(Bucket=BUCKET)["PublicAccessBlockConfiguration"].values())


# ------------------------------------------------------------------ remediator
def test_remediates_when_a_person_turns_protection_off(aws_env):
    sns = boto3.client("sns", region_name="us-east-1")
    os.environ["SNS_TOPIC_ARN"] = sns.create_topic(Name="alerts")["TopicArn"]
    remediate = load("remediate")
    aws_env.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=OFF)

    result = remediate.lambda_handler(s3_event(HUMAN_ARN), None)

    assert result["action"] == "remediated"
    assert all_blocked(aws_env)
    os.environ.pop("SNS_TOPIC_ARN")


def test_remediates_when_settings_are_deleted(aws_env):
    remediate = load("remediate")
    aws_env.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=OFF)
    aws_env.delete_public_access_block(Bucket=BUCKET)

    result = remediate.lambda_handler(s3_event(HUMAN_ARN, "DeleteBucketPublicAccessBlock"), None)

    assert result["action"] == "remediated"
    assert all_blocked(aws_env)


def test_ignores_its_own_changes_so_it_cannot_loop(aws_env):
    remediate = load("remediate")
    aws_env.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=OFF)

    result = remediate.lambda_handler(s3_event(SELF_ARN), None)

    assert result == {"action": "skipped", "reason": "self-triggered"}
    assert not all_blocked(aws_env)  # untouched


def test_skips_when_already_protected(aws_env):
    remediate = load("remediate")
    aws_env.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration={k: True for k in OFF})

    result = remediate.lambda_handler(s3_event(HUMAN_ARN), None)

    assert result["reason"] == "already blocked"


def test_skips_failed_api_calls(aws_env):
    remediate = load("remediate")
    result = remediate.lambda_handler(s3_event(HUMAN_ARN, error="AccessDenied"), None)
    assert result["reason"] == "change failed"


# ------------------------------------------------------------------ file API
def api_event(route, user="user-1", body=None, query=None):
    return {
        "routeKey": route,
        "requestContext": {"authorizer": {"jwt": {"claims": {"sub": user, "cognito:username": "demo"}}}},
        "body": json.dumps(body) if body is not None else None,
        "queryStringParameters": query,
    }


def call(api, *args, **kwargs):
    response = api.handler(api_event(*args, **kwargs), None)
    return response["statusCode"], json.loads(response["body"])


def test_users_only_see_their_own_files(aws_env):
    api = load("api")
    aws_env.put_object(Bucket=BUCKET, Key="users/user-1/mine.txt", Body=b"a")
    aws_env.put_object(Bucket=BUCKET, Key="users/user-2/theirs.txt", Body=b"b")

    status, body = call(api, "GET /files", user="user-1")

    assert status == 200
    assert [f["name"] for f in body["files"]] == ["mine.txt"]


def test_upload_url_is_scoped_size_limited_and_sanitised(aws_env):
    api = load("api")
    status, body = call(api, "POST /upload-url", body={"name": "../../users/user-2/evil.txt", "size": 10, "type": "text/plain"})

    assert status == 200
    assert body["fields"]["key"] == "users/user-1/evil.txt"
    policy = json.loads(__import__("base64").b64decode(body["fields"]["policy"]))
    assert ["content-length-range", 1, 10 * 1024 * 1024] in policy["conditions"]


def test_upload_rejects_oversized_files(aws_env):
    api = load("api")
    status, body = call(api, "POST /upload-url", body={"name": "big.bin", "size": 50 * 1024 * 1024})
    assert status == 400
    assert "too large" in body["error"]


def test_download_link_only_for_existing_own_file(aws_env):
    api = load("api")
    aws_env.put_object(Bucket=BUCKET, Key="users/user-1/report.pdf", Body=b"x")

    ok_status, ok_body = call(api, "GET /download-url", query={"name": "report.pdf"})
    other_status, _ = call(api, "GET /download-url", user="user-2", query={"name": "report.pdf"})

    assert ok_status == 200 and "X-Amz-Signature" in ok_body["url"]
    assert other_status == 404


def test_delete_own_file(aws_env):
    api = load("api")
    aws_env.put_object(Bucket=BUCKET, Key="users/user-1/old.txt", Body=b"x")
    status, _ = call(api, "DELETE /files", query={"name": "old.txt"})
    assert status == 200
    assert "Contents" not in aws_env.list_objects_v2(Bucket=BUCKET, Prefix="users/user-1/")


def test_status_reports_risk_and_recent_fixes(aws_env):
    logs = boto3.client("logs", region_name="us-east-1")
    group = os.environ["REMEDIATOR_LOG_GROUP"]
    logs.create_log_group(logGroupName=group)
    logs.create_log_stream(logGroupName=group, logStreamName="s1")
    logs.put_log_events(logGroupName=group, logStreamName="s1", logEvents=[{
        "timestamp": int(__import__("time").time() * 1000),
        "message": f"[INFO]\tRemediation successful! Public access re-blocked on {BUCKET} (changed by {HUMAN_ARN} via PutBucketPublicAccessBlock)",
    }])
    api = load("api")
    aws_env.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration=OFF)

    status, body = call(api, "GET /status")

    assert status == 200
    checks = {c["id"]: c for c in body["checks"]}
    assert checks["public-access"]["ok"] is False
    assert body["recentFixes"][0]["bucket"] == BUCKET
    assert body["recentFixes"][0]["actor"] == "terraform-admin"


def test_unknown_route_is_404(aws_env):
    api = load("api")
    status, _ = call(api, "GET /admin")
    assert status == 404
