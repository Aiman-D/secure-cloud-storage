# Enterprise Secure Cloud Storage Architecture 🛡️

This is a comprehensive, enterprise-grade cloud security engineering portfolio project. It goes beyond basic cloud storage by implementing active threat remediation, continuous integration security scanning, and least-privilege programmable access—all built on AWS using Infrastructure as Code (Terraform).

## 🚀 "Impressive" Enterprise Features Implemented

1. **Automated Event-Driven Remediation (AWS Lambda + EventBridge)**
   - We don't just alert on misconfigurations; we fix them. If an admin or compromised account attempts to make an S3 bucket public (via `PutBucketAcl`, `PutBucketPolicy`, or `PutBucketPublicAccessBlock`), an EventBridge rule instantly captures the CloudTrail event.
   - This triggers a custom **Python AWS Lambda function** (`remediate.py`) that instantly reverts the change, enforcing `BlockPublicAccess` within seconds.

2. **Continuous Security Scanning (CI/CD Pipeline)**
   - Included a GitHub Actions workflow (`.github/workflows/security-scan.yml`) that automatically runs `tfsec` on every push and pull request. 
   - This ensures no security vulnerabilities (like unencrypted buckets) are merged into the infrastructure codebase.

3. **Custom Python Security Client (Boto3)**
   - Provided `src/secure_client.py` to demonstrate how an application should programmatically interact with this secure infrastructure.
   - The script demonstrates assuming a least-privilege IAM role via STS, securely uploading files, programmatically verifying Server-Side Encryption (SSE-S3) on objects, and generating time-limited presigned URLs.

4. **Robust Infrastructure Base (Terraform)**
   - Centralized CloudTrail logging.
   - S3 Versioning & Lifecycle Rules (keeping costs in the Free Tier).
   - strict Bucket Policies enforcing HTTPS (`aws:SecureTransport`).
   - IAM Access Analyzer enabled for continuous monitoring of resource sharing.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/downloads) installed locally.
- An [AWS Account](https://aws.amazon.com/free/) (Architected to use AWS Free Tier services).
- [AWS CLI](https://aws.amazon.com/cli/) configured with your credentials (`aws configure`).
- Python 3.x and `boto3` (`pip install boto3`) to run the secure client.

## How to Deploy & Test

### 1. Deploy the Infrastructure
1. Navigate to the `terraform` directory: `cd terraform`
2. Initialize Terraform: `terraform init`
3. Deploy the resources: `terraform apply`

### 2. Test the Automated Remediation
1. Go into the AWS Console and find the generated Data S3 Bucket.
2. Attempt to turn off "Block all public access" in the permissions tab.
3. Wait a few seconds and refresh the page. The Lambda function will have automatically re-enabled "Block all public access"!

### 3. Run the Secure Client
1. Find the ARN of the `app-role` from the terraform outputs.
2. Run the client script:
   ```bash
   python src/secure_client.py <APP_ROLE_ARN> <DATA_BUCKET_NAME> path/to/some_test_file.txt
   ```
3. The script will securely assume the role, upload the file, verify encryption, and print a shareable link.

## Clean Up

To destroy all provisioned infrastructure:
```bash
terraform destroy
```
