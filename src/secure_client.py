import boto3
import json
import logging
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class SecureStorageClient:
    def __init__(self, role_arn, region_name="us-east-1"):
        """
        Initializes the client by assuming the least-privilege IAM role.
        """
        logging.info(f"Assuming role: {role_arn}...")
        sts_client = boto3.client('sts', region_name=region_name)
        
        try:
            assumed_role_object = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="SecureClientSession"
            )
            credentials = assumed_role_object['Credentials']
            
            # Initialize S3 client with assumed role credentials
            self.s3_client = boto3.client(
                's3',
                region_name=region_name,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
            )
            logging.info("Successfully assumed role and initialized S3 client.")
        except ClientError as e:
            logging.error(f"Error assuming role: {e}")
            raise

    def secure_upload(self, file_path, bucket_name, object_name=None):
        """
        Uploads a file securely. The bucket policy enforces encryption,
        but we can also explicitly request it here.
        """
        if object_name is None:
            object_name = file_path

        try:
            logging.info(f"Uploading {file_path} to {bucket_name}/{object_name}...")
            self.s3_client.upload_file(
                file_path, 
                bucket_name, 
                object_name,
                ExtraArgs={'ServerSideEncryption': 'AES256'}
            )
            logging.info("Upload successful.")
        except ClientError as e:
            logging.error(f"Upload failed: {e}")
            raise

    def verify_encryption(self, bucket_name, object_name):
        """
        Verifies that the uploaded object is encrypted on the server side.
        """
        try:
            response = self.s3_client.head_object(Bucket=bucket_name, Key=object_name)
            encryption = response.get('ServerSideEncryption')
            if encryption:
                logging.info(f"Verification Passed: Object '{object_name}' is encrypted with {encryption}.")
                return True
            else:
                logging.warning(f"Verification Failed: Object '{object_name}' is NOT encrypted!")
                return False
        except ClientError as e:
            logging.error(f"Error checking encryption status: {e}")
            raise

    def generate_presigned_url(self, bucket_name, object_name, expiration=3600):
        """
        Generates a secure, time-limited presigned URL to share the object without making it public.
        """
        try:
            response = self.s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
            logging.info(f"Generated presigned URL (valid for {expiration} seconds).")
            return response
        except ClientError as e:
            logging.error(f"Error generating presigned URL: {e}")
            raise

if __name__ == "__main__":
    import sys
    
    # Example usage (Requires AWS credentials to be configured in the environment)
    if len(sys.argv) != 4:
        print("Usage: python secure_client.py <ROLE_ARN> <BUCKET_NAME> <FILE_TO_UPLOAD>")
        sys.exit(1)

    ROLE_ARN = sys.argv[1]
    BUCKET_NAME = sys.argv[2]
    FILE_PATH = sys.argv[3]
    OBJECT_NAME = "secure-upload-" + FILE_PATH.split('/')[-1]

    client = SecureStorageClient(ROLE_ARN)
    
    # 1. Upload File
    client.secure_upload(FILE_PATH, BUCKET_NAME, OBJECT_NAME)
    
    # 2. Verify Security
    client.verify_encryption(BUCKET_NAME, OBJECT_NAME)
    
    # 3. Generate Temporary Access Link
    url = client.generate_presigned_url(BUCKET_NAME, OBJECT_NAME, expiration=300) # 5 minutes
    print(f"\nShareable Link (Expires in 5 mins):\n{url}\n")
