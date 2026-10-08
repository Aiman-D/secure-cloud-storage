import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')

def lambda_handler(event, context):
    """
    This Lambda function is triggered by EventBridge when a PutBucketPublicAccessBlock
    or PutBucketPolicy API call is made. It automatically remediates the issue by
    re-applying the Block Public Access settings.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        
        # Extract bucket name depending on the event structure
        bucket_name = None
        request_parameters = detail.get('requestParameters', {})
        if request_parameters and 'bucketName' in request_parameters:
            bucket_name = request_parameters['bucketName']
            
        if not bucket_name:
            logger.warning("Bucket name not found in event, skipping remediation.")
            return
            
        logger.info(f"Security event '{event_name}' detected on bucket: {bucket_name}")
        
        # Remediation Action: Enforce Public Access Block
        logger.info("Applying Remediation: Enforcing S3 Block Public Access...")
        
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        logger.info(f"Remediation successful! Public access is blocked on {bucket_name}.")
        
        return {
            'statusCode': 200,
            'body': json.dumps(f"Remediation applied to {bucket_name}")
        }
        
    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        raise e
