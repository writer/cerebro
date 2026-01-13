"""AWS finding producers."""

from .bucket_cleartext_key import AwsBucketCleartextKeyProducer
from .codebuild_public_trigger import AwsCodeBuildPublicTriggerProducer
from .codebuild_source_credential import AwsCodeBuildSourceCredentialProducer
from .ec2_instance_public_ip import Ec2InstancePublicIpProducer
from .ec2_internet_facing_iam import EC2InternetFacingIAMProducer
from .iam_user_without_mfa import AwsIamUserWithoutMfaProducer
from .load_balancer_certificate_expiry import AwsLoadBalancerCertificateExpiryProducer
from .load_balancer_missing_https import AwsLoadBalancerMissingHttpsProducer
from .load_balancer_public_http import AwsLoadBalancerPublicHttpProducer
from .load_balancer_target_exposure import AwsLoadBalancerTargetExposureProducer
from .load_balancer_weak_tls import AwsLoadBalancerWeakTlsProducer
from .s3_bucket_public import AwsS3BucketPublicProducer
from .s3_bucket_unencrypted import AwsS3BucketUnencryptedProducer
from .security_group_admin_port import AwsSecurityGroupAdminPortProducer
from .security_group_public_ingress import AwsSecurityGroupPublicIngressProducer
from .service_account_open_assume import AwsServiceAccountOpenAssumeProducer
from .storage_write_access import AwsStorageWriteAccessProducer

__all__ = [
    "AwsBucketCleartextKeyProducer",
    "AwsCodeBuildPublicTriggerProducer",
    "AwsCodeBuildSourceCredentialProducer",
    "AwsIamUserWithoutMfaProducer",
    "AwsLoadBalancerCertificateExpiryProducer",
    "AwsLoadBalancerMissingHttpsProducer",
    "AwsLoadBalancerPublicHttpProducer",
    "AwsLoadBalancerTargetExposureProducer",
    "AwsLoadBalancerWeakTlsProducer",
    "AwsS3BucketPublicProducer",
    "AwsS3BucketUnencryptedProducer",
    "AwsSecurityGroupAdminPortProducer",
    "AwsSecurityGroupPublicIngressProducer",
    "AwsServiceAccountOpenAssumeProducer",
    "AwsStorageWriteAccessProducer",
    "EC2InternetFacingIAMProducer",
    "Ec2InstancePublicIpProducer",
]
