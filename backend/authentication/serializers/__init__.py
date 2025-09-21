"""
Serializers package for authentication app.
"""
import logging

# Create logger for serializers
logger = logging.getLogger(__name__)

from .registration import UserRegistrationSerializer
from .login import (
    UserLoginSerializer,
    TokenRefreshSerializer,
    LogoutSerializer
)
from .profile import (
    UserProfileSerializer,
    UserProfileUpdateSerializer,
    UserProfileHistorySerializer,
    ProfileCompletionSerializer,
    ProfileVisibilitySerializer
)
from .privacy import (
    PrivacySettingsSerializer,
    PrivacySettingsUpdateSerializer,
    ConsentManagementSerializer,
    PrivacyTemplateSerializer,
    PrivacySettingsHistorySerializer,
    DataExportRequestSerializer,
    AccountDeletionRequestSerializer,
    PrivacyComplianceReportSerializer
)
from .mfa import (
    MFASetupSerializer,
    MFASetupResponseSerializer,
    MFAVerificationSerializer,
    MFALoginVerificationSerializer,
    MFAStatusSerializer,
    MFADeviceSerializer,
    TrustedDeviceSerializer,
    MFADisableSerializer,
    BackupCodesRegenerateSerializer,
    BackupCodesResponseSerializer,
    MFARecoveryRequestSerializer,
    MFARecoveryVerifySerializer,
    TrustedDeviceRevokeSerializer
)

__all__ = [
    # Registration
    'UserRegistrationSerializer',

    # Authentication
    'UserLoginSerializer',
    'TokenRefreshSerializer',
    'LogoutSerializer',

    # Profile
    'UserProfileSerializer',
    'UserProfileUpdateSerializer',
    'UserProfileHistorySerializer',
    'ProfileCompletionSerializer',
    'ProfileVisibilitySerializer',

    # Privacy
    'PrivacySettingsSerializer',
    'PrivacySettingsUpdateSerializer',
    'ConsentManagementSerializer',
    'PrivacyTemplateSerializer',
    'PrivacySettingsHistorySerializer',
    'DataExportRequestSerializer',
    'AccountDeletionRequestSerializer',
    'PrivacyComplianceReportSerializer',

    # MFA
    'MFASetupSerializer',
    'MFASetupResponseSerializer',
    'MFAVerificationSerializer',
    'MFALoginVerificationSerializer',
    'MFAStatusSerializer',
    'MFADeviceSerializer',
    'TrustedDeviceSerializer',
    'MFADisableSerializer',
    'BackupCodesRegenerateSerializer',
    'BackupCodesResponseSerializer',
    'MFARecoveryRequestSerializer',
    'MFARecoveryVerifySerializer',
    'TrustedDeviceRevokeSerializer'
]