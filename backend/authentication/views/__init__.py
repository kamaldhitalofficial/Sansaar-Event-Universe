"""
Views package for authentication app.
"""

from .registration import (
    register_user,
    registration_status,
    check_email_availability,
    verify_email,
    resend_verification_email
)
from .login import (
    login_user,
    logout_user,
    refresh_token
)
from .session import (
    get_user_sessions,
    terminate_session
)
from .profile import (
    get_profile,
    update_profile,
    upload_profile_picture,
    delete_profile_picture,
    get_profile_completion,
    update_privacy_settings,
    update_communication_preferences,
    get_profile_history,
    get_profile_statistics,
    get_public_profile,
    delete_profile,
    reset_profile
)
from .privacy import (
    get_privacy_settings,
    update_privacy_settings as update_privacy_settings_new,
    manage_consent,
    apply_privacy_template,
    export_user_data,
    request_account_deletion,
    get_privacy_history,
    get_privacy_compliance_report,
    complete_privacy_review
)
from .mfa import (
    mfa_status,
    mfa_setup,
    mfa_verify_setup,
    mfa_verify_login,
    mfa_disable,
    mfa_regenerate_backup_codes,
    mfa_devices,
    trusted_devices,
    revoke_trusted_device,
    mfa_recovery_request,
    mfa_recovery_verify,
    check_trusted_device
)

__all__ = [
    # Registration
    'register_user',
    'registration_status',
    'check_email_availability',
    'verify_email',
    'resend_verification_email',

    # Authentication
    'login_user',
    'logout_user',
    'refresh_token',

    # Session
    'get_user_sessions',
    'terminate_session',

    # Profile
    'get_profile',
    'update_profile',
    'upload_profile_picture',
    'delete_profile_picture',
    'get_profile_completion',
    'update_privacy_settings',
    'update_communication_preferences',
    'get_profile_history',
    'get_profile_statistics',
    'get_public_profile',
    'delete_profile',
    'reset_profile',

    # Privacy
    'get_privacy_settings',
    'update_privacy_settings_new',
    'manage_consent',
    'apply_privacy_template',
    'export_user_data',
    'request_account_deletion',
    'get_privacy_history',
    'get_privacy_compliance_report',
    'complete_privacy_review',

    # MFA
    'mfa_status',
    'mfa_setup',
    'mfa_verify_setup',
    'mfa_verify_login',
    'mfa_disable',
    'mfa_regenerate_backup_codes',
    'mfa_devices',
    'trusted_devices',
    'revoke_trusted_device',
    'mfa_recovery_request',
    'mfa_recovery_verify',
    'check_trusted_device'
]