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
    'reset_profile'
]