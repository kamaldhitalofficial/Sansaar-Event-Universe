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
    'ProfileVisibilitySerializer'
]