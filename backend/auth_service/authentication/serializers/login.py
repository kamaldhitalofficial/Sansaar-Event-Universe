"""
Authentication serializers for login, logout, and token management.
"""
import logging
from django.contrib.auth import get_user_model
from django.core.validators import EmailValidator
from django.utils import timezone
from rest_framework import serializers

User = get_user_model()
logger = logging.getLogger(__name__)


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login with comprehensive validation.
    """
    email = serializers.EmailField(
        validators=[EmailValidator(message="Enter a valid email address.")]
    )
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    remember_me = serializers.BooleanField(default=False, required=False)

    def validate(self, attrs):
        """
        Validate login credentials and check account status.
        """
        email = attrs.get('email', '').lower().strip()
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError({
                'non_field_errors': ['Email and password are required.']
            })

        # Get user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'non_field_errors': ['Invalid email or password.']
            })

        # Check if account is locked
        if user.is_account_locked():
            lock_time_remaining = user.account_locked_until - timezone.now()
            minutes_remaining = int(lock_time_remaining.total_seconds() / 60)
            raise serializers.ValidationError({
                'non_field_errors': [
                    f'Account is locked due to multiple failed login attempts. '
                    f'Please try again in {minutes_remaining} minutes.'
                ]
            })

        # Check if account is active
        if not user.is_active:
            raise serializers.ValidationError({
                'non_field_errors': ['Account is not active. Please verify your email address.']
            })

        # Authenticate user
        if not user.check_password(password):
            # Increment failed login attempts
            user.increment_failed_login()

            # Log failed attempt
            logger.warning(f"Failed login attempt for user: {email}")

            raise serializers.ValidationError({
                'non_field_errors': ['Invalid email or password.']
            })

        # Reset failed login attempts on successful authentication
        user.reset_failed_login_attempts()

        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        attrs['user'] = user
        return attrs


class TokenRefreshSerializer(serializers.Serializer):
    """
    Serializer for refreshing access tokens.
    """
    refresh_token = serializers.CharField(write_only=True)

    def validate_refresh_token(self, value):
        """
        Validate the refresh token using SimpleJWT.
        """
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

        try:
            RefreshToken(value)
        except (InvalidToken, TokenError) as e:
            raise serializers.ValidationError(f'Invalid refresh token: {str(e)}')

        return value


class LogoutSerializer(serializers.Serializer):
    """
    Serializer for user logout.
    """
    logout_all_devices = serializers.BooleanField(default=False, required=False)