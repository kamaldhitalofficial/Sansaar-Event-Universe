"""
Registration service for handling user registration logic.
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
import logging
import hashlib

User = get_user_model()
logger = logging.getLogger(__name__)


class RegistrationService:
    """
    Service class for handling user registration operations.
    """

    @staticmethod
    def create_user(validated_data, request=None):
        """
        Create a new user with the provided validated data and send verification email.

        Args:
            validated_data (dict): Validated user data from serializer
            request: Django request object for tracking

        Returns:
            tuple: (user: User, verification_sent: bool, message: str)
        """
        try:
            # Extract password
            password = validated_data.pop('password')

            # Create user (inactive by default)
            user = User.objects.create_user(
                password=password,
                is_active=False,  # Requires email verification
                **validated_data
            )

            # Send verification email
            from .email_service import EmailService
            success, message, verification = EmailService.send_verification_email(user, request)

            logger.info(f"User created successfully: {user.email}, verification email sent: {success}")
            return user, success, message

        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise

    @staticmethod
    def generate_verification_token(user):
        """
        Generate a unique verification token for email verification.

        Args:
            user (User): User instance

        Returns:
            str: Verification token
        """
        # Create a unique token based on user data and timestamp
        token_data = f"{user.id}{user.email}{timezone.now().isoformat()}"
        token = hashlib.sha256(token_data.encode()).hexdigest()

        # Store token in cache with 24-hour expiration
        cache_key = f"email_verification_{token}"
        cache.set(cache_key, {
            'user_id': str(user.id),
            'email': user.email,
            'created_at': timezone.now().isoformat()
        }, 86400)  # 24 hours

        logger.info(f"Verification token generated for user: {user.email}")
        return token

    @staticmethod
    def validate_verification_token(token):
        """
        Validate an email verification token.

        Args:
            token (str): Verification token

        Returns:
            dict or None: Token data if valid, None otherwise
        """
        cache_key = f"email_verification_{token}"
        token_data = cache.get(cache_key)

        if token_data:
            logger.info(f"Valid verification token found for user: {token_data.get('email')}")
            return token_data

        logger.warning(f"Invalid or expired verification token: {token}")
        return None

    @staticmethod
    def activate_user(token):
        """
        Activate a user account using verification token.

        Args:
            token (str): Verification token

        Returns:
            tuple: (success: bool, user: User or None, message: str)
        """
        token_data = RegistrationService.validate_verification_token(token)

        if not token_data:
            return False, None, "Invalid or expired verification token"

        try:
            user = User.objects.get(id=token_data['user_id'])

            if user.is_active and user.is_email_verified:
                return False, user, "Account is already activated"

            # Activate user
            user.is_active = True
            user.is_email_verified = True
            user.save(update_fields=['is_active', 'is_email_verified'])

            # Remove token from cache
            cache_key = f"email_verification_{token}"
            cache.delete(cache_key)

            logger.info(f"User account activated: {user.email}")
            return True, user, "Account activated successfully"

        except User.DoesNotExist:
            logger.error(f"User not found for verification token: {token_data.get('user_id')}")
            return False, None, "User not found"
        except Exception as e:
            logger.error(f"Failed to activate user: {e}")
            return False, None, "Activation failed"

    @staticmethod
    def resend_verification_email(email):
        """
        Resend verification email for a user.

        Args:
            email (str): User email address

        Returns:
            tuple: (success: bool, message: str)
        """
        from .email_service import EmailService
        return EmailService.resend_verification_email(email)

    @staticmethod
    def check_email_availability(email):
        """
        Check if an email address is available for registration.

        Args:
            email (str): Email address to check

        Returns:
            bool: True if available, False if taken
        """
        return not User.objects.filter(email=email).exists()

    @staticmethod
    def get_registration_stats():
        """
        Get registration statistics for monitoring.

        Returns:
            dict: Registration statistics
        """
        from datetime import timedelta

        now = timezone.now()
        today = now.date()
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)

        stats = {
            'total_users': User.objects.count(),
            'active_users': User.objects.filter(is_active=True).count(),
            'verified_users': User.objects.filter(is_email_verified=True).count(),
            'registrations_today': User.objects.filter(date_joined__date=today).count(),
            'registrations_this_week': User.objects.filter(date_joined__gte=week_ago).count(),
            'registrations_this_month': User.objects.filter(date_joined__gte=month_ago).count(),
            'pending_verification': User.objects.filter(
                is_active=False,
                is_email_verified=False
            ).count()
        }

        return stats