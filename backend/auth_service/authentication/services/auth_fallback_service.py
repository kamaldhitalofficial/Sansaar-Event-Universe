import logging
from typing import Dict, List, Optional, Any
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
from authentication.models import SocialAccount
from authentication.services.email_service import EmailService

User = get_user_model()
logger = logging.getLogger(__name__)


class AuthenticationFallbackService:
    """Service for handling authentication fallbacks when social auth fails."""

    FALLBACK_CACHE_PREFIX = 'auth_fallback'
    FALLBACK_CACHE_TIMEOUT = 3600  # 1 hour

    def __init__(self):
        self.email_service = EmailService()

    def record_social_auth_failure(self, provider: str, error_code: str, user_email: Optional[str] = None,
                                   error_details: Optional[Dict] = None) -> str:
        """
        Record a social authentication failure for monitoring and fallback.

        Args:
            provider: Social provider name (e.g., 'google')
            error_code: OAuth error code
            user_email: User email if available
            error_details: Additional error information

        Returns:
            Fallback session ID for tracking
        """
        import uuid

        fallback_id = str(uuid.uuid4())

        failure_data = {
            'provider': provider,
            'error_code': error_code,
            'user_email': user_email,
            'error_details': error_details or {},
            'timestamp': timezone.now().isoformat(),
            'fallback_options': self._get_fallback_options(provider, user_email),
            'retry_count': 0
        }

        # Cache the failure data
        cache_key = f"{self.FALLBACK_CACHE_PREFIX}:{fallback_id}"
        cache.set(cache_key, failure_data, self.FALLBACK_CACHE_TIMEOUT)

        # Log the failure
        logger.warning(f"Social auth failure recorded: {provider} - {error_code} - {user_email}")

        # Send notification email if user email is available
        if user_email and error_code not in ['access_denied']:  # Don't email for user cancellations
            self._send_fallback_notification_email(user_email, provider, fallback_id)

        return fallback_id

    def get_fallback_options(self, fallback_id: str) -> Dict[str, Any]:
        """
        Get available fallback options for a failed authentication attempt.

        Args:
            fallback_id: Fallback session ID

        Returns:
            Dict with fallback options and recommendations
        """
        cache_key = f"{self.FALLBACK_CACHE_PREFIX}:{fallback_id}"
        failure_data = cache.get(cache_key)

        if not failure_data:
            return {
                'success': False,
                'error': 'Fallback session not found or expired'
            }

        provider = failure_data['provider']
        error_code = failure_data['error_code']
        user_email = failure_data.get('user_email')

        # Get current fallback options
        fallback_options = self._get_fallback_options(provider, user_email)

        # Add retry recommendation based on error type
        retry_recommendation = self._get_retry_recommendation(error_code, failure_data['retry_count'])

        return {
            'success': True,
            'provider': provider,
            'error_code': error_code,
            'user_email': user_email,
            'fallback_options': fallback_options,
            'retry_recommendation': retry_recommendation,
            'failure_timestamp': failure_data['timestamp']
        }

    def _get_fallback_options(self, provider: str, user_email: Optional[str] = None) -> Dict[str, Any]:
        """Get available fallback authentication options."""
        options = {
            'email_password_login': {
                'available': True,
                'url': '/auth/login/',
                'description': 'Sign in with email and password',
                'priority': 1
            },
            'password_reset': {
                'available': bool(user_email),
                'url': '/auth/password-reset/',
                'description': 'Reset your password if you forgot it',
                'priority': 2
            },
            'registration': {
                'available': True,
                'url': '/auth/register/',
                'description': 'Create a new account with email',
                'priority': 3
            },
            'contact_support': {
                'available': True,
                'url': '/support/contact/',
                'description': 'Contact support for help',
                'priority': 4
            }
        }

        # Check if user exists for better recommendations
        if user_email:
            try:
                user = User.objects.get(email=user_email)

                # User exists - prioritize login and password reset
                options['email_password_login']['priority'] = 1
                options['password_reset']['priority'] = 2
                options['registration']['available'] = False

                # Check if user has other social accounts
                other_social_accounts = SocialAccount.objects.filter(
                    user=user,
                    is_active=True
                ).exclude(provider=provider)

                if other_social_accounts.exists():
                    for account in other_social_accounts:
                        options[f'{account.provider}_login'] = {
                            'available': True,
                            'url': f'/auth/{account.provider}/login/',
                            'description': f'Sign in with {account.provider.title()}',
                            'priority': 1
                        }

            except User.DoesNotExist:
                # User doesn't exist - prioritize registration
                options['registration']['priority'] = 1
                options['email_password_login']['priority'] = 2
                options['password_reset']['available'] = False

        return options

    def _get_retry_recommendation(self, error_code: str, retry_count: int) -> Dict[str, Any]:
        """Get recommendation for retrying social authentication."""
        retry_recommendations = {
            'access_denied': {
                'should_retry': False,
                'message': 'User cancelled authentication. Try alternative login methods.',
                'wait_time': None
            },
            'invalid_request': {
                'should_retry': True,
                'message': 'There was a technical issue. Please try again.',
                'wait_time': 30  # seconds
            },
            'server_error': {
                'should_retry': retry_count < 3,
                'message': 'Google services are temporarily unavailable. Try again in a few minutes.',
                'wait_time': 300  # 5 minutes
            },
            'temporarily_unavailable': {
                'should_retry': retry_count < 2,
                'message': 'Service temporarily unavailable. Please try again later.',
                'wait_time': 600  # 10 minutes
            },
            'rate_limit_exceeded': {
                'should_retry': retry_count < 1,
                'message': 'Too many attempts. Please wait before trying again.',
                'wait_time': 1800  # 30 minutes
            }
        }

        default_recommendation = {
            'should_retry': retry_count < 2,
            'message': 'Authentication failed. You can try again or use alternative login methods.',
            'wait_time': 60
        }

        recommendation = retry_recommendations.get(error_code, default_recommendation)

        # Adjust based on retry count
        if retry_count >= 3:
            recommendation['should_retry'] = False
            recommendation[
                'message'] = 'Multiple attempts failed. Please use alternative login methods or contact support.'

        return recommendation

    def increment_retry_count(self, fallback_id: str) -> bool:
        """
        Increment retry count for a fallback session.

        Args:
            fallback_id: Fallback session ID

        Returns:
            True if increment was successful, False if session not found
        """
        cache_key = f"{self.FALLBACK_CACHE_PREFIX}:{fallback_id}"
        failure_data = cache.get(cache_key)

        if not failure_data:
            return False

        failure_data['retry_count'] += 1
        failure_data['last_retry'] = timezone.now().isoformat()

        cache.set(cache_key, failure_data, self.FALLBACK_CACHE_TIMEOUT)
        return True

    def _send_fallback_notification_email(self, user_email: str, provider: str, fallback_id: str):
        """Send email notification about authentication failure with fallback options."""
        try:
            # This would typically send an email with fallback options
            # For now, we'll just log it
            logger.info(f"Fallback notification email would be sent to {user_email} for {provider} failure")

            # In a real implementation:
            # self.email_service.send_auth_fallback_email(user_email, provider, fallback_id)

        except Exception as e:
            logger.error(f"Failed to send fallback notification email: {e}")

    def get_provider_health_status(self, provider: str) -> Dict[str, Any]:
        """
        Get health status for a social authentication provider.

        Args:
            provider: Provider name (e.g., 'google')

        Returns:
            Dict with provider health information
        """
        # Get recent failures from cache
        cache_pattern = f"{self.FALLBACK_CACHE_PREFIX}:*"

        # In a real implementation, you'd query a proper monitoring system
        # For now, we'll return a basic status

        return {
            'provider': provider,
            'status': 'operational',  # operational, degraded, outage
            'last_checked': timezone.now().isoformat(),
            'recent_failures': 0,
            'success_rate': 95.0,
            'average_response_time': 1200,  # milliseconds
            'recommended_action': 'none'  # none, retry, fallback
        }

    def get_system_wide_fallback_stats(self) -> Dict[str, Any]:
        """Get system-wide authentication fallback statistics."""
        # This would typically query a monitoring database
        # For now, return mock data structure

        return {
            'total_auth_attempts': 1000,
            'successful_auths': 950,
            'failed_auths': 50,
            'fallback_usage': {
                'email_password': 30,
                'password_reset': 15,
                'registration': 5
            },
            'provider_stats': {
                'google': {
                    'attempts': 500,
                    'successes': 475,
                    'failures': 25,
                    'common_errors': ['server_error', 'temporarily_unavailable']
                }
            },
            'time_period': '24h',
            'last_updated': timezone.now().isoformat()
        }

    def cleanup_expired_fallback_sessions(self) -> int:
        """
        Clean up expired fallback sessions from cache.

        Returns:
            Number of sessions cleaned up
        """
        # This would typically be run as a periodic task
        # Django cache handles TTL automatically, but we could implement
        # additional cleanup logic here if needed

        logger.info("Fallback session cleanup completed")
        return 0  # Cache handles TTL automatically

    def create_fallback_recovery_link(self, user_email: str, provider: str) -> Optional[str]:
        """
        Create a recovery link for users who can't authenticate via social providers.

        Args:
            user_email: User's email address
            provider: Failed social provider

        Returns:
            Recovery link URL or None if user not found
        """
        try:
            user = User.objects.get(email=user_email)

            # Generate a secure recovery token
            import secrets
            recovery_token = secrets.token_urlsafe(32)

            # Store recovery token in cache
            recovery_data = {
                'user_id': str(user.id),
                'email': user_email,
                'provider': provider,
                'created_at': timezone.now().isoformat(),
                'used': False
            }

            cache_key = f"auth_recovery:{recovery_token}"
            cache.set(cache_key, recovery_data, 3600)  # 1 hour expiry

            # Build recovery URL
            recovery_url = f"/auth/recover/{recovery_token}/"

            logger.info(f"Created recovery link for {user_email} after {provider} failure")
            return recovery_url

        except User.DoesNotExist:
            logger.warning(f"Cannot create recovery link for non-existent user: {user_email}")
            return None
        except Exception as e:
            logger.error(f"Error creating recovery link: {e}")
            return None