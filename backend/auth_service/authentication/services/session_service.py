"""
Session management service for tracking user sessions and tokens.
"""
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from django.contrib.auth import get_user_model
from ..models import UserSession, LoginHistory
from ..utils.device_detection import get_client_ip, get_device_fingerprint
import logging
import user_agents

User = get_user_model()
logger = logging.getLogger(__name__)


class SessionService:
    """Service for managing user sessions and tokens."""

    @staticmethod
    def create_session(user, request, token_id, expires_at):
        """
        Create a new user session.

        Args:
            user: User instance
            request: Django request object
            token_id: JWT token ID
            expires_at: Session expiration datetime

        Returns:
            UserSession instance
        """
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Parse user agent for device info
        device_info = SessionService._parse_user_agent(user_agent)

        # Create session
        session = UserSession.objects.create(
            user=user,
            session_key=f"session_{token_id}",
            token_id=token_id,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            device_type=device_info['device_type'],
            browser=device_info['browser'],
            operating_system=device_info['operating_system']
        )

        logger.info(f"Session created for user {user.email} with token_id {token_id}")
        return session

    @staticmethod
    def get_session_by_token_id(token_id):
        """
        Get session by token ID.

        Args:
            token_id: JWT token ID

        Returns:
            UserSession instance or None
        """
        try:
            return UserSession.objects.get(token_id=token_id, is_active=True)
        except UserSession.DoesNotExist:
            return None

    @staticmethod
    def get_user_sessions(user_id, active_only=True):
        """
        Get all sessions for a user.

        Args:
            user_id: User ID
            active_only: Whether to return only active sessions

        Returns:
            QuerySet of UserSession instances
        """
        queryset = UserSession.objects.filter(user_id=user_id)
        if active_only:
            queryset = queryset.filter(is_active=True)
        return queryset.order_by('-last_activity')

    @staticmethod
    def terminate_session(token_id, reason='manual_logout'):
        """
        Terminate a session by token ID.

        Args:
            token_id: JWT token ID
            reason: Reason for termination

        Returns:
            bool: True if session was terminated
        """
        try:
            session = UserSession.objects.get(token_id=token_id, is_active=True)
            session.terminate(reason)
            logger.info(f"Session terminated for token_id {token_id}, reason: {reason}")
            return True
        except UserSession.DoesNotExist:
            logger.warning(f"Attempted to terminate non-existent session: {token_id}")
            return False

    @staticmethod
    def terminate_all_user_sessions(user_id, reason='password_change', exclude_token_id=None):
        """
        Terminate all sessions for a user.

        Args:
            user_id: User ID
            reason: Reason for termination
            exclude_token_id: Token ID to exclude from termination

        Returns:
            int: Number of sessions terminated
        """
        queryset = UserSession.objects.filter(user_id=user_id, is_active=True)

        if exclude_token_id:
            queryset = queryset.exclude(token_id=exclude_token_id)

        count = 0
        for session in queryset:
            session.terminate(reason)
            count += 1

        logger.info(f"Terminated {count} sessions for user {user_id}, reason: {reason}")
        return count

    @staticmethod
    def update_session_activity(token_id):
        """
        Update last activity for a session.

        Args:
            token_id: JWT token ID
        """
        try:
            session = UserSession.objects.get(token_id=token_id, is_active=True)
            session.update_activity()
        except UserSession.DoesNotExist:
            pass  # Session might have been terminated

    @staticmethod
    def cleanup_expired_sessions():
        """
        Clean up expired sessions.

        Returns:
            int: Number of sessions cleaned up
        """
        expired_sessions = UserSession.objects.filter(
            is_active=True,
            expires_at__lt=timezone.now()
        )

        count = 0
        for session in expired_sessions:
            session.terminate('expired')
            count += 1

        logger.info(f"Cleaned up {count} expired sessions")
        return count

    @staticmethod
    def get_session_summary(user_id):
        """
        Get session summary for a user.

        Args:
            user_id: User ID

        Returns:
            dict: Session summary
        """
        active_sessions = SessionService.get_user_sessions(user_id, active_only=True)

        summary = {
            'total_active_sessions': active_sessions.count(),
            'sessions': []
        }

        for session in active_sessions[:10]:  # Limit to 10 most recent
            summary['sessions'].append({
                'token_id': session.token_id,
                'device_type': session.device_type,
                'browser': session.browser,
                'operating_system': session.operating_system,
                'ip_address': session.ip_address,
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'is_current': False  # This would be set by the calling code
            })

        return summary

    @staticmethod
    def _parse_user_agent(user_agent):
        """
        Parse user agent string to extract device information.

        Args:
            user_agent: User agent string

        Returns:
            dict: Device information
        """
        try:
            ua = user_agents.parse(user_agent)

            # Device type
            if ua.is_mobile:
                device_type = 'mobile'
            elif ua.is_tablet:
                device_type = 'tablet'
            else:
                device_type = 'desktop'

            # Browser information
            browser = 'unknown'
            if ua.browser.family:
                browser_version = f" {ua.browser.version_string}" if ua.browser.version_string else ""
                browser = f"{ua.browser.family}{browser_version}"

            # Operating system
            operating_system = 'unknown'
            if ua.os.family:
                os_version = f" {ua.os.version_string}" if ua.os.version_string else ""
                operating_system = f"{ua.os.family}{os_version}"

            return {
                'device_type': device_type,
                'browser': browser,
                'operating_system': operating_system
            }

        except Exception as e:
            logger.warning(f"Failed to parse user agent: {str(e)}")
            return {
                'device_type': 'unknown',
                'browser': 'unknown',
                'operating_system': 'unknown'
            }