from django.db import models
from django.utils import timezone
import uuid
import user_agents
from .user import User


class LoginHistory(models.Model):
    """Model to track user login history and device information."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_history')

    # Login attempt details
    login_time = models.DateTimeField(default=timezone.now)
    success = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=100, blank=True, null=True)

    # Device and location information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    device_type = models.CharField(max_length=50, blank=True)  # mobile, desktop, tablet
    browser = models.CharField(max_length=100, blank=True)
    operating_system = models.CharField(max_length=100, blank=True)

    # Geographic information (basic)
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)

    # Security flags
    is_suspicious = models.BooleanField(default=False)
    is_new_device = models.BooleanField(default=False)

    # Session information
    session_id = models.CharField(max_length=255, blank=True, null=True)
    token_id = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        db_table = 'auth_login_history'
        verbose_name = 'Login History'
        verbose_name_plural = 'Login Histories'
        ordering = ['-login_time']
        indexes = [
            models.Index(fields=['user', '-login_time']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['success']),
            models.Index(fields=['is_suspicious']),
            models.Index(fields=['login_time']),
        ]

    def __str__(self):
        status = "Success" if self.success else f"Failed ({self.failure_reason})"
        return f"{self.user.email} - {status} - {self.login_time.strftime('%Y-%m-%d %H:%M:%S')}"

    def save(self, *args, **kwargs):
        """Parse user agent information before saving."""
        if self.user_agent and not self.browser:
            self._parse_user_agent()
        super().save(*args, **kwargs)

    def _parse_user_agent(self):
        """Parse user agent string to extract device information."""
        try:
            ua = user_agents.parse(self.user_agent)

            # Device type
            if ua.is_mobile:
                self.device_type = 'mobile'
            elif ua.is_tablet:
                self.device_type = 'tablet'
            else:
                self.device_type = 'desktop'

            # Browser information
            if ua.browser.family:
                browser_version = f" {ua.browser.version_string}" if ua.browser.version_string else ""
                self.browser = f"{ua.browser.family}{browser_version}"

            # Operating system
            if ua.os.family:
                os_version = f" {ua.os.version_string}" if ua.os.version_string else ""
                self.operating_system = f"{ua.os.family}{os_version}"

        except Exception as e:
            # If parsing fails, just store basic info
            self.device_type = 'unknown'
            self.browser = 'unknown'
            self.operating_system = 'unknown'

    @classmethod
    def create_login_attempt(cls, user, request, success=False, failure_reason=None, token_id=None):
        """
        Create a login history entry.

        Args:
            user: User instance
            request: Django request object
            success: Whether login was successful
            failure_reason: Reason for failure if applicable
            token_id: JWT token ID if login was successful

        Returns:
            LoginHistory instance
        """
        from ..utils.device_detection import get_client_ip, detect_new_device

        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Check if this is a new device
        is_new_device = detect_new_device(user, ip_address, user_agent) if success else False

        login_entry = cls.objects.create(
            user=user,
            success=success,
            failure_reason=failure_reason,
            ip_address=ip_address,
            user_agent=user_agent,
            is_new_device=is_new_device,
            token_id=token_id
        )

        return login_entry


class UserSession(models.Model):
    """Model to track active user sessions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')

    # Session details
    session_key = models.CharField(max_length=255, unique=True)
    token_id = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()

    # Device information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    device_type = models.CharField(max_length=50, blank=True)
    browser = models.CharField(max_length=100, blank=True)
    operating_system = models.CharField(max_length=100, blank=True)

    # Session status
    is_active = models.BooleanField(default=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    logout_reason = models.CharField(max_length=100, blank=True, null=True)

    class Meta:
        db_table = 'auth_user_session'
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user', '-last_activity']),
            models.Index(fields=['token_id']),
            models.Index(fields=['is_active']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.device_type} - {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"

    def is_expired(self):
        """Check if the session has expired."""
        return timezone.now() > self.expires_at

    def terminate(self, reason='manual_logout'):
        """Terminate the session."""
        self.is_active = False
        self.logout_time = timezone.now()
        self.logout_reason = reason
        self.save(update_fields=['is_active', 'logout_time', 'logout_reason'])

    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])