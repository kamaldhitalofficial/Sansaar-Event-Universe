from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import EmailValidator
from django.utils import timezone
from datetime import timedelta
import uuid
import user_agents


class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication."""

    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with an email and password."""
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser with an email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if not extra_fields.get('is_staff'):
            raise ValueError('Superuser must have is_staff=True.')
        if not extra_fields.get('is_superuser'):
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model with email as the unique identifier."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()],
        help_text='Required. Enter a valid email address.'
    )
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)

    # Account status fields
    is_active = models.BooleanField(default=False)  # Requires email verification
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)

    # Timestamps
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)

    # Security fields
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
            models.Index(fields=['date_joined']),
        ]

    def __str__(self):
        """Return string representation of the user."""
        if self.first_name and self.last_name:
            return "{0} {1} ({2})".format(self.first_name, self.last_name, self.email)
        return self.email

    def get_full_name(self):
        """Return the full name of the user."""
        if self.first_name and self.last_name:
            full_name = "{0} {1}".format(self.first_name, self.last_name)
            return full_name.strip()
        return self.email

    def get_short_name(self):
        """Return the short name for the user."""
        if self.first_name:
            return self.first_name
        return self.email

    def clean(self):
        """Validate the user model."""
        super(User, self).clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def is_account_locked(self):
        """Check if the account is currently locked."""
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False

    def lock_account(self, duration_minutes=30):
        """Lock the account for the specified duration."""
        lock_until = timezone.now() + timedelta(minutes=duration_minutes)
        self.account_locked_until = lock_until
        self.save(update_fields=['account_locked_until'])

    def unlock_account(self):
        """Unlock the account and reset failed login attempts."""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['account_locked_until', 'failed_login_attempts'])

    def increment_failed_login(self):
        """Increment failed login attempts and lock account if threshold reached."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lock_account()
        self.save(update_fields=['failed_login_attempts'])

    def reset_failed_login_attempts(self):
        """Reset failed login attempts on successful login."""
        if self.failed_login_attempts > 0:
            self.failed_login_attempts = 0
            self.save(update_fields=['failed_login_attempts'])


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
        from .utils.device_detection import get_client_ip, detect_new_device

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


class EmailVerification(models.Model):
    """Model to handle email verification tokens for user account activation."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_verifications')

    # Token details
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    email = models.EmailField(validators=[EmailValidator()])

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)

    # Status tracking
    is_used = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)

    # Request tracking
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        db_table = 'auth_email_verification'
        verbose_name = 'Email Verification'
        verbose_name_plural = 'Email Verifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['email']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['is_used']),
        ]

    def __str__(self):
        status = "Verified" if self.is_used else "Pending"
        return f"{self.email} - {status} - {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"

    def save(self, *args, **kwargs):
        """Set expiration time if not provided."""
        if not self.expires_at:
            # Token expires in 24 hours
            self.expires_at = self.created_at + timedelta(hours=24)
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if the verification token has expired."""
        return timezone.now() > self.expires_at

    def is_valid(self):
        """Check if the token is valid (not used and not expired)."""
        return not self.is_used and not self.is_expired()

    def verify(self):
        """Mark the token as used and set verification timestamp."""
        if not self.is_valid():
            return False

        self.is_used = True
        self.verified_at = timezone.now()
        self.save(update_fields=['is_used', 'verified_at'])

        # Update user's email verification status
        self.user.is_email_verified = True
        self.user.is_active = True
        self.user.save(update_fields=['is_email_verified', 'is_active'])

        return True

    def increment_attempts(self):
        """Increment verification attempts counter."""
        self.attempts += 1
        self.save(update_fields=['attempts'])

    @classmethod
    def create_verification(cls, user, email=None, request=None):
        """
        Create a new email verification token for a user.

        Args:
            user: User instance
            email: Email to verify (defaults to user's email)
            request: Django request object for tracking

        Returns:
            EmailVerification instance
        """
        from .utils.device_detection import get_client_ip

        email = email or user.email
        ip_address = get_client_ip(request) if request else None
        user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''

        # Invalidate any existing unused tokens for this user and email
        cls.objects.filter(
            user=user,
            email=email,
            is_used=False
        ).update(is_used=True)

        verification = cls.objects.create(
            user=user,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent
        )

        return verification

    @classmethod
    def get_valid_token(cls, token):
        """
        Get a valid verification token.

        Args:
            token: UUID token string

        Returns:
            EmailVerification instance or None
        """
        try:
            verification = cls.objects.get(token=token)
            if verification.is_valid():
                return verification
        except cls.DoesNotExist:
            pass
        return None


class PasswordReset(models.Model):
    """Model to handle secure password reset functionality."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_resets')

    # Token details
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    email = models.EmailField(validators=[EmailValidator()])

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    # Status tracking
    is_used = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)

    # Request tracking
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Security tracking
    reset_ip_address = models.GenericIPAddressField(null=True, blank=True)
    reset_user_agent = models.TextField(blank=True)

    class Meta:
        db_table = 'auth_password_reset'
        verbose_name = 'Password Reset'
        verbose_name_plural = 'Password Resets'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['email']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['is_used']),
        ]

    def __str__(self):
        status = "Used" if self.is_used else "Pending"
        return f"{self.email} - {status} - {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}"

    def save(self, *args, **kwargs):
        """Set expiration time if not provided."""
        if not self.expires_at:
            # Token expires in 1 hour for security
            self.expires_at = self.created_at + timedelta(hours=1)
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if the reset token has expired."""
        return timezone.now() > self.expires_at

    def is_valid(self):
        """Check if the token is valid (not used and not expired)."""
        return not self.is_used and not self.is_expired()

    def use_token(self, request=None):
        """
        Mark the token as used and record usage details.

        Args:
            request: Django request object for tracking

        Returns:
            bool: True if token was successfully used
        """
        if not self.is_valid():
            return False

        from .utils.device_detection import get_client_ip

        self.is_used = True
        self.used_at = timezone.now()

        if request:
            self.reset_ip_address = get_client_ip(request)
            self.reset_user_agent = request.META.get('HTTP_USER_AGENT', '')

        self.save(update_fields=[
            'is_used', 'used_at', 'reset_ip_address', 'reset_user_agent'
        ])

        # Update user's password change timestamp
        self.user.password_changed_at = timezone.now()
        self.user.save(update_fields=['password_changed_at'])

        return True

    def increment_attempts(self):
        """Increment reset attempts counter."""
        self.attempts += 1
        self.save(update_fields=['attempts'])

    @classmethod
    def create_reset(cls, user, request=None):
        """
        Create a new password reset token for a user.

        Args:
            user: User instance
            request: Django request object for tracking

        Returns:
            PasswordReset instance
        """
        from .utils.device_detection import get_client_ip

        ip_address = get_client_ip(request) if request else None
        user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''

        # Invalidate any existing unused tokens for this user
        cls.objects.filter(
            user=user,
            is_used=False
        ).update(is_used=True)

        reset = cls.objects.create(
            user=user,
            email=user.email,
            ip_address=ip_address,
            user_agent=user_agent
        )

        return reset

    @classmethod
    def get_valid_token(cls, token):
        """
        Get a valid reset token.

        Args:
            token: UUID token string

        Returns:
            PasswordReset instance or None
        """
        try:
            reset = cls.objects.get(token=token)
            if reset.is_valid():
                return reset
        except cls.DoesNotExist:
            pass
        return None