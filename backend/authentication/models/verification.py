from django.db import models
from django.core.validators import EmailValidator
from django.utils import timezone
from datetime import timedelta
import uuid
from .user import User


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
        from ..utils.device_detection import get_client_ip

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

        from ..utils.device_detection import get_client_ip

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
        from ..utils.device_detection import get_client_ip

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