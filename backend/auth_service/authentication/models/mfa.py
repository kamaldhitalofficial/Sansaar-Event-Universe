from django.db import models
from django.utils import timezone
from django.core.validators import RegexValidator
import uuid
import secrets
import string
from .user import User


class MFADevice(models.Model):
    """Model for Multi-Factor Authentication devices supporting TOTP."""

    MFA_TYPE_CHOICES = [
        ('totp', 'Time-based One-Time Password'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='mfa_devices'
    )

    # Device information
    device_name = models.CharField(
        max_length=100,
        help_text='User-friendly name for the device (e.g., "iPhone Authenticator")'
    )
    mfa_type = models.CharField(
        max_length=10,
        choices=MFA_TYPE_CHOICES,
        default='totp'
    )

    # TOTP specific fields
    secret_key = models.CharField(
        max_length=32,
        help_text='Base32 encoded secret key for TOTP generation'
    )

    # Status and metadata
    is_active = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    verified_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    # Security fields
    failed_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'auth_mfa_device'
        verbose_name = 'MFA Device'
        verbose_name_plural = 'MFA Devices'
        unique_together = ['user', 'device_name']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.device_name} ({self.mfa_type.upper()})"

    def is_locked(self):
        """Check if the MFA device is currently locked due to failed attempts."""
        if self.locked_until:
            return timezone.now() < self.locked_until
        return False

    def increment_failed_attempts(self):
        """Increment failed attempts and lock device if threshold reached."""
        self.failed_attempts += 1
        if self.failed_attempts >= 5:  # Lock after 5 failed attempts
            from datetime import timedelta
            self.locked_until = timezone.now() + timedelta(minutes=15)
        self.save(update_fields=['failed_attempts', 'locked_until'])

    def reset_failed_attempts(self):
        """Reset failed attempts on successful verification."""
        if self.failed_attempts > 0 or self.locked_until:
            self.failed_attempts = 0
            self.locked_until = None
            self.save(update_fields=['failed_attempts', 'locked_until'])

    def mark_as_used(self):
        """Mark the device as recently used."""
        self.last_used_at = timezone.now()
        self.save(update_fields=['last_used_at'])

    def verify_device(self):
        """Mark the device as verified and active."""
        self.is_verified = True
        self.is_active = True
        self.verified_at = timezone.now()
        self.save(update_fields=['is_verified', 'is_active', 'verified_at'])


class MFABackupCode(models.Model):
    """Model for MFA backup codes for account recovery."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='mfa_backup_codes'
    )

    # Backup code (hashed for security)
    code_hash = models.CharField(
        max_length=128,
        help_text='Hashed backup code for security'
    )

    # Status
    is_used = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'auth_mfa_backup_code'
        verbose_name = 'MFA Backup Code'
        verbose_name_plural = 'MFA Backup Codes'
        indexes = [
            models.Index(fields=['user', 'is_used']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        status = "Used" if self.is_used else "Available"
        return f"{self.user.email} - Backup Code ({status})"

    def mark_as_used(self):
        """Mark the backup code as used."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])

    @classmethod
    def generate_codes_for_user(cls, user, count=10):
        """Generate backup codes for a user."""
        from django.contrib.auth.hashers import make_password

        # Delete existing unused backup codes
        cls.objects.filter(user=user, is_used=False).delete()

        codes = []
        backup_codes = []

        for _ in range(count):
            # Generate a random 8-character alphanumeric code
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            codes.append(code)

            # Create backup code with hashed value
            backup_code = cls(
                user=user,
                code_hash=make_password(code)
            )
            backup_codes.append(backup_code)

        # Bulk create backup codes
        cls.objects.bulk_create(backup_codes)

        return codes  # Return plain text codes for user to save


class TrustedDevice(models.Model):
    """Model for tracking trusted devices for MFA bypass."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='trusted_devices'
    )

    # Device identification
    device_fingerprint = models.CharField(
        max_length=128,
        help_text='Unique fingerprint for device identification'
    )
    device_name = models.CharField(
        max_length=100,
        help_text='User-friendly device name'
    )

    # Device metadata
    user_agent = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField()

    # Status
    is_active = models.BooleanField(default=True)

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    last_used_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(
        help_text='When this trusted device expires (default 30 days)'
    )

    class Meta:
        db_table = 'auth_trusted_device'
        verbose_name = 'Trusted Device'
        verbose_name_plural = 'Trusted Devices'
        unique_together = ['user', 'device_fingerprint']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['device_fingerprint']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.device_name}"

    def is_expired(self):
        """Check if the trusted device has expired."""
        return timezone.now() > self.expires_at

    def is_valid(self):
        """Check if the trusted device is valid (active and not expired)."""
        return self.is_active and not self.is_expired()

    def extend_expiry(self, days=30):
        """Extend the expiry date of the trusted device."""
        from datetime import timedelta
        self.expires_at = timezone.now() + timedelta(days=days)
        self.last_used_at = timezone.now()
        self.save(update_fields=['expires_at', 'last_used_at'])

    def revoke(self):
        """Revoke the trusted device."""
        self.is_active = False
        self.save(update_fields=['is_active'])

    @classmethod
    def create_trusted_device(cls, user, device_fingerprint, device_name, user_agent='', ip_address='127.0.0.1',
                              days=30):
        """Create a new trusted device for a user."""
        from datetime import timedelta

        # Deactivate existing device with same fingerprint
        cls.objects.filter(
            user=user,
            device_fingerprint=device_fingerprint
        ).update(is_active=False)

        # Create new trusted device
        expires_at = timezone.now() + timedelta(days=days)

        return cls.objects.create(
            user=user,
            device_fingerprint=device_fingerprint,
            device_name=device_name,
            user_agent=user_agent,
            ip_address=ip_address,
            expires_at=expires_at
        )