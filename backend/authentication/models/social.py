from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
import uuid
import json


class SocialAccount(models.Model):
    """Model to link social accounts (Google) with User accounts."""

    PROVIDER_CHOICES = [
        ('google', 'Google'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        'authentication.User',
        on_delete=models.CASCADE,
        related_name='social_accounts'
    )
    provider = models.CharField(
        max_length=50,
        choices=PROVIDER_CHOICES,
        help_text='Social authentication provider'
    )
    provider_id = models.CharField(
        max_length=255,
        help_text='Unique identifier from the social provider'
    )
    email = models.EmailField(
        help_text='Email address from the social provider'
    )

    # Profile information from social provider
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    profile_picture_url = models.URLField(blank=True, null=True)

    # Token information
    access_token = models.TextField(
        blank=True,
        help_text='OAuth access token (encrypted in production)'
    )
    refresh_token = models.TextField(
        blank=True,
        help_text='OAuth refresh token (encrypted in production)'
    )
    token_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the access token expires'
    )

    # Additional provider data
    extra_data = models.JSONField(
        default=dict,
        blank=True,
        help_text='Additional data from the social provider'
    )

    # Metadata
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this social account is active'
    )
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'auth_social_account'
        verbose_name = 'Social Account'
        verbose_name_plural = 'Social Accounts'
        unique_together = [
            ('provider', 'provider_id'),
            ('user', 'provider'),
        ]
        indexes = [
            models.Index(fields=['provider', 'provider_id']),
            models.Index(fields=['user', 'provider']),
            models.Index(fields=['email']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.provider} ({self.provider_id})"

    def clean(self):
        """Validate the social account model."""
        super().clean()

        # Validate provider-specific constraints
        if self.provider == 'google' and not self.provider_id:
            raise ValidationError('Google provider requires a provider_id')

        # Ensure email matches user's email for new accounts
        if not self.pk and self.email != self.user.email:
            # Allow different emails for existing social accounts
            pass

    def is_token_expired(self):
        """Check if the access token is expired."""
        if not self.token_expires_at:
            return False
        return timezone.now() >= self.token_expires_at

    def update_tokens(self, access_token, refresh_token=None, expires_in=None):
        """Update OAuth tokens."""
        self.access_token = access_token
        if refresh_token:
            self.refresh_token = refresh_token

        if expires_in:
            self.token_expires_at = timezone.now() + timezone.timedelta(seconds=expires_in)

        self.save(update_fields=['access_token', 'refresh_token', 'token_expires_at', 'updated_at'])

    def update_profile_info(self, first_name=None, last_name=None, profile_picture_url=None, extra_data=None):
        """Update profile information from social provider."""
        updated_fields = ['updated_at']

        if first_name is not None:
            self.first_name = first_name
            updated_fields.append('first_name')

        if last_name is not None:
            self.last_name = last_name
            updated_fields.append('last_name')

        if profile_picture_url is not None:
            self.profile_picture_url = profile_picture_url
            updated_fields.append('profile_picture_url')

        if extra_data is not None:
            self.extra_data.update(extra_data)
            updated_fields.append('extra_data')

        self.save(update_fields=updated_fields)

    def record_login(self):
        """Record that this social account was used for login."""
        self.last_login_at = timezone.now()
        self.save(update_fields=['last_login_at'])


class SocialAccountLinkRequest(models.Model):
    """Model to track account linking requests for existing users."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('expired', 'Expired'),
        ('cancelled', 'Cancelled'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        'authentication.User',
        on_delete=models.CASCADE,
        related_name='social_link_requests'
    )
    provider = models.CharField(
        max_length=50,
        choices=SocialAccount.PROVIDER_CHOICES
    )
    provider_id = models.CharField(
        max_length=255,
        help_text='Unique identifier from the social provider'
    )
    provider_email = models.EmailField(
        help_text='Email from the social provider'
    )

    # Request metadata
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    verification_token = models.CharField(
        max_length=255,
        unique=True,
        help_text='Token for verifying the link request'
    )

    # Temporary storage for social account data
    temp_social_data = models.JSONField(
        default=dict,
        help_text='Temporary storage for social account data during linking'
    )

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(
        help_text='When this link request expires'
    )
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'auth_social_link_request'
        verbose_name = 'Social Account Link Request'
        verbose_name_plural = 'Social Account Link Requests'
        indexes = [
            models.Index(fields=['verification_token']),
            models.Index(fields=['user', 'provider']),
            models.Index(fields=['status', 'expires_at']),
        ]

    def __str__(self):
        return f"Link request: {self.user.email} -> {self.provider} ({self.status})"

    def save(self, *args, **kwargs):
        """Set expiration time if not provided."""
        if not self.expires_at:
            # Link requests expire in 1 hour
            self.expires_at = timezone.now() + timezone.timedelta(hours=1)
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if the link request has expired."""
        return timezone.now() >= self.expires_at

    def complete_linking(self):
        """Mark the linking request as completed."""
        self.status = 'completed'
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'completed_at'])

    def cancel_linking(self):
        """Cancel the linking request."""
        self.status = 'cancelled'
        self.save(update_fields=['status'])