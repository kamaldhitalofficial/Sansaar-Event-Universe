from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
import uuid
from .user import User


class PrivacySettings(models.Model):
    """
    Model for managing user privacy settings and GDPR compliance.
    Provides granular control over data sharing, visibility, and consent management.
    """

    # Data processing consent choices
    CONSENT_CHOICES = [
        ('granted', 'Consent Granted'),
        ('denied', 'Consent Denied'),
        ('withdrawn', 'Consent Withdrawn'),
        ('pending', 'Consent Pending'),
    ]

    # Data sharing levels
    DATA_SHARING_CHOICES = [
        ('none', 'No Data Sharing'),
        ('essential', 'Essential Services Only'),
        ('analytics', 'Analytics and Improvement'),
        ('marketing', 'Marketing and Promotions'),
        ('full', 'Full Data Sharing'),
    ]

    # Communication preferences
    COMMUNICATION_FREQUENCY_CHOICES = [
        ('never', 'Never'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('important_only', 'Important Updates Only'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='privacy_settings')

    # GDPR Consent Management
    data_processing_consent = models.CharField(
        max_length=20,
        choices=CONSENT_CHOICES,
        default='pending',
        help_text='Consent for processing personal data'
    )
    data_processing_consent_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Date when data processing consent was given/withdrawn'
    )

    marketing_consent = models.CharField(
        max_length=20,
        choices=CONSENT_CHOICES,
        default='denied',
        help_text='Consent for marketing communications'
    )
    marketing_consent_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Date when marketing consent was given/withdrawn'
    )

    analytics_consent = models.CharField(
        max_length=20,
        choices=CONSENT_CHOICES,
        default='denied',
        help_text='Consent for analytics and usage tracking'
    )
    analytics_consent_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Date when analytics consent was given/withdrawn'
    )

    # Data Sharing Controls
    data_sharing_level = models.CharField(
        max_length=20,
        choices=DATA_SHARING_CHOICES,
        default='essential',
        help_text='Level of data sharing with third parties'
    )

    allow_data_export = models.BooleanField(
        default=True,
        help_text='Allow user to export their data'
    )

    allow_account_deletion = models.BooleanField(
        default=True,
        help_text='Allow user to request account deletion'
    )

    # Profile Visibility Controls
    profile_searchable = models.BooleanField(
        default=True,
        help_text='Allow profile to appear in search results'
    )

    profile_indexable = models.BooleanField(
        default=False,
        help_text='Allow search engines to index profile'
    )

    show_online_status = models.BooleanField(
        default=False,
        help_text='Show when user is online'
    )

    show_last_seen = models.BooleanField(
        default=False,
        help_text='Show when user was last active'
    )

    # Communication Preferences
    email_notifications = models.BooleanField(
        default=True,
        help_text='Receive email notifications'
    )

    sms_notifications = models.BooleanField(
        default=False,
        help_text='Receive SMS notifications'
    )

    push_notifications = models.BooleanField(
        default=True,
        help_text='Receive push notifications'
    )

    marketing_emails = models.BooleanField(
        default=False,
        help_text='Receive marketing emails'
    )

    newsletter_subscription = models.BooleanField(
        default=False,
        help_text='Subscribe to newsletter'
    )

    communication_frequency = models.CharField(
        max_length=20,
        choices=COMMUNICATION_FREQUENCY_CHOICES,
        default='important_only',
        help_text='Frequency of non-essential communications'
    )

    # Security and Privacy Features
    two_factor_required = models.BooleanField(
        default=False,
        help_text='Require two-factor authentication'
    )

    login_notifications = models.BooleanField(
        default=True,
        help_text='Notify about new login attempts'
    )

    suspicious_activity_alerts = models.BooleanField(
        default=True,
        help_text='Alert about suspicious account activity'
    )

    data_breach_notifications = models.BooleanField(
        default=True,
        help_text='Notify about data breaches (required by law)'
    )

    # Data Retention Preferences
    auto_delete_inactive_data = models.BooleanField(
        default=False,
        help_text='Automatically delete data after inactivity period'
    )

    data_retention_period_months = models.PositiveIntegerField(
        default=24,
        help_text='Months to retain data after account deletion request'
    )

    # Third-party Integration Controls
    allow_social_login = models.BooleanField(
        default=True,
        help_text='Allow login through social media accounts'
    )

    share_with_partners = models.BooleanField(
        default=False,
        help_text='Share data with trusted partners'
    )

    allow_api_access = models.BooleanField(
        default=False,
        help_text='Allow third-party API access to account data'
    )

    # Compliance and Legal
    gdpr_compliant = models.BooleanField(
        default=True,
        help_text='Account follows GDPR compliance rules'
    )

    ccpa_compliant = models.BooleanField(
        default=True,
        help_text='Account follows CCPA compliance rules'
    )

    # Audit and Tracking
    settings_last_reviewed = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Date when user last reviewed privacy settings'
    )

    consent_version = models.CharField(
        max_length=10,
        default='1.0',
        help_text='Version of privacy policy user consented to'
    )

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    # Audit Fields
    last_updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='privacy_updates',
        help_text='User who last updated these privacy settings'
    )

    class Meta:
        db_table = 'auth_privacy_settings'
        verbose_name = 'Privacy Settings'
        verbose_name_plural = 'Privacy Settings'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['data_processing_consent']),
            models.Index(fields=['marketing_consent']),
            models.Index(fields=['gdpr_compliant']),
            models.Index(fields=['created_at']),
            models.Index(fields=['updated_at']),
            models.Index(fields=['settings_last_reviewed']),
        ]

    def __str__(self):
        """Return string representation of privacy settings."""
        return f"Privacy Settings for {self.user.email}"

    def clean(self):
        """Validate privacy settings model."""
        super().clean()

        # Validate data retention period
        if self.data_retention_period_months < 1:
            raise ValidationError({
                'data_retention_period_months': 'Data retention period must be at least 1 month.'
            })

        if self.data_retention_period_months > 120:  # 10 years max
            raise ValidationError({
                'data_retention_period_months': 'Data retention period cannot exceed 120 months (10 years).'
            })

        # Validate consent dates
        if self.data_processing_consent in ['granted', 'withdrawn'] and not self.data_processing_consent_date:
            raise ValidationError({
                'data_processing_consent_date': 'Consent date is required when consent is granted or withdrawn.'
            })

    def save(self, *args, **kwargs):
        """Override save to handle consent date updates."""
        # Set consent dates when consent status changes
        if self.pk:
            try:
                old_instance = PrivacySettings.objects.get(pk=self.pk)

                # Update data processing consent date
                if old_instance.data_processing_consent != self.data_processing_consent:
                    if self.data_processing_consent in ['granted', 'denied', 'withdrawn']:
                        self.data_processing_consent_date = timezone.now()

                # Update marketing consent date
                if old_instance.marketing_consent != self.marketing_consent:
                    if self.marketing_consent in ['granted', 'denied', 'withdrawn']:
                        self.marketing_consent_date = timezone.now()

                # Update analytics consent date
                if old_instance.analytics_consent != self.analytics_consent:
                    if self.analytics_consent in ['granted', 'denied', 'withdrawn']:
                        self.analytics_consent_date = timezone.now()

            except PrivacySettings.DoesNotExist:
                pass
        else:
            # New instance - set initial consent dates if needed
            if self.data_processing_consent in ['granted', 'denied', 'withdrawn']:
                self.data_processing_consent_date = timezone.now()
            if self.marketing_consent in ['granted', 'denied', 'withdrawn']:
                self.marketing_consent_date = timezone.now()
            if self.analytics_consent in ['granted', 'denied', 'withdrawn']:
                self.analytics_consent_date = timezone.now()

        # Set last_updated_by if provided in kwargs
        if 'updated_by' in kwargs:
            self.last_updated_by = kwargs.pop('updated_by')

        super().save(*args, **kwargs)

    def grant_consent(self, consent_type, updated_by=None):
        """
        Grant consent for a specific type.

        Args:
            consent_type: Type of consent ('data_processing', 'marketing', 'analytics')
            updated_by: User who is granting the consent
        """
        consent_field = f"{consent_type}_consent"
        if hasattr(self, consent_field):
            setattr(self, consent_field, 'granted')
            if updated_by:
                self.last_updated_by = updated_by
            self.save()
            return True
        return False

    def withdraw_consent(self, consent_type, updated_by=None):
        """
        Withdraw consent for a specific type.

        Args:
            consent_type: Type of consent ('data_processing', 'marketing', 'analytics')
            updated_by: User who is withdrawing the consent
        """
        consent_field = f"{consent_type}_consent"
        if hasattr(self, consent_field):
            setattr(self, consent_field, 'withdrawn')
            if updated_by:
                self.last_updated_by = updated_by
            self.save()
            return True
        return False

    def has_valid_consent(self, consent_type):
        """
        Check if user has valid consent for a specific type.

        Args:
            consent_type: Type of consent to check

        Returns:
            bool: True if consent is granted, False otherwise
        """
        consent_field = f"{consent_type}_consent"
        if hasattr(self, consent_field):
            return getattr(self, consent_field) == 'granted'
        return False

    def get_consent_summary(self):
        """
        Get a summary of all consent statuses.

        Returns:
            dict: Dictionary with consent types and their statuses
        """
        return {
            'data_processing': {
                'status': self.data_processing_consent,
                'date': self.data_processing_consent_date,
            },
            'marketing': {
                'status': self.marketing_consent,
                'date': self.marketing_consent_date,
            },
            'analytics': {
                'status': self.analytics_consent,
                'date': self.analytics_consent_date,
            },
        }

    def is_gdpr_compliant(self):
        """
        Check if current settings are GDPR compliant.

        Returns:
            bool: True if compliant, False otherwise
        """
        # Must have explicit consent for data processing
        if self.data_processing_consent not in ['granted', 'denied']:
            return False

        # Must have data breach notifications enabled (legal requirement)
        if not self.data_breach_notifications:
            return False

        # Must allow data export (right to portability)
        if not self.allow_data_export:
            return False

        # Must allow account deletion (right to erasure)
        if not self.allow_account_deletion:
            return False

        return True

    def update_settings_review_date(self):
        """Update the date when user last reviewed privacy settings."""
        self.settings_last_reviewed = timezone.now()
        self.save(update_fields=['settings_last_reviewed'])

    def needs_consent_renewal(self, months=12):
        """
        Check if consent needs to be renewed based on age.

        Args:
            months: Number of months after which consent should be renewed

        Returns:
            bool: True if consent needs renewal
        """
        if not self.data_processing_consent_date:
            return True

        from datetime import timedelta
        renewal_date = self.data_processing_consent_date + timedelta(days=months * 30)
        return timezone.now() > renewal_date

    def get_privacy_score(self):
        """
        Calculate a privacy score based on current settings.
        Higher score means more privacy-focused settings.

        Returns:
            int: Privacy score from 0-100
        """
        score = 0

        # Data sharing controls (30 points)
        if self.data_sharing_level == 'none':
            score += 15
        elif self.data_sharing_level == 'essential':
            score += 10
        elif self.data_sharing_level == 'analytics':
            score += 5

        if not self.share_with_partners:
            score += 10
        if not self.allow_api_access:
            score += 5

        # Profile visibility (25 points)
        if not self.profile_searchable:
            score += 10
        if not self.profile_indexable:
            score += 10
        if not self.show_online_status:
            score += 3
        if not self.show_last_seen:
            score += 2

        # Communication preferences (20 points)
        if not self.marketing_emails:
            score += 5
        if not self.newsletter_subscription:
            score += 5
        if self.communication_frequency in ['never', 'important_only']:
            score += 10

        # Security features (15 points)
        if self.two_factor_required:
            score += 10
        if self.login_notifications:
            score += 3
        if self.suspicious_activity_alerts:
            score += 2

        # Data retention (10 points)
        if self.auto_delete_inactive_data:
            score += 5
        if self.data_retention_period_months <= 12:
            score += 5
        elif self.data_retention_period_months <= 24:
            score += 3

        return min(score, 100)

    @classmethod
    def create_default_settings(cls, user):
        """
        Create default privacy settings for a new user.

        Args:
            user: User instance

        Returns:
            PrivacySettings instance
        """
        settings = cls.objects.create(
            user=user,
            data_processing_consent='pending',
            marketing_consent='denied',
            analytics_consent='denied',
            data_sharing_level='essential',
            profile_searchable=True,
            profile_indexable=False,
            email_notifications=True,
            push_notifications=True,
            marketing_emails=False,
            newsletter_subscription=False,
            two_factor_required=False,
            login_notifications=True,
            suspicious_activity_alerts=True,
            data_breach_notifications=True,
            gdpr_compliant=True,
            ccpa_compliant=True,
        )
        return settings

    def apply_privacy_template(self, template_name):
        """
        Apply a predefined privacy template.

        Args:
            template_name: Name of the template ('strict', 'balanced', 'open')
        """
        templates = {
            'strict': {
                'data_sharing_level': 'none',
                'profile_searchable': False,
                'profile_indexable': False,
                'show_online_status': False,
                'show_last_seen': False,
                'marketing_emails': False,
                'newsletter_subscription': False,
                'communication_frequency': 'never',
                'share_with_partners': False,
                'allow_api_access': False,
                'two_factor_required': True,
                'auto_delete_inactive_data': True,
                'data_retention_period_months': 12,
            },
            'balanced': {
                'data_sharing_level': 'essential',
                'profile_searchable': True,
                'profile_indexable': False,
                'show_online_status': False,
                'show_last_seen': False,
                'marketing_emails': False,
                'newsletter_subscription': False,
                'communication_frequency': 'important_only',
                'share_with_partners': False,
                'allow_api_access': False,
                'two_factor_required': False,
                'auto_delete_inactive_data': False,
                'data_retention_period_months': 24,
            },
            'open': {
                'data_sharing_level': 'analytics',
                'profile_searchable': True,
                'profile_indexable': True,
                'show_online_status': True,
                'show_last_seen': True,
                'marketing_emails': True,
                'newsletter_subscription': True,
                'communication_frequency': 'monthly',
                'share_with_partners': True,
                'allow_api_access': True,
                'two_factor_required': False,
                'auto_delete_inactive_data': False,
                'data_retention_period_months': 36,
            }
        }

        if template_name in templates:
            template = templates[template_name]
            for field, value in template.items():
                if hasattr(self, field):
                    setattr(self, field, value)
            self.save()
            return True
        return False


class PrivacySettingsHistory(models.Model):
    """Model to track changes to privacy settings for audit purposes."""

    ACTION_CHOICES = [
        ('create', 'Settings Created'),
        ('update', 'Settings Updated'),
        ('consent_granted', 'Consent Granted'),
        ('consent_withdrawn', 'Consent Withdrawn'),
        ('template_applied', 'Privacy Template Applied'),
        ('review_completed', 'Privacy Review Completed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    privacy_settings = models.ForeignKey(
        PrivacySettings,
        on_delete=models.CASCADE,
        related_name='history'
    )

    # Change tracking
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    changed_fields = models.JSONField(default=dict, help_text='Fields that were changed')
    old_values = models.JSONField(default=dict, help_text='Previous values of changed fields')
    new_values = models.JSONField(default=dict, help_text='New values of changed fields')

    # Audit information
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    changed_at = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Additional context
    reason = models.CharField(max_length=255, blank=True, help_text='Reason for the change')
    consent_version = models.CharField(
        max_length=10,
        blank=True,
        help_text='Privacy policy version at time of change'
    )

    class Meta:
        db_table = 'auth_privacy_settings_history'
        verbose_name = 'Privacy Settings History'
        verbose_name_plural = 'Privacy Settings Histories'
        ordering = ['-changed_at']
        indexes = [
            models.Index(fields=['privacy_settings', '-changed_at']),
            models.Index(fields=['changed_by']),
            models.Index(fields=['action']),
            models.Index(fields=['changed_at']),
        ]

    def __str__(self):
        return f"{self.privacy_settings.user.email} - {self.get_action_display()} - {self.changed_at.strftime('%Y-%m-%d %H:%M:%S')}"

    @classmethod
    def log_change(cls, privacy_settings, action, changed_fields=None, old_values=None,
                   new_values=None, changed_by=None, request=None, reason='', consent_version=''):
        """
        Log a privacy settings change for audit purposes.

        Args:
            privacy_settings: PrivacySettings instance
            action: Type of action performed
            changed_fields: List of field names that changed
            old_values: Dictionary of old field values
            new_values: Dictionary of new field values
            changed_by: User who made the change
            request: Django request object for tracking
            reason: Reason for the change
            consent_version: Privacy policy version
        """
        from ..utils.device_detection import get_client_ip

        ip_address = get_client_ip(request) if request else None
        user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''

        history_entry = cls.objects.create(
            privacy_settings=privacy_settings,
            action=action,
            changed_fields=changed_fields or [],
            old_values=old_values or {},
            new_values=new_values or {},
            changed_by=changed_by,
            ip_address=ip_address,
            user_agent=user_agent,
            reason=reason,
            consent_version=consent_version
        )

        return history_entry