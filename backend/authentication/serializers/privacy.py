"""
Privacy serializers for privacy settings and consent management.
"""
import logging
from rest_framework import serializers
from django.utils import timezone
from ..models.privacy import PrivacySettings, PrivacySettingsHistory

logger = logging.getLogger(__name__)


class PrivacySettingsSerializer(serializers.ModelSerializer):
    """
    Serializer for reading privacy settings.
    """
    consent_summary = serializers.SerializerMethodField()
    privacy_score = serializers.SerializerMethodField()
    is_gdpr_compliant = serializers.SerializerMethodField()
    needs_consent_renewal = serializers.SerializerMethodField()

    class Meta:
        model = PrivacySettings
        fields = [
            'id', 'user',
            # GDPR Consent Management
            'data_processing_consent', 'data_processing_consent_date',
            'marketing_consent', 'marketing_consent_date',
            'analytics_consent', 'analytics_consent_date',
            # Data Sharing Controls
            'data_sharing_level', 'allow_data_export', 'allow_account_deletion',
            # Profile Visibility Controls
            'profile_searchable', 'profile_indexable', 'show_online_status', 'show_last_seen',
            # Communication Preferences
            'email_notifications', 'sms_notifications', 'push_notifications',
            'marketing_emails', 'newsletter_subscription', 'communication_frequency',
            # Security and Privacy Features
            'two_factor_required', 'login_notifications', 'suspicious_activity_alerts',
            'data_breach_notifications',
            # Data Retention Preferences
            'auto_delete_inactive_data', 'data_retention_period_months',
            # Third-party Integration Controls
            'allow_social_login', 'share_with_partners', 'allow_api_access',
            # Compliance and Legal
            'gdpr_compliant', 'ccpa_compliant',
            # Audit and Tracking
            'settings_last_reviewed', 'consent_version',
            # Timestamps
            'created_at', 'updated_at',
            # Computed fields
            'consent_summary', 'privacy_score', 'is_gdpr_compliant', 'needs_consent_renewal'
        ]
        read_only_fields = [
            'id', 'user', 'created_at', 'updated_at',
            'data_processing_consent_date', 'marketing_consent_date', 'analytics_consent_date',
            'consent_summary', 'privacy_score', 'is_gdpr_compliant', 'needs_consent_renewal'
        ]

    def get_consent_summary(self, obj):
        """Get consent summary for all consent types."""
        return obj.get_consent_summary()

    def get_privacy_score(self, obj):
        """Get privacy score based on current settings."""
        return obj.get_privacy_score()

    def get_is_gdpr_compliant(self, obj):
        """Check if current settings are GDPR compliant."""
        return obj.is_gdpr_compliant()

    def get_needs_consent_renewal(self, obj):
        """Check if consent needs renewal."""
        return obj.needs_consent_renewal()


class PrivacySettingsUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating privacy settings.
    """

    class Meta:
        model = PrivacySettings
        fields = [
            # Data Sharing Controls
            'data_sharing_level', 'allow_data_export', 'allow_account_deletion',
            # Profile Visibility Controls
            'profile_searchable', 'profile_indexable', 'show_online_status', 'show_last_seen',
            # Communication Preferences
            'email_notifications', 'sms_notifications', 'push_notifications',
            'marketing_emails', 'newsletter_subscription', 'communication_frequency',
            # Security and Privacy Features
            'two_factor_required', 'login_notifications', 'suspicious_activity_alerts',
            'data_breach_notifications',
            # Data Retention Preferences
            'auto_delete_inactive_data', 'data_retention_period_months',
            # Third-party Integration Controls
            'allow_social_login', 'share_with_partners', 'allow_api_access',
        ]

    def validate_data_retention_period_months(self, value):
        """Validate data retention period."""
        if value < 1:
            raise serializers.ValidationError("Data retention period must be at least 1 month.")
        if value > 120:  # 10 years max
            raise serializers.ValidationError("Data retention period cannot exceed 120 months (10 years).")
        return value

    def validate(self, attrs):
        """Validate privacy settings."""
        # Ensure data breach notifications cannot be disabled (legal requirement)
        if 'data_breach_notifications' in attrs and not attrs['data_breach_notifications']:
            raise serializers.ValidationError({
                'data_breach_notifications': 'Data breach notifications cannot be disabled due to legal requirements.'
            })

        # Ensure data export and account deletion cannot be disabled (GDPR requirement)
        if 'allow_data_export' in attrs and not attrs['allow_data_export']:
            raise serializers.ValidationError({
                'allow_data_export': 'Data export cannot be disabled due to GDPR requirements.'
            })

        if 'allow_account_deletion' in attrs and not attrs['allow_account_deletion']:
            raise serializers.ValidationError({
                'allow_account_deletion': 'Account deletion cannot be disabled due to GDPR requirements.'
            })

        return attrs

    def update(self, instance, validated_data):
        """Update privacy settings with audit logging."""
        request = self.context.get('request')

        # Track changed fields for audit
        changed_fields = []
        old_values = {}
        new_values = {}

        for field, new_value in validated_data.items():
            old_value = getattr(instance, field)
            if old_value != new_value:
                changed_fields.append(field)
                old_values[field] = old_value
                new_values[field] = new_value

        # Update the instance
        for field, value in validated_data.items():
            setattr(instance, field, value)

        # Update review date
        instance.settings_last_reviewed = timezone.now()

        # Save with audit info
        if request and hasattr(request, 'user'):
            instance.save(updated_by=request.user)
        else:
            instance.save()

        # Log the change
        if changed_fields:
            PrivacySettingsHistory.log_change(
                privacy_settings=instance,
                action='update',
                changed_fields=changed_fields,
                old_values=old_values,
                new_values=new_values,
                changed_by=request.user if request and hasattr(request, 'user') else None,
                request=request,
                reason='Privacy settings updated by user'
            )

        return instance


class ConsentManagementSerializer(serializers.Serializer):
    """
    Serializer for managing user consent.
    """
    consent_type = serializers.ChoiceField(
        choices=['data_processing', 'marketing', 'analytics'],
        help_text='Type of consent to manage'
    )
    action = serializers.ChoiceField(
        choices=['grant', 'withdraw'],
        help_text='Action to perform on consent'
    )
    reason = serializers.CharField(
        max_length=255,
        required=False,
        help_text='Optional reason for consent change'
    )

    def validate_consent_type(self, value):
        """Validate consent type."""
        valid_types = ['data_processing', 'marketing', 'analytics']
        if value not in valid_types:
            raise serializers.ValidationError(f"Invalid consent type. Must be one of: {', '.join(valid_types)}")
        return value

    def validate(self, attrs):
        """Validate consent management request."""
        consent_type = attrs.get('consent_type')
        action = attrs.get('action')

        # Data processing consent cannot be withdrawn (required for service)
        if consent_type == 'data_processing' and action == 'withdraw':
            raise serializers.ValidationError({
                'consent_type': 'Data processing consent cannot be withdrawn as it is required for service operation.'
            })

        return attrs


class PrivacyTemplateSerializer(serializers.Serializer):
    """
    Serializer for applying privacy templates.
    """
    template_name = serializers.ChoiceField(
        choices=['strict', 'balanced', 'open'],
        help_text='Privacy template to apply'
    )

    def validate_template_name(self, value):
        """Validate template name."""
        valid_templates = ['strict', 'balanced', 'open']
        if value not in valid_templates:
            raise serializers.ValidationError(f"Invalid template. Must be one of: {', '.join(valid_templates)}")
        return value


class PrivacySettingsHistorySerializer(serializers.ModelSerializer):
    """
    Serializer for privacy settings history.
    """
    changed_by_email = serializers.CharField(source='changed_by.email', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = PrivacySettingsHistory
        fields = [
            'id', 'action', 'action_display', 'changed_fields', 'old_values', 'new_values',
            'changed_by', 'changed_by_email', 'changed_at', 'ip_address', 'user_agent',
            'reason', 'consent_version'
        ]
        read_only_fields = ['__all__']


class DataExportRequestSerializer(serializers.Serializer):
    """
    Serializer for data export requests.
    """
    export_format = serializers.ChoiceField(
        choices=['json', 'xml'],
        default='json',
        help_text='Format for data export'
    )
    include_history = serializers.BooleanField(
        default=True,
        help_text='Include change history in export'
    )
    include_privacy_settings = serializers.BooleanField(
        default=True,
        help_text='Include privacy settings in export'
    )


class AccountDeletionRequestSerializer(serializers.Serializer):
    """
    Serializer for account deletion requests.
    """
    confirmation_text = serializers.CharField(
        max_length=50,
        help_text='Type "DELETE MY ACCOUNT" to confirm deletion'
    )
    reason = serializers.CharField(
        max_length=500,
        required=False,
        help_text='Optional reason for account deletion'
    )
    delete_immediately = serializers.BooleanField(
        default=False,
        help_text='Delete account immediately (cannot be undone)'
    )

    def validate_confirmation_text(self, value):
        """Validate confirmation text."""
        if value.upper() != "DELETE MY ACCOUNT":
            raise serializers.ValidationError('You must type "DELETE MY ACCOUNT" to confirm deletion.')
        return value


class PrivacyComplianceReportSerializer(serializers.Serializer):
    """
    Serializer for privacy compliance reports.
    """
    user_email = serializers.EmailField(read_only=True)
    gdpr_compliant = serializers.BooleanField(read_only=True)
    ccpa_compliant = serializers.BooleanField(read_only=True)
    privacy_score = serializers.IntegerField(read_only=True)
    consent_status = serializers.DictField(read_only=True)
    last_review_date = serializers.DateTimeField(read_only=True)
    needs_consent_renewal = serializers.BooleanField(read_only=True)
    compliance_issues = serializers.ListField(read_only=True)
    recommendations = serializers.ListField(read_only=True)