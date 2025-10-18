"""
Privacy service for managing user privacy settings and consent.
"""
import logging
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db import transaction
from ..models.privacy import PrivacySettings, PrivacySettingsHistory
from ..models.user import User
from ..models.profile import UserProfile

logger = logging.getLogger(__name__)


class PrivacyService:
    """Service class for privacy settings and consent management."""

    @staticmethod
    def get_or_create_privacy_settings(user):
        """
        Get or create privacy settings for a user.

        Args:
            user: User instance

        Returns:
            PrivacySettings instance
        """
        try:
            privacy_settings, created = PrivacySettings.objects.get_or_create(
                user=user,
                defaults={
                    'data_processing_consent': 'pending',
                    'marketing_consent': 'denied',
                    'analytics_consent': 'denied',
                }
            )

            if created:
                logger.info(f"Created default privacy settings for user: {user.email}")

                # Log creation
                PrivacySettingsHistory.log_change(
                    privacy_settings=privacy_settings,
                    action='create',
                    changed_fields=['all'],
                    new_values={'status': 'created'},
                    changed_by=user,
                    reason='Initial privacy settings created'
                )

            return privacy_settings

        except Exception as e:
            logger.error(f"Failed to get/create privacy settings for user {user.email}: {str(e)}")
            raise

    @staticmethod
    def update_privacy_settings(user, settings_data, request=None):
        """
        Update privacy settings for a user.

        Args:
            user: User instance
            settings_data: Dictionary of settings to update
            request: Django request object

        Returns:
            tuple: (success, privacy_settings, errors)
        """
        try:
            privacy_settings = PrivacyService.get_or_create_privacy_settings(user)

            # Track changes for audit
            changed_fields = []
            old_values = {}
            new_values = {}

            for field, new_value in settings_data.items():
                if hasattr(privacy_settings, field):
                    old_value = getattr(privacy_settings, field)
                    if old_value != new_value:
                        changed_fields.append(field)
                        old_values[field] = old_value
                        new_values[field] = new_value
                        setattr(privacy_settings, field, new_value)

            if changed_fields:
                # Update review date
                privacy_settings.settings_last_reviewed = timezone.now()
                privacy_settings.save(updated_by=user)

                # Log the change
                PrivacySettingsHistory.log_change(
                    privacy_settings=privacy_settings,
                    action='update',
                    changed_fields=changed_fields,
                    old_values=old_values,
                    new_values=new_values,
                    changed_by=user,
                    request=request,
                    reason='Privacy settings updated by user'
                )

                logger.info(f"Privacy settings updated for user {user.email}: {changed_fields}")

            return True, privacy_settings, {}

        except ValidationError as e:
            logger.warning(f"Privacy settings validation failed for user {user.email}: {str(e)}")
            return False, None, {'validation': str(e)}
        except Exception as e:
            logger.error(f"Failed to update privacy settings for user {user.email}: {str(e)}")
            return False, None, {'error': str(e)}

    @staticmethod
    def manage_consent(user, consent_type, action, reason='', request=None):
        """
        Grant or withdraw consent for a specific type.

        Args:
            user: User instance
            consent_type: Type of consent ('data_processing', 'marketing', 'analytics')
            action: Action to perform ('grant', 'withdraw')
            reason: Reason for consent change
            request: Django request object

        Returns:
            tuple: (success, privacy_settings, errors)
        """
        try:
            privacy_settings = PrivacyService.get_or_create_privacy_settings(user)

            # Validate consent type and action
            valid_types = ['data_processing', 'marketing', 'analytics']
            if consent_type not in valid_types:
                return False, None, {'consent_type': f'Invalid consent type. Must be one of: {", ".join(valid_types)}'}

            if action not in ['grant', 'withdraw']:
                return False, None, {'action': 'Invalid action. Must be "grant" or "withdraw"'}

            # Data processing consent cannot be withdrawn
            if consent_type == 'data_processing' and action == 'withdraw':
                return False, None, {'consent_type': 'Data processing consent cannot be withdrawn as it is required for service operation.'}

            # Get current consent status
            consent_field = f"{consent_type}_consent"
            old_status = getattr(privacy_settings, consent_field)

            # Update consent
            if action == 'grant':
                success = privacy_settings.grant_consent(consent_type, updated_by=user)
                new_status = 'granted'
                action_type = 'consent_granted'
            else:
                success = privacy_settings.withdraw_consent(consent_type, updated_by=user)
                new_status = 'withdrawn'
                action_type = 'consent_withdrawn'

            if success:
                # Log the consent change
                PrivacySettingsHistory.log_change(
                    privacy_settings=privacy_settings,
                    action=action_type,
                    changed_fields=[consent_field],
                    old_values={consent_field: old_status},
                    new_values={consent_field: new_status},
                    changed_by=user,
                    request=request,
                    reason=reason or f'Consent {action}ed by user'
                )

                logger.info(f"Consent {action}ed for user {user.email}: {consent_type}")
                return True, privacy_settings, {}
            else:
                return False, None, {'error': f'Failed to {action} consent for {consent_type}'}

        except Exception as e:
            logger.error(f"Failed to manage consent for user {user.email}: {str(e)}")
            return False, None, {'error': str(e)}

    @staticmethod
    def apply_privacy_template(user, template_name, request=None):
        """
        Apply a predefined privacy template.

        Args:
            user: User instance
            template_name: Name of the template ('strict', 'balanced', 'open')
            request: Django request object

        Returns:
            tuple: (success, privacy_settings, errors)
        """
        try:
            privacy_settings = PrivacyService.get_or_create_privacy_settings(user)

            # Store old values for audit
            old_values = {}
            template_fields = [
                'data_sharing_level', 'profile_searchable', 'profile_indexable',
                'show_online_status', 'show_last_seen', 'marketing_emails',
                'newsletter_subscription', 'communication_frequency',
                'share_with_partners', 'allow_api_access', 'two_factor_required',
                'auto_delete_inactive_data', 'data_retention_period_months'
            ]

            for field in template_fields:
                old_values[field] = getattr(privacy_settings, field)

            # Apply template
            success = privacy_settings.apply_privacy_template(template_name)

            if success:
                # Get new values for audit
                new_values = {}
                for field in template_fields:
                    new_values[field] = getattr(privacy_settings, field)

                # Log the template application
                PrivacySettingsHistory.log_change(
                    privacy_settings=privacy_settings,
                    action='template_applied',
                    changed_fields=template_fields,
                    old_values=old_values,
                    new_values=new_values,
                    changed_by=user,
                    request=request,
                    reason=f'Applied {template_name} privacy template'
                )

                logger.info(f"Privacy template '{template_name}' applied for user: {user.email}")
                return True, privacy_settings, {}
            else:
                return False, None, {'template_name': f'Invalid template name: {template_name}'}

        except Exception as e:
            logger.error(f"Failed to apply privacy template for user {user.email}: {str(e)}")
            return False, None, {'error': str(e)}

    @staticmethod
    def export_user_data(user, export_format='json', include_history=True, include_privacy_settings=True):
        """
        Export user data for GDPR compliance.

        Args:
            user: User instance
            export_format: Format for export ('json', 'xml')
            include_history: Include change history
            include_privacy_settings: Include privacy settings

        Returns:
            tuple: (success, data, errors)
        """
        try:
            export_data = {
                'user_info': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_active': user.is_active,
                    'date_joined': user.date_joined.isoformat() if user.date_joined else None,
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                },
                'export_info': {
                    'exported_at': timezone.now().isoformat(),
                    'export_format': export_format,
                    'includes_history': include_history,
                    'includes_privacy_settings': include_privacy_settings,
                }
            }

            # Include profile data if exists
            try:
                profile = UserProfile.objects.get(user=user)
                export_data['profile'] = {
                    'bio': profile.bio,
                    'date_of_birth': profile.date_of_birth.isoformat() if profile.date_of_birth else None,
                    'gender': profile.gender,
                    'phone_number': profile.phone_number,
                    'city': profile.city,
                    'country': profile.country,
                    'website_url': profile.website_url,
                    'linkedin_url': profile.linkedin_url,
                    'twitter_handle': profile.twitter_handle,
                    'created_at': profile.created_at.isoformat() if profile.created_at else None,
                    'updated_at': profile.updated_at.isoformat() if profile.updated_at else None,
                }
            except UserProfile.DoesNotExist:
                export_data['profile'] = None

            # Include privacy settings if requested
            if include_privacy_settings:
                try:
                    privacy_settings = PrivacySettings.objects.get(user=user)
                    export_data['privacy_settings'] = {
                        'data_processing_consent': privacy_settings.data_processing_consent,
                        'data_processing_consent_date': privacy_settings.data_processing_consent_date.isoformat() if privacy_settings.data_processing_consent_date else None,
                        'marketing_consent': privacy_settings.marketing_consent,
                        'marketing_consent_date': privacy_settings.marketing_consent_date.isoformat() if privacy_settings.marketing_consent_date else None,
                        'analytics_consent': privacy_settings.analytics_consent,
                        'analytics_consent_date': privacy_settings.analytics_consent_date.isoformat() if privacy_settings.analytics_consent_date else None,
                        'data_sharing_level': privacy_settings.data_sharing_level,
                        'profile_searchable': privacy_settings.profile_searchable,
                        'profile_indexable': privacy_settings.profile_indexable,
                        'email_notifications': privacy_settings.email_notifications,
                        'marketing_emails': privacy_settings.marketing_emails,
                        'newsletter_subscription': privacy_settings.newsletter_subscription,
                        'communication_frequency': privacy_settings.communication_frequency,
                        'gdpr_compliant': privacy_settings.gdpr_compliant,
                        'ccpa_compliant': privacy_settings.ccpa_compliant,
                        'consent_version': privacy_settings.consent_version,
                        'created_at': privacy_settings.created_at.isoformat() if privacy_settings.created_at else None,
                        'updated_at': privacy_settings.updated_at.isoformat() if privacy_settings.updated_at else None,
                    }
                except PrivacySettings.DoesNotExist:
                    export_data['privacy_settings'] = None

            # Include history if requested
            if include_history:
                try:
                    privacy_settings = PrivacySettings.objects.get(user=user)
                    history = PrivacySettingsHistory.objects.filter(
                        privacy_settings=privacy_settings
                    ).order_by('-changed_at')[:100]  # Limit to last 100 changes

                    export_data['privacy_history'] = [
                        {
                            'action': entry.action,
                            'changed_fields': entry.changed_fields,
                            'old_values': entry.old_values,
                            'new_values': entry.new_values,
                            'changed_at': entry.changed_at.isoformat() if entry.changed_at else None,
                            'reason': entry.reason,
                            'ip_address': entry.ip_address,
                        }
                        for entry in history
                    ]
                except PrivacySettings.DoesNotExist:
                    export_data['privacy_history'] = []

            # Format data based on requested format
            if export_format == 'json':
                formatted_data = json.dumps(export_data, indent=2, ensure_ascii=False)
            elif export_format == 'xml':
                formatted_data = PrivacyService._dict_to_xml(export_data, 'user_data')
            else:
                return False, None, {'export_format': 'Invalid export format. Must be "json" or "xml"'}

            logger.info(f"Data exported for user {user.email} in {export_format} format")
            return True, formatted_data, {}

        except Exception as e:
            logger.error(f"Failed to export data for user {user.email}: {str(e)}")
            return False, None, {'error': str(e)}

    @staticmethod
    def _dict_to_xml(data, root_name):
        """Convert dictionary to XML format."""
        def _build_xml(parent, data):
            if isinstance(data, dict):
                for key, value in data.items():
                    child = ET.SubElement(parent, str(key))
                    _build_xml(child, value)
            elif isinstance(data, list):
                for item in data:
                    item_elem = ET.SubElement(parent, 'item')
                    _build_xml(item_elem, item)
            else:
                parent.text = str(data) if data is not None else ''

        root = ET.Element(root_name)
        _build_xml(root, data)
        return ET.tostring(root, encoding='unicode')

    @staticmethod
    def request_account_deletion(user, reason='', delete_immediately=False, request=None):
        """
        Request account deletion (Right to be forgotten).

        Args:
            user: User instance
            reason: Reason for deletion
            delete_immediately: Whether to delete immediately
            request: Django request object

        Returns:
            tuple: (success, message, errors)
        """
        try:
            privacy_settings = PrivacyService.get_or_create_privacy_settings(user)

            if delete_immediately:
                # Immediate deletion
                with transaction.atomic():
                    # Log the deletion request
                    PrivacySettingsHistory.log_change(
                        privacy_settings=privacy_settings,
                        action='account_deletion_immediate',
                        changed_fields=['account_status'],
                        old_values={'account_status': 'active'},
                        new_values={'account_status': 'deleted'},
                        changed_by=user,
                        request=request,
                        reason=reason or 'Immediate account deletion requested by user'
                    )

                    # Delete user data
                    user.delete()

                    logger.info(f"Account immediately deleted for user: {user.email}")
                    return True, 'Account deleted immediately', {}
            else:
                # Schedule deletion (grace period)
                deletion_date = timezone.now() + timedelta(days=30)  # 30-day grace period

                # Mark user as inactive
                user.is_active = False
                user.save()

                # Log the deletion request
                PrivacySettingsHistory.log_change(
                    privacy_settings=privacy_settings,
                    action='account_deletion_scheduled',
                    changed_fields=['account_status', 'deletion_date'],
                    old_values={'account_status': 'active'},
                    new_values={
                        'account_status': 'scheduled_for_deletion',
                        'deletion_date': deletion_date.isoformat()
                    },
                    changed_by=user,
                    request=request,
                    reason=reason or 'Account deletion scheduled by user'
                )

                logger.info(f"Account deletion scheduled for user: {user.email} on {deletion_date}")
                return True, f'Account scheduled for deletion on {deletion_date.strftime("%Y-%m-%d")}. You can reactivate before this date.', {}

        except Exception as e:
            logger.error(f"Failed to process account deletion for user {user.email}: {str(e)}")
            return False, None, {'error': str(e)}

    @staticmethod
    def get_privacy_compliance_report(user):
        """
        Generate privacy compliance report for a user.

        Args:
            user: User instance

        Returns:
            dict: Compliance report
        """
        try:
            privacy_settings = PrivacyService.get_or_create_privacy_settings(user)

            # Check compliance
            gdpr_compliant = privacy_settings.is_gdpr_compliant()
            privacy_score = privacy_settings.get_privacy_score()
            needs_renewal = privacy_settings.needs_consent_renewal()

            # Identify compliance issues
            compliance_issues = []
            recommendations = []

            if not gdpr_compliant:
                compliance_issues.append('Not GDPR compliant')
                recommendations.append('Review and update privacy settings to ensure GDPR compliance')

            if needs_renewal:
                compliance_issues.append('Consent needs renewal')
                recommendations.append('Renew consent for data processing')

            if privacy_score < 50:
                compliance_issues.append('Low privacy score')
                recommendations.append('Consider applying stricter privacy settings')

            if privacy_settings.data_processing_consent == 'pending':
                compliance_issues.append('Data processing consent pending')
                recommendations.append('Provide explicit consent for data processing')

            report = {
                'user_email': user.email,
                'gdpr_compliant': gdpr_compliant,
                'ccpa_compliant': privacy_settings.ccpa_compliant,
                'privacy_score': privacy_score,
                'consent_status': privacy_settings.get_consent_summary(),
                'last_review_date': privacy_settings.settings_last_reviewed,
                'needs_consent_renewal': needs_renewal,
                'compliance_issues': compliance_issues,
                'recommendations': recommendations,
                'generated_at': timezone.now(),
            }

            return report

        except Exception as e:
            logger.error(f"Failed to generate compliance report for user {user.email}: {str(e)}")
            return {'error': str(e)}

    @staticmethod
    def get_privacy_history(user, limit=50):
        """
        Get privacy settings change history for a user.

        Args:
            user: User instance
            limit: Maximum number of history entries to return

        Returns:
            QuerySet: Privacy settings history
        """
        try:
            privacy_settings = PrivacySettings.objects.get(user=user)
            return PrivacySettingsHistory.objects.filter(
                privacy_settings=privacy_settings
            ).order_by('-changed_at')[:limit]

        except PrivacySettings.DoesNotExist:
            return PrivacySettingsHistory.objects.none()
        except Exception as e:
            logger.error(f"Failed to get privacy history for user {user.email}: {str(e)}")
            return PrivacySettingsHistory.objects.none()

    @staticmethod
    def complete_privacy_review(user, request=None):
        """
        Mark privacy settings as reviewed by user.

        Args:
            user: User instance
            request: Django request object

        Returns:
            tuple: (success, privacy_settings, errors)
        """
        try:
            privacy_settings = PrivacyService.get_or_create_privacy_settings(user)
            privacy_settings.update_settings_review_date()

            # Log the review
            PrivacySettingsHistory.log_change(
                privacy_settings=privacy_settings,
                action='review_completed',
                changed_fields=['settings_last_reviewed'],
                old_values={'settings_last_reviewed': None},
                new_values={'settings_last_reviewed': privacy_settings.settings_last_reviewed.isoformat()},
                changed_by=user,
                request=request,
                reason='Privacy settings reviewed by user'
            )

            logger.info(f"Privacy review completed for user: {user.email}")
            return True, privacy_settings, {}

        except Exception as e:
            logger.error(f"Failed to complete privacy review for user {user.email}: {str(e)}")
            return False, None, {'error': str(e)}