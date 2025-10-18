"""
Unit tests for privacy management functionality.
"""
import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from ..models.privacy import PrivacySettings, PrivacySettingsHistory
from ..models.profile import UserProfile
from ..services.privacy_service import PrivacyService
from ..serializers.privacy import (
    PrivacySettingsSerializer,
    PrivacySettingsUpdateSerializer,
    ConsentManagementSerializer,
    PrivacyTemplateSerializer,
    DataExportRequestSerializer,
    AccountDeletionRequestSerializer
)

User = get_user_model()


class PrivacySettingsModelTest(TestCase):
    """Test PrivacySettings model functionality."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.privacy_settings = PrivacySettings.objects.create(
            user=self.user,
            data_processing_consent='granted',
            data_processing_consent_date=timezone.now(),
            marketing_consent='denied',
            marketing_consent_date=timezone.now(),
            analytics_consent='granted',
            analytics_consent_date=timezone.now()
        )

    def test_privacy_settings_creation(self):
        """Test privacy settings creation."""
        self.assertEqual(self.privacy_settings.user, self.user)
        self.assertEqual(self.privacy_settings.data_processing_consent, 'granted')
        self.assertEqual(self.privacy_settings.marketing_consent, 'denied')
        self.assertEqual(self.privacy_settings.analytics_consent, 'granted')
        self.assertTrue(self.privacy_settings.gdpr_compliant)
        self.assertTrue(self.privacy_settings.ccpa_compliant)

    def test_consent_management_methods(self):
        """Test consent grant and withdraw methods."""
        # Test granting marketing consent
        success = self.privacy_settings.grant_consent('marketing')
        self.assertTrue(success)
        self.assertEqual(self.privacy_settings.marketing_consent, 'granted')
        self.assertIsNotNone(self.privacy_settings.marketing_consent_date)

        # Test withdrawing marketing consent
        success = self.privacy_settings.withdraw_consent('marketing')
        self.assertTrue(success)
        self.assertEqual(self.privacy_settings.marketing_consent, 'withdrawn')

        # Test invalid consent type
        success = self.privacy_settings.grant_consent('invalid_type')
        self.assertFalse(success)

    def test_has_valid_consent(self):
        """Test consent validation method."""
        self.assertTrue(self.privacy_settings.has_valid_consent('data_processing'))
        self.assertFalse(self.privacy_settings.has_valid_consent('marketing'))
        self.assertTrue(self.privacy_settings.has_valid_consent('analytics'))
        self.assertFalse(self.privacy_settings.has_valid_consent('invalid_type'))

    def test_get_consent_summary(self):
        """Test consent summary method."""
        summary = self.privacy_settings.get_consent_summary()

        self.assertIn('data_processing', summary)
        self.assertIn('marketing', summary)
        self.assertIn('analytics', summary)

        self.assertEqual(summary['data_processing']['status'], 'granted')
        self.assertEqual(summary['marketing']['status'], 'denied')
        self.assertEqual(summary['analytics']['status'], 'granted')

    def test_is_gdpr_compliant(self):
        """Test GDPR compliance check."""
        # Should be compliant with default settings
        self.assertTrue(self.privacy_settings.is_gdpr_compliant())

        # Should not be compliant if data processing consent is pending
        self.privacy_settings.data_processing_consent = 'pending'
        self.assertFalse(self.privacy_settings.is_gdpr_compliant())

        # Should not be compliant if data export is disabled
        self.privacy_settings.data_processing_consent = 'granted'
        self.privacy_settings.allow_data_export = False
        self.assertFalse(self.privacy_settings.is_gdpr_compliant())

    def test_needs_consent_renewal(self):
        """Test consent renewal check."""
        # Fresh consent should not need renewal
        self.assertFalse(self.privacy_settings.needs_consent_renewal())

        # Old consent should need renewal
        old_date = timezone.now() - timedelta(days=400)
        self.privacy_settings.data_processing_consent_date = old_date
        self.privacy_settings.save()
        self.assertTrue(self.privacy_settings.needs_consent_renewal())

    def test_get_privacy_score(self):
        """Test privacy score calculation."""
        score = self.privacy_settings.get_privacy_score()
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

        # Test with strict settings
        self.privacy_settings.data_sharing_level = 'none'
        self.privacy_settings.profile_searchable = False
        self.privacy_settings.profile_indexable = False
        self.privacy_settings.marketing_emails = False
        self.privacy_settings.two_factor_required = True
        strict_score = self.privacy_settings.get_privacy_score()

        self.assertGreater(strict_score, score)

    def test_apply_privacy_template(self):
        """Test privacy template application."""
        # Test strict template
        success = self.privacy_settings.apply_privacy_template('strict')
        self.assertTrue(success)
        self.assertEqual(self.privacy_settings.data_sharing_level, 'none')
        self.assertFalse(self.privacy_settings.profile_searchable)
        self.assertTrue(self.privacy_settings.two_factor_required)

        # Test balanced template
        success = self.privacy_settings.apply_privacy_template('balanced')
        self.assertTrue(success)
        self.assertEqual(self.privacy_settings.data_sharing_level, 'essential')
        self.assertTrue(self.privacy_settings.profile_searchable)
        self.assertFalse(self.privacy_settings.two_factor_required)

        # Test invalid template
        success = self.privacy_settings.apply_privacy_template('invalid')
        self.assertFalse(success)

    def test_create_default_settings(self):
        """Test default settings creation."""
        new_user = User.objects.create_user(
            email='newuser@example.com',
            password='testpass123'
        )

        default_settings = PrivacySettings.create_default_settings(new_user)

        self.assertEqual(default_settings.user, new_user)
        self.assertEqual(default_settings.data_processing_consent, 'pending')
        self.assertEqual(default_settings.marketing_consent, 'denied')
        self.assertEqual(default_settings.analytics_consent, 'denied')
        self.assertTrue(default_settings.gdpr_compliant)


class PrivacySettingsHistoryTest(TestCase):
    """Test PrivacySettingsHistory model functionality."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.privacy_settings = PrivacySettings.objects.create(user=self.user)
        self.factory = RequestFactory()

    def test_log_change(self):
        """Test logging privacy settings changes."""
        request = self.factory.post('/test/')
        request.user = self.user
        request.META = {'HTTP_USER_AGENT': 'Test Agent', 'REMOTE_ADDR': '127.0.0.1'}

        history_entry = PrivacySettingsHistory.log_change(
            privacy_settings=self.privacy_settings,
            action='update',
            changed_fields=['marketing_emails'],
            old_values={'marketing_emails': False},
            new_values={'marketing_emails': True},
            changed_by=self.user,
            request=request,
            reason='User updated marketing preferences'
        )

        self.assertEqual(history_entry.privacy_settings, self.privacy_settings)
        self.assertEqual(history_entry.action, 'update')
        self.assertEqual(history_entry.changed_fields, ['marketing_emails'])
        self.assertEqual(history_entry.old_values, {'marketing_emails': False})
        self.assertEqual(history_entry.new_values, {'marketing_emails': True})
        self.assertEqual(history_entry.changed_by, self.user)
        self.assertEqual(history_entry.reason, 'User updated marketing preferences')
        self.assertIsNotNone(history_entry.ip_address)
        self.assertIsNotNone(history_entry.user_agent)


class PrivacyServiceTest(TestCase):
    """Test PrivacyService functionality."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.factory = RequestFactory()

    def test_get_or_create_privacy_settings(self):
        """Test getting or creating privacy settings."""
        # Should create new settings
        privacy_settings = PrivacyService.get_or_create_privacy_settings(self.user)
        self.assertIsInstance(privacy_settings, PrivacySettings)
        self.assertEqual(privacy_settings.user, self.user)

        # Should get existing settings
        existing_settings = PrivacyService.get_or_create_privacy_settings(self.user)
        self.assertEqual(privacy_settings.id, existing_settings.id)

    def test_update_privacy_settings(self):
        """Test updating privacy settings."""
        request = self.factory.post('/test/')
        request.user = self.user

        settings_data = {
            'marketing_emails': True,
            'data_sharing_level': 'analytics',
            'profile_searchable': False
        }

        success, privacy_settings, errors = PrivacyService.update_privacy_settings(
            user=self.user,
            settings_data=settings_data,
            request=request
        )

        self.assertTrue(success)
        self.assertIsInstance(privacy_settings, PrivacySettings)
        self.assertEqual(privacy_settings.marketing_emails, True)
        self.assertEqual(privacy_settings.data_sharing_level, 'analytics')
        self.assertEqual(privacy_settings.profile_searchable, False)
        self.assertEqual(errors, {})

    def test_manage_consent(self):
        """Test consent management."""
        request = self.factory.post('/test/')
        request.user = self.user

        # Test granting marketing consent
        success, privacy_settings, errors = PrivacyService.manage_consent(
            user=self.user,
            consent_type='marketing',
            action='grant',
            reason='User wants marketing emails',
            request=request
        )

        self.assertTrue(success)
        self.assertEqual(privacy_settings.marketing_consent, 'granted')
        self.assertEqual(errors, {})

        # Test withdrawing marketing consent
        success, privacy_settings, errors = PrivacyService.manage_consent(
            user=self.user,
            consent_type='marketing',
            action='withdraw',
            reason='User no longer wants marketing emails',
            request=request
        )

        self.assertTrue(success)
        self.assertEqual(privacy_settings.marketing_consent, 'withdrawn')

        # Test invalid consent type
        success, privacy_settings, errors = PrivacyService.manage_consent(
            user=self.user,
            consent_type='invalid',
            action='grant',
            request=request
        )

        self.assertFalse(success)
        self.assertIn('consent_type', errors)

        # Test withdrawing data processing consent (should fail)
        success, privacy_settings, errors = PrivacyService.manage_consent(
            user=self.user,
            consent_type='data_processing',
            action='withdraw',
            request=request
        )

        self.assertFalse(success)
        self.assertIn('consent_type', errors)

    def test_apply_privacy_template(self):
        """Test applying privacy templates."""
        request = self.factory.post('/test/')
        request.user = self.user

        # Test applying strict template
        success, privacy_settings, errors = PrivacyService.apply_privacy_template(
            user=self.user,
            template_name='strict',
            request=request
        )

        self.assertTrue(success)
        self.assertEqual(privacy_settings.data_sharing_level, 'none')
        self.assertFalse(privacy_settings.profile_searchable)

        # Test invalid template
        success, privacy_settings, errors = PrivacyService.apply_privacy_template(
            user=self.user,
            template_name='invalid',
            request=request
        )

        self.assertFalse(success)
        self.assertIn('template_name', errors)

    def test_export_user_data(self):
        """Test user data export."""
        # Create profile for more complete export
        UserProfile.objects.create(
            user=self.user,
            bio='Test bio',
            phone_number='+1234567890'
        )

        # Test JSON export
        success, data, errors = PrivacyService.export_user_data(
            user=self.user,
            export_format='json',
            include_history=True,
            include_privacy_settings=True
        )

        self.assertTrue(success)
        self.assertIsInstance(data, str)

        # Parse JSON to verify structure
        parsed_data = json.loads(data)
        self.assertIn('user_info', parsed_data)
        self.assertIn('profile', parsed_data)
        self.assertIn('privacy_settings', parsed_data)
        self.assertIn('export_info', parsed_data)

        # Test XML export
        success, data, errors = PrivacyService.export_user_data(
            user=self.user,
            export_format='xml'
        )

        self.assertTrue(success)
        self.assertIn('<user_data>', data)

        # Test invalid format
        success, data, errors = PrivacyService.export_user_data(
            user=self.user,
            export_format='invalid'
        )

        self.assertFalse(success)
        self.assertIn('export_format', errors)

    def test_request_account_deletion(self):
        """Test account deletion requests."""
        request = self.factory.post('/test/')
        request.user = self.user

        # Test scheduled deletion
        success, message, errors = PrivacyService.request_account_deletion(
            user=self.user,
            reason='No longer need account',
            delete_immediately=False,
            request=request
        )

        self.assertTrue(success)
        self.assertIn('scheduled for deletion', message)

        # User should be inactive
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

    def test_get_privacy_compliance_report(self):
        """Test privacy compliance report generation."""
        report = PrivacyService.get_privacy_compliance_report(self.user)

        self.assertIn('user_email', report)
        self.assertIn('gdpr_compliant', report)
        self.assertIn('privacy_score', report)
        self.assertIn('consent_status', report)
        self.assertIn('compliance_issues', report)
        self.assertIn('recommendations', report)

        self.assertEqual(report['user_email'], self.user.email)
        self.assertIsInstance(report['privacy_score'], int)
        self.assertIsInstance(report['compliance_issues'], list)
        self.assertIsInstance(report['recommendations'], list)

    def test_get_privacy_history(self):
        """Test getting privacy history."""
        # Create some history
        privacy_settings = PrivacyService.get_or_create_privacy_settings(self.user)
        PrivacySettingsHistory.log_change(
            privacy_settings=privacy_settings,
            action='update',
            changed_fields=['marketing_emails'],
            old_values={'marketing_emails': False},
            new_values={'marketing_emails': True},
            changed_by=self.user
        )

        history = PrivacyService.get_privacy_history(self.user, limit=10)
        self.assertGreater(len(history), 0)

        # Test with user who has no privacy settings
        new_user = User.objects.create_user(
            email='newuser@example.com',
            password='testpass123'
        )
        history = PrivacyService.get_privacy_history(new_user)
        self.assertEqual(len(history), 0)

    def test_complete_privacy_review(self):
        """Test completing privacy review."""
        request = self.factory.post('/test/')
        request.user = self.user

        success, privacy_settings, errors = PrivacyService.complete_privacy_review(
            user=self.user,
            request=request
        )

        self.assertTrue(success)
        self.assertIsNotNone(privacy_settings.settings_last_reviewed)
        self.assertEqual(errors, {})


class PrivacySerializersTest(TestCase):
    """Test privacy serializers."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.privacy_settings = PrivacySettings.objects.create(
            user=self.user,
            data_processing_consent='granted',
            data_processing_consent_date=timezone.now(),
            marketing_consent='denied',
            marketing_consent_date=timezone.now()
        )

    def test_privacy_settings_serializer(self):
        """Test PrivacySettingsSerializer."""
        serializer = PrivacySettingsSerializer(self.privacy_settings)
        data = serializer.data

        self.assertIn('data_processing_consent', data)
        self.assertIn('marketing_consent', data)
        self.assertIn('consent_summary', data)
        self.assertIn('privacy_score', data)
        self.assertIn('is_gdpr_compliant', data)

        self.assertEqual(data['data_processing_consent'], 'granted')
        self.assertEqual(data['marketing_consent'], 'denied')
        self.assertIsInstance(data['privacy_score'], int)
        self.assertIsInstance(data['is_gdpr_compliant'], bool)

    def test_privacy_settings_update_serializer(self):
        """Test PrivacySettingsUpdateSerializer."""
        data = {
            'marketing_emails': True,
            'data_sharing_level': 'analytics',
            'profile_searchable': False
        }

        serializer = PrivacySettingsUpdateSerializer(
            self.privacy_settings,
            data=data,
            partial=True
        )

        self.assertTrue(serializer.is_valid())

        updated_settings = serializer.save()
        self.assertEqual(updated_settings.marketing_emails, True)
        self.assertEqual(updated_settings.data_sharing_level, 'analytics')
        self.assertEqual(updated_settings.profile_searchable, False)

    def test_privacy_settings_update_serializer_validation(self):
        """Test PrivacySettingsUpdateSerializer validation."""
        # Test disabling data breach notifications (should fail)
        data = {'data_breach_notifications': False}

        serializer = PrivacySettingsUpdateSerializer(
            self.privacy_settings,
            data=data,
            partial=True
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn('data_breach_notifications', serializer.errors)

        # Test invalid data retention period
        data = {'data_retention_period_months': 0}

        serializer = PrivacySettingsUpdateSerializer(
            self.privacy_settings,
            data=data,
            partial=True
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn('data_retention_period_months', serializer.errors)

    def test_consent_management_serializer(self):
        """Test ConsentManagementSerializer."""
        # Valid data
        data = {
            'consent_type': 'marketing',
            'action': 'grant',
            'reason': 'User wants marketing emails'
        }

        serializer = ConsentManagementSerializer(data=data)
        self.assertTrue(serializer.is_valid())

        # Invalid consent type
        data['consent_type'] = 'invalid'
        serializer = ConsentManagementSerializer(data=data)
        self.assertFalse(serializer.is_valid())

        # Try to withdraw data processing consent (should fail)
        data = {
            'consent_type': 'data_processing',
            'action': 'withdraw'
        }

        serializer = ConsentManagementSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('consent_type', serializer.errors)

    def test_privacy_template_serializer(self):
        """Test PrivacyTemplateSerializer."""
        # Valid template
        data = {'template_name': 'strict'}
        serializer = PrivacyTemplateSerializer(data=data)
        self.assertTrue(serializer.is_valid())

        # Invalid template
        data = {'template_name': 'invalid'}
        serializer = PrivacyTemplateSerializer(data=data)
        self.assertFalse(serializer.is_valid())

    def test_data_export_request_serializer(self):
        """Test DataExportRequestSerializer."""
        data = {
            'export_format': 'json',
            'include_history': True,
            'include_privacy_settings': True
        }

        serializer = DataExportRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid())

        validated_data = serializer.validated_data
        self.assertEqual(validated_data['export_format'], 'json')
        self.assertTrue(validated_data['include_history'])
        self.assertTrue(validated_data['include_privacy_settings'])

    def test_account_deletion_request_serializer(self):
        """Test AccountDeletionRequestSerializer."""
        # Valid confirmation
        data = {
            'confirmation_text': 'DELETE MY ACCOUNT',
            'reason': 'No longer need account',
            'delete_immediately': False
        }

        serializer = AccountDeletionRequestSerializer(data=data)
        self.assertTrue(serializer.is_valid())

        # Invalid confirmation
        data['confirmation_text'] = 'delete account'
        serializer = AccountDeletionRequestSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('confirmation_text', serializer.errors)


class PrivacyAPITest(APITestCase):
    """Test privacy management API endpoints."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

        # Clear cache before each test
        cache.clear()

    def test_get_privacy_settings(self):
        """Test getting privacy settings."""
        url = '/api/auth/privacy/settings/'
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('privacy_settings', response.data)

        privacy_data = response.data['privacy_settings']
        self.assertIn('data_processing_consent', privacy_data)
        self.assertIn('marketing_consent', privacy_data)
        self.assertIn('privacy_score', privacy_data)

    def test_update_privacy_settings(self):
        """Test updating privacy settings."""
        url = '/api/auth/privacy/settings/update/'
        data = {
            'marketing_emails': True,
            'data_sharing_level': 'analytics',
            'profile_searchable': False
        }

        response = self.client.patch(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('privacy_settings', response.data)

        # Verify changes
        privacy_settings = PrivacySettings.objects.get(user=self.user)
        self.assertTrue(privacy_settings.marketing_emails)
        self.assertEqual(privacy_settings.data_sharing_level, 'analytics')
        self.assertFalse(privacy_settings.profile_searchable)

    def test_update_privacy_settings_validation(self):
        """Test privacy settings update validation."""
        url = '/api/auth/privacy/settings/update/'
        data = {
            'data_breach_notifications': False  # Should fail
        }

        response = self.client.patch(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('details', response.data)

    @patch('authentication.views.privacy.increment_rate_limit')
    @patch('authentication.views.privacy.is_rate_limited')
    def test_update_privacy_settings_rate_limiting(self, mock_is_rate_limited, mock_increment):
        """Test privacy settings update rate limiting."""
        mock_is_rate_limited.return_value = (True, 0, timezone.now().timestamp() + 3600)

        url = '/api/auth/privacy/settings/update/'
        data = {'marketing_emails': True}

        response = self.client.patch(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn('RATE_LIMIT_EXCEEDED', response.data['code'])

    def test_manage_consent(self):
        """Test consent management."""
        url = '/api/auth/privacy/consent/'

        # Grant marketing consent
        data = {
            'consent_type': 'marketing',
            'action': 'grant',
            'reason': 'User wants marketing emails'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('consent_status', response.data)
        self.assertEqual(response.data['consent_status']['status'], 'granted')

        # Verify in database
        privacy_settings = PrivacySettings.objects.get(user=self.user)
        self.assertEqual(privacy_settings.marketing_consent, 'granted')

    def test_manage_consent_invalid_data(self):
        """Test consent management with invalid data."""
        url = '/api/auth/privacy/consent/'

        # Try to withdraw data processing consent
        data = {
            'consent_type': 'data_processing',
            'action': 'withdraw'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('details', response.data)

    def test_apply_privacy_template(self):
        """Test applying privacy templates."""
        url = '/api/auth/privacy/template/'
        data = {'template_name': 'strict'}

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('privacy_settings', response.data)

        # Verify strict template was applied
        privacy_settings = PrivacySettings.objects.get(user=self.user)
        self.assertEqual(privacy_settings.data_sharing_level, 'none')
        self.assertFalse(privacy_settings.profile_searchable)

    def test_export_user_data(self):
        """Test user data export."""
        url = '/api/auth/privacy/export/'
        data = {
            'export_format': 'json',
            'include_history': True,
            'include_privacy_settings': True
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertIn('attachment', response['Content-Disposition'])

        # Verify JSON content
        content = response.content.decode('utf-8')
        parsed_data = json.loads(content)
        self.assertIn('user_info', parsed_data)
        self.assertIn('export_info', parsed_data)

    def test_request_account_deletion(self):
        """Test account deletion request."""
        url = '/api/auth/privacy/delete-account/'
        data = {
            'confirmation_text': 'DELETE MY ACCOUNT',
            'reason': 'No longer need account',
            'delete_immediately': False
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('scheduled for deletion', response.data['message'])

        # Verify user is inactive
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

    def test_get_privacy_history(self):
        """Test getting privacy history."""
        # Create some history first
        privacy_settings = PrivacyService.get_or_create_privacy_settings(self.user)
        PrivacySettingsHistory.log_change(
            privacy_settings=privacy_settings,
            action='update',
            changed_fields=['marketing_emails'],
            old_values={'marketing_emails': False},
            new_values={'marketing_emails': True},
            changed_by=self.user
        )

        url = '/api/auth/privacy/history/'
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('history', response.data)
        self.assertGreater(len(response.data['history']), 0)

    def test_get_privacy_compliance_report(self):
        """Test getting privacy compliance report."""
        url = '/api/auth/privacy/compliance-report/'
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('report', response.data)

        report = response.data['report']
        self.assertIn('user_email', report)
        self.assertIn('gdpr_compliant', report)
        self.assertIn('privacy_score', report)
        self.assertIn('consent_status', report)

    def test_complete_privacy_review(self):
        """Test completing privacy review."""
        url = '/api/auth/privacy/complete-review/'
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('review_date', response.data)

        # Verify in database
        privacy_settings = PrivacySettings.objects.get(user=self.user)
        self.assertIsNotNone(privacy_settings.settings_last_reviewed)

    def test_unauthenticated_access(self):
        """Test that unauthenticated users cannot access privacy endpoints."""
        self.client.force_authenticate(user=None)

        urls = [
            '/api/auth/privacy/settings/',
            '/api/auth/privacy/settings/update/',
            '/api/auth/privacy/consent/',
            '/api/auth/privacy/template/',
            '/api/auth/privacy/export/',
            '/api/auth/privacy/delete-account/',
            '/api/auth/privacy/history/',
            '/api/auth/privacy/compliance-report/',
            '/api/auth/privacy/complete-review/',
        ]

        for url in urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivacyIntegrationTest(APITestCase):
    """Integration tests for privacy management system."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

        # Clear cache
        cache.clear()

    def test_complete_privacy_workflow(self):
        """Test complete privacy management workflow."""
        # 0. First grant data processing consent to make GDPR compliant
        response = self.client.post('/api/auth/privacy/consent/', {
            'consent_type': 'data_processing',
            'action': 'grant',
            'reason': 'User accepts data processing for service'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 1. Get initial privacy settings
        response = self.client.get('/api/auth/privacy/settings/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        initial_score = response.data['privacy_settings']['privacy_score']

        # 2. Apply strict privacy template
        response = self.client.post('/api/auth/privacy/template/', {
            'template_name': 'strict'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        strict_score = response.data['privacy_settings']['privacy_score']
        self.assertGreater(strict_score, initial_score)

        # 3. Grant marketing consent
        response = self.client.post('/api/auth/privacy/consent/', {
            'consent_type': 'marketing',
            'action': 'grant',
            'reason': 'User wants promotional emails'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 4. Update specific privacy settings
        response = self.client.patch('/api/auth/privacy/settings/update/', {
            'email_notifications': True,
            'newsletter_subscription': True
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 5. Complete privacy review
        response = self.client.post('/api/auth/privacy/complete-review/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 6. Get compliance report
        response = self.client.get('/api/auth/privacy/compliance-report/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        report = response.data['report']
        self.assertTrue(report['gdpr_compliant'])

        # 7. Get privacy history
        response = self.client.get('/api/auth/privacy/history/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreater(len(response.data['history']), 0)

        # 8. Export user data
        response = self.client.post('/api/auth/privacy/export/', {
            'export_format': 'json',
            'include_history': True,
            'include_privacy_settings': True
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify all changes are reflected in final settings
        privacy_settings = PrivacySettings.objects.get(user=self.user)
        self.assertEqual(privacy_settings.data_sharing_level, 'none')  # From strict template
        self.assertEqual(privacy_settings.marketing_consent, 'granted')  # From consent grant
        self.assertTrue(privacy_settings.email_notifications)  # From settings update
        self.assertIsNotNone(privacy_settings.settings_last_reviewed)  # From review completion

    def test_gdpr_compliance_workflow(self):
        """Test GDPR compliance workflow."""
        # 1. Check initial compliance
        response = self.client.get('/api/auth/privacy/compliance-report/')
        initial_report = response.data['report']

        # 2. Grant all consents (including data processing for GDPR compliance)
        for consent_type in ['data_processing', 'marketing', 'analytics']:
            response = self.client.post('/api/auth/privacy/consent/', {
                'consent_type': consent_type,
                'action': 'grant'
            })
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 3. Update settings for better compliance
        response = self.client.patch('/api/auth/privacy/settings/update/', {
            'data_sharing_level': 'essential',
            'allow_data_export': True,
            'allow_account_deletion': True,
            'data_breach_notifications': True
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 4. Complete privacy review
        response = self.client.post('/api/auth/privacy/complete-review/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 5. Check final compliance
        response = self.client.get('/api/auth/privacy/compliance-report/')
        final_report = response.data['report']

        self.assertTrue(final_report['gdpr_compliant'])
        self.assertEqual(len(final_report['compliance_issues']), 0)

        # 6. Test data export (GDPR right to portability)
        response = self.client.post('/api/auth/privacy/export/', {
            'export_format': 'json',
            'include_history': True,
            'include_privacy_settings': True
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 7. Test account deletion request (GDPR right to erasure)
        response = self.client.post('/api/auth/privacy/delete-account/', {
            'confirmation_text': 'DELETE MY ACCOUNT',
            'reason': 'GDPR test',
            'delete_immediately': False
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)