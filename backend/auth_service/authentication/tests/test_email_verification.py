"""
Tests for email verification functionality.
Covers requirements 2.1, 2.2, 2.3, 2.4, 2.5 for email verification system.
"""
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.urls import reverse
from django.utils import timezone
from django.core.cache import cache
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch, MagicMock
from datetime import timedelta
from ..models import EmailVerification
from ..services.email_service import EmailService
import uuid

User = get_user_model()


class EmailVerificationModelTest(TestCase):
    """Test EmailVerification model functionality."""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            is_active=False,
            is_email_verified=False
        )

    def test_create_verification(self):
        """Test creating email verification token."""
        try:
            verification = EmailVerification.create_verification(self.user)
            print(f"Verification created successfully: {verification}")
        except Exception as e:
            print(f"Error creating verification: {str(e)}")
            raise

        self.assertIsNotNone(verification)
        self.assertEqual(verification.user, self.user)
        self.assertEqual(verification.email, self.user.email)
        self.assertFalse(verification.is_used)
        self.assertTrue(verification.is_valid())

    def test_verify_token(self):
        """Test verifying email with token."""
        verification = EmailVerification.create_verification(self.user)

        # Verify the token
        success = verification.verify()

        self.assertTrue(success)
        self.assertTrue(verification.is_used)
        self.assertIsNotNone(verification.verified_at)

        # Check user status updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)
        self.assertTrue(self.user.is_active)

    def test_expired_token(self):
        """Test that expired tokens are invalid."""
        verification = EmailVerification.create_verification(self.user)

        # Manually set expiration to past
        verification.expires_at = timezone.now() - timedelta(hours=1)
        verification.save()

        self.assertFalse(verification.is_valid())
        self.assertTrue(verification.is_expired())

    def test_token_uniqueness(self):
        """Test that each verification token is unique (Requirement 2.1)."""
        verification1 = EmailVerification.create_verification(self.user)

        # Create another user and verification
        user2 = User.objects.create_user(
            email='test2@example.com',
            password='TestPassword123!',
            is_active=False,
            is_email_verified=False
        )
        verification2 = EmailVerification.create_verification(user2)

        # Tokens should be unique
        self.assertNotEqual(verification1.token, verification2.token)

        # Both should be valid UUID4
        self.assertIsInstance(verification1.token, uuid.UUID)
        self.assertIsInstance(verification2.token, uuid.UUID)

    def test_token_expiration_24_hours(self):
        """Test that tokens expire after 24 hours (Requirement 2.1)."""
        verification = EmailVerification.create_verification(self.user)

        # Check that expiration is set to approximately 24 hours from creation
        expected_expiry = verification.created_at + timedelta(hours=24)
        time_diff = abs((verification.expires_at - expected_expiry).total_seconds())

        # Allow for small timing differences (within 1 second)
        self.assertLess(time_diff, 1.0)

    def test_multiple_tokens_invalidation(self):
        """Test that creating new token invalidates previous unused tokens (Requirement 2.1)."""
        # Create first verification token
        verification1 = EmailVerification.create_verification(self.user)
        self.assertFalse(verification1.is_used)

        # Create second verification token
        verification2 = EmailVerification.create_verification(self.user)

        # First token should be marked as used
        verification1.refresh_from_db()
        self.assertTrue(verification1.is_used)
        self.assertFalse(verification2.is_used)

    def test_token_validation_with_attempts_tracking(self):
        """Test token validation with attempts tracking (Requirement 2.2)."""
        verification = EmailVerification.create_verification(self.user)

        # Initial attempts should be 0
        self.assertEqual(verification.attempts, 0)

        # Increment attempts
        verification.increment_attempts()
        self.assertEqual(verification.attempts, 1)

        # Verify token successfully
        success = verification.verify()
        self.assertTrue(success)
        self.assertTrue(verification.is_used)
        self.assertIsNotNone(verification.verified_at)

    def test_user_activation_on_verification(self):
        """Test that user is activated upon successful verification (Requirement 2.2)."""
        # User starts inactive and unverified
        self.assertFalse(self.user.is_active)
        self.assertFalse(self.user.is_email_verified)

        verification = EmailVerification.create_verification(self.user)
        success = verification.verify()

        self.assertTrue(success)

        # Check user status updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertTrue(self.user.is_email_verified)

    def test_used_token_cannot_be_reused(self):
        """Test that used tokens cannot be verified again (Requirement 2.2)."""
        verification = EmailVerification.create_verification(self.user)

        # First verification should succeed
        success1 = verification.verify()
        self.assertTrue(success1)

        # Second verification attempt should fail
        success2 = verification.verify()
        self.assertFalse(success2)

    def test_get_valid_token(self):
        """Test getting valid token by UUID."""
        verification = EmailVerification.create_verification(self.user)

        # Test valid token
        found_verification = EmailVerification.get_valid_token(verification.token)
        self.assertEqual(found_verification, verification)

        # Test invalid token
        invalid_token = uuid.uuid4()
        found_verification = EmailVerification.get_valid_token(invalid_token)
        self.assertIsNone(found_verification)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    DEFAULT_FROM_EMAIL='test@example.com'
)
class EmailServiceTest(TestCase):
    """Test EmailService functionality."""

    def setUp(self):
        from django.core.cache import cache
        # Clear cache to avoid rate limiting between tests
        cache.clear()

        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User',
            is_active=False,
            is_email_verified=False
        )

    def tearDown(self):
        from django.core.cache import cache
        # Clear cache after each test
        cache.clear()

    def test_send_verification_email(self):
        """Test sending verification email."""
        # First test creating verification token
        verification = EmailVerification.create_verification(self.user)
        self.assertIsNotNone(verification)
        print(f"Verification created: {verification}")

        # Now test sending email
        success, message, verification = EmailService.send_verification_email(self.user)

        # Debug output
        print(f"Success: {success}, Message: {message}, Verification: {verification}")
        if not success:
            print(f"Error message: {message}")

        self.assertTrue(success, f"Email sending failed with message: {message}")
        self.assertIsNotNone(verification)
        self.assertEqual(len(mail.outbox), 1)

        # Check email content
        email = mail.outbox[0]
        self.assertEqual(email.to, [self.user.email])
        self.assertIn('Verify your email address', email.subject)
        self.assertIn(str(verification.token), email.body)

    def test_verify_email(self):
        """Test email verification process."""
        # Create verification
        success, message, verification = EmailService.send_verification_email(self.user)
        self.assertTrue(success)

        # Verify email
        success, user, message = EmailService.verify_email(verification.token)

        self.assertTrue(success)
        self.assertEqual(user, self.user)
        self.assertEqual(message, "Email verified successfully")

        # Check user status
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)
        self.assertTrue(self.user.is_active)

    def test_verify_invalid_token(self):
        """Test verification with invalid token."""
        invalid_token = uuid.uuid4()
        success, user, message = EmailService.verify_email(invalid_token)

        self.assertFalse(success)
        self.assertIsNone(user)
        self.assertEqual(message, "Invalid or expired verification token")

    def test_resend_verification_email(self):
        """Test resending verification email."""
        success, message = EmailService.resend_verification_email(self.user.email)

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)

    def test_resend_for_verified_user(self):
        """Test resending for already verified user."""
        self.user.is_active = True
        self.user.is_email_verified = True
        self.user.save()

        success, message = EmailService.resend_verification_email(self.user.email)

        self.assertFalse(success)
        self.assertEqual(message, "Account is already verified")

    def test_resend_for_nonexistent_email(self):
        """Test resending for non-existent email."""
        success, message = EmailService.resend_verification_email('nonexistent@example.com')

        self.assertFalse(success)
        self.assertIn("If this email is registered", message)

    def test_email_content_includes_token(self):
        """Test that verification email contains the token (Requirement 2.3)."""
        success, message, verification = EmailService.send_verification_email(self.user)

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)

        email = mail.outbox[0]
        # Token should be in email body
        self.assertIn(str(verification.token), email.body)

        # Email should have proper subject
        self.assertIn('Verify your email address', email.subject)

        # Email should be sent to correct recipient
        self.assertEqual(email.to, [self.user.email])

    def test_email_template_personalization(self):
        """Test that email template includes user information (Requirement 2.3)."""
        # Set user's first name
        self.user.first_name = 'John'
        self.user.save()

        success, message, verification = EmailService.send_verification_email(self.user)

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)

        email = mail.outbox[0]
        # Should include user's name in greeting
        self.assertIn('John', email.body)

        # Should include site name
        self.assertIn('Sansaar Event Universe', email.body)

        # Should include expiration information
        self.assertIn('expire', email.body.lower())

    def test_verification_url_format(self):
        """Test that verification URL is properly formatted (Requirement 2.3)."""
        success, message, verification = EmailService.send_verification_email(self.user)

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)

        email = mail.outbox[0]
        # Should contain a clickable verification URL
        expected_url_part = f"/verify-email/{verification.token}"
        self.assertIn(expected_url_part, email.body)

    def test_rate_limiting_prevents_spam(self):
        """Test that rate limiting prevents email spam (Requirement 2.4)."""
        # First email should succeed
        success1, message1, verification1 = EmailService.send_verification_email(self.user)
        self.assertTrue(success1)

        # Immediate second attempt should be rate limited
        success2, message2, verification2 = EmailService.send_verification_email(self.user)
        self.assertFalse(success2)
        self.assertIn("recently sent", message2)
        self.assertIsNone(verification2)

    def test_rate_limiting_cache_key_format(self):
        """Test that rate limiting uses proper cache key format (Requirement 2.4)."""
        # Send first email
        EmailService.send_verification_email(self.user)

        # Check that cache key exists
        cache_key = f"email_verification_sent_{self.user.email}"
        cached_value = cache.get(cache_key)
        self.assertIsNotNone(cached_value)

    def test_rate_limiting_timeout(self):
        """Test that rate limiting expires after timeout (Requirement 2.4)."""
        # Send first email
        EmailService.send_verification_email(self.user)

        # Manually clear cache to simulate timeout
        cache_key = f"email_verification_sent_{self.user.email}"
        cache.delete(cache_key)

        # Second attempt should now succeed
        success, message, verification = EmailService.send_verification_email(self.user)
        self.assertTrue(success)

    def test_resend_functionality_basic(self):
        """Test basic resend functionality (Requirement 2.4)."""
        # Clear cache first
        cache.clear()

        success, message = EmailService.resend_verification_email(self.user.email)

        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(message, "Verification email sent successfully")

    def test_resend_rate_limiting(self):
        """Test that resend functionality respects rate limiting (Requirement 2.4)."""
        # Send first email via resend
        success1, message1 = EmailService.resend_verification_email(self.user.email)
        self.assertTrue(success1)

        # Immediate second resend should be rate limited
        success2, message2 = EmailService.resend_verification_email(self.user.email)
        self.assertFalse(success2)
        self.assertIn("recently sent", message2)

    def test_clear_error_messages_invalid_token(self):
        """Test clear error messages for invalid tokens (Requirement 2.5)."""
        invalid_token = uuid.uuid4()
        success, user, message = EmailService.verify_email(invalid_token)

        self.assertFalse(success)
        self.assertIsNone(user)
        self.assertEqual(message, "Invalid or expired verification token")

    def test_clear_error_messages_expired_token(self):
        """Test clear error messages for expired tokens (Requirement 2.5)."""
        verification = EmailVerification.create_verification(self.user)

        # Manually expire the token
        verification.expires_at = timezone.now() - timedelta(hours=1)
        verification.save()

        success, user, message = EmailService.verify_email(verification.token)

        self.assertFalse(success)
        self.assertIsNone(user)
        self.assertEqual(message, "Invalid or expired verification token")

    def test_recovery_options_for_failed_verification(self):
        """Test recovery options when verification fails (Requirement 2.5)."""
        # Test that resend works after failed verification
        verification = EmailVerification.create_verification(self.user)

        # Expire the token
        verification.expires_at = timezone.now() - timedelta(hours=1)
        verification.save()

        # Verification should fail
        success, user, message = EmailService.verify_email(verification.token)
        self.assertFalse(success)

        # But resend should work (after clearing rate limit)
        cache.clear()
        success, message = EmailService.resend_verification_email(self.user.email)
        self.assertTrue(success)


@override_settings(
    EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    DEFAULT_FROM_EMAIL='test@example.com'
)
class EmailVerificationAPITest(APITestCase):
    """Test email verification API endpoints."""

    def setUp(self):
        from django.core.cache import cache
        # Clear cache to avoid rate limiting between tests
        cache.clear()

        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            is_active=False,
            is_email_verified=False
        )

    def tearDown(self):
        from django.core.cache import cache
        # Clear cache after each test
        cache.clear()

    def test_registration_sends_verification_email(self):
        """Test that registration sends verification email."""
        url = reverse('authentication:register')
        data = {
            'email': 'newuser@example.com',
            'password': 'NewPassword123!',
            'password_confirm': 'NewPassword123!',
            'first_name': 'New',
            'last_name': 'User'
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['verification_email_sent'])
        self.assertEqual(len(mail.outbox), 1)

    def test_verify_email_endpoint(self):
        """Test email verification endpoint."""
        # Create verification token
        verification = EmailVerification.create_verification(self.user)

        url = reverse('authentication:verify_email', kwargs={'token': verification.token})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Email verified successfully', response.data['message'])

        # Check user status
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)
        self.assertTrue(self.user.is_active)

    def test_verify_email_invalid_token(self):
        """Test verification with invalid token."""
        invalid_token = uuid.uuid4()
        url = reverse('authentication:verify_email', kwargs={'token': invalid_token})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code'], 'VERIFICATION_FAILED')

    def test_resend_verification_endpoint(self):
        """Test resend verification email endpoint."""
        url = reverse('authentication:resend_verification')
        data = {'email': self.user.email}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(mail.outbox), 1)

    def test_resend_verification_rate_limiting(self):
        """Test rate limiting for resend verification."""
        # Set rate limit in cache (simulating recent send)
        cache.set(f"email_verification_sent_{self.user.email}", "sent", 300)

        url = reverse('authentication:resend_verification')
        data = {'email': self.user.email}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("recently sent", response.data['error'])

    def test_verify_email_endpoint_success_response(self):
        """Test successful verification endpoint response format (Requirement 2.2)."""
        verification = EmailVerification.create_verification(self.user)

        url = reverse('authentication:verify_email', kwargs={'token': verification.token})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)

        # Check user data in response
        user_data = response.data['user']
        self.assertEqual(user_data['email'], self.user.email)
        self.assertTrue(user_data['is_email_verified'])
        self.assertTrue(user_data['is_active'])

    def test_verify_email_endpoint_error_response(self):
        """Test error response format for verification endpoint (Requirement 2.5)."""
        invalid_token = uuid.uuid4()
        url = reverse('authentication:verify_email', kwargs={'token': invalid_token})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertIn('code', response.data)
        self.assertEqual(response.data['code'], 'VERIFICATION_FAILED')

    def test_resend_verification_endpoint_success(self):
        """Test successful resend verification endpoint (Requirement 2.4)."""
        url = reverse('authentication:resend_verification')
        data = {'email': self.user.email}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('email', response.data)
        self.assertEqual(response.data['email'], self.user.email)

    def test_resend_verification_endpoint_validation(self):
        """Test validation for resend verification endpoint (Requirement 2.5)."""
        url = reverse('authentication:resend_verification')

        # Test missing email
        response = self.client.post(url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code'], 'EMAIL_REQUIRED')

        # Test empty email
        response = self.client.post(url, {'email': ''})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code'], 'EMAIL_REQUIRED')

    def test_resend_verification_already_verified_user(self):
        """Test resend for already verified user (Requirement 2.4)."""
        # Verify the user first
        self.user.is_active = True
        self.user.is_email_verified = True
        self.user.save()

        url = reverse('authentication:resend_verification')
        data = {'email': self.user.email}

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['code'], 'RESEND_FAILED')
        self.assertIn("already verified", response.data['error'])

    def test_registration_triggers_verification_email(self):
        """Test that registration automatically sends verification email (Requirement 2.3)."""
        url = reverse('authentication:register')
        data = {
            'email': 'newuser@example.com',
            'password': 'NewPassword123!',
            'password_confirm': 'NewPassword123!',
            'first_name': 'New',
            'last_name': 'User'
        }

        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['verification_email_sent'])
        self.assertEqual(len(mail.outbox), 1)

        # Check that user is created but not active
        user = User.objects.get(email='newuser@example.com')
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_email_verified)

    def test_email_service_error_handling(self):
        """Test email service error handling (Requirement 2.5)."""
        with patch('authentication.services.email_service.send_mail') as mock_send_mail:
            # Simulate email sending failure
            mock_send_mail.side_effect = Exception("SMTP server error")

            success, message, verification = EmailService.send_verification_email(self.user)

            self.assertFalse(success)
            self.assertIn("Failed to send verification email", message)
            self.assertIsNone(verification)

    def test_verification_token_security(self):
        """Test verification token security properties (Requirement 2.1)."""
        verification = EmailVerification.create_verification(self.user)

        # Token should be UUID4 (cryptographically secure)
        self.assertEqual(verification.token.version, 4)

        # Token should be unique and unpredictable
        tokens = set()
        for _ in range(10):
            user = User.objects.create_user(
                email=f'test{_}@example.com',
                password='TestPassword123!'
            )
            v = EmailVerification.create_verification(user)
            tokens.add(str(v.token))

        # All tokens should be unique
        self.assertEqual(len(tokens), 10)

    def test_verification_request_tracking(self):
        """Test that verification requests are tracked (Requirement 2.1)."""
        # Create mock request
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/')
        request.META['HTTP_USER_AGENT'] = 'Test Browser'
        request.META['REMOTE_ADDR'] = '192.168.1.1'

        verification = EmailVerification.create_verification(self.user, request=request)

        # Should track IP and user agent
        self.assertEqual(verification.ip_address, '192.168.1.1')
        self.assertEqual(verification.user_agent, 'Test Browser')

    def test_email_verification_model_string_representation(self):
        """Test EmailVerification model string representation."""
        verification = EmailVerification.create_verification(self.user)

        str_repr = str(verification)
        self.assertIn(self.user.email, str_repr)
        self.assertIn('Pending', str_repr)

        # After verification
        verification.verify()
        str_repr = str(verification)
        self.assertIn('Verified', str_repr)

    def test_email_verification_model_indexes(self):
        """Test that proper database indexes are defined in model meta."""
        # Check that indexes are defined in the model's Meta class
        indexes = EmailVerification._meta.indexes

        # Should have at least some indexes defined
        self.assertGreater(len(indexes), 0, "EmailVerification model should have indexes defined")

        # Check that key fields are indexed (by checking model meta)
        indexed_fields = []
        for index in indexes:
            indexed_fields.extend(index.fields)

        # Key fields that should be indexed
        important_fields = ['token', 'user', 'email', 'expires_at', 'is_used']

        # At least some important fields should be indexed
        indexed_important_fields = [field for field in important_fields if field in indexed_fields]
        self.assertGreater(len(indexed_important_fields), 0,
                          f"At least some important fields should be indexed: {important_fields}")

    @patch('authentication.services.email_service.logger')
    def test_email_service_logging(self, mock_logger):
        """Test that email service properly logs events (Requirement 2.5)."""
        # Test successful email sending
        EmailService.send_verification_email(self.user)

        # Should log info messages
        mock_logger.info.assert_called()

        # Test failed verification
        invalid_token = uuid.uuid4()
        EmailService.verify_email(invalid_token)

        # Should not log errors for invalid tokens (expected behavior)
        # But should handle gracefully