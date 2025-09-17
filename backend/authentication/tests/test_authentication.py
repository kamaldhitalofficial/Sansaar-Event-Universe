"""
Unit tests for user authentication flows and JWT token generation/validation.
Tests Requirements: 3.1, 3.2, 3.3, 3.4, 9.1, 9.2, 9.3
"""
import json
from datetime import timedelta
from unittest.mock import patch, MagicMock
from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.core.cache import cache
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from ..models import LoginHistory, UserSession
from ..serializers import UserLoginSerializer, TokenRefreshSerializer, LogoutSerializer
from ..services.session_service import SessionService

User = get_user_model()


class UserLoginSerializerTests(TestCase):
    """
    Unit tests for UserLoginSerializer validation logic.
    Tests Requirements: 3.1, 3.2, 3.3, 3.4
    """

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            is_active=True,
            is_email_verified=True
        )
        self.valid_data = {
            'email': 'test@example.com',
            'password': 'TestPassword123!',
            'remember_me': False
        }

    def test_valid_login_credentials(self):
        """Test serializer with valid login credentials - Requirement 3.1"""
        serializer = UserLoginSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['user'], self.user)

    def test_invalid_email_format(self):
        """Test login with invalid email format - Requirement 3.1"""
        invalid_emails = [
            'invalid-email',
            'test@',
            '@example.com',
            '',
            'test space@example.com'
        ]

        for invalid_email in invalid_emails:
            with self.subTest(email=invalid_email):
                data = self.valid_data.copy()
                data['email'] = invalid_email
                serializer = UserLoginSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('email', serializer.errors)

    def test_nonexistent_user(self):
        """Test login with non-existent user - Requirement 3.1"""
        data = self.valid_data.copy()
        data['email'] = 'nonexistent@example.com'
        serializer = UserLoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)
        self.assertIn('Invalid email or password', str(serializer.errors['non_field_errors']))

    def test_incorrect_password(self):
        """Test login with incorrect password - Requirement 3.1"""
        data = self.valid_data.copy()
        data['password'] = 'WrongPassword123!'
        serializer = UserLoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)
        self.assertIn('Invalid email or password', str(serializer.errors['non_field_errors']))

        # Verify failed login attempt was incremented
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)

    def test_inactive_user_login(self):
        """Test login with inactive user - Requirement 3.2"""
        self.user.is_active = False
        self.user.save()

        serializer = UserLoginSerializer(data=self.valid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)
        self.assertIn('Account is not active', str(serializer.errors['non_field_errors']))

    def test_locked_account_login(self):
        """Test login with locked account - Requirement 3.3"""
        # Lock the account
        self.user.lock_account(duration_minutes=30)

        serializer = UserLoginSerializer(data=self.valid_data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('non_field_errors', serializer.errors)
        self.assertIn('Account is locked', str(serializer.errors['non_field_errors']))

    def test_successful_login_resets_failed_attempts(self):
        """Test that successful login resets failed attempts - Requirement 3.3"""
        # Set some failed attempts
        self.user.failed_login_attempts = 3
        self.user.save()

        serializer = UserLoginSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())

        # Verify failed attempts were reset
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_successful_login_updates_last_login(self):
        """Test that successful login updates last_login timestamp - Requirement 3.4"""
        old_last_login = self.user.last_login

        serializer = UserLoginSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())

        self.user.refresh_from_db()
        self.assertNotEqual(self.user.last_login, old_last_login)
        self.assertIsNotNone(self.user.last_login)

    def test_remember_me_functionality(self):
        """Test remember_me field handling - Requirement 3.4"""
        data = self.valid_data.copy()
        data['remember_me'] = True

        serializer = UserLoginSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertTrue(serializer.validated_data['remember_me'])

    def test_missing_credentials(self):
        """Test login with missing credentials - Requirement 3.1"""
        # Missing email
        data = {'password': 'TestPassword123!'}
        serializer = UserLoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

        # Missing password
        data = {'email': 'test@example.com'}
        serializer = UserLoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)

        # Both missing
        data = {}
        serializer = UserLoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertIn('password', serializer.errors)

    def test_email_normalization(self):
        """Test email normalization during login - Requirement 3.1"""
        data = self.valid_data.copy()
        data['email'] = '  TEST@EXAMPLE.COM  '

        serializer = UserLoginSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data['user'], self.user)


class TokenRefreshSerializerTests(TestCase):
    """
    Unit tests for TokenRefreshSerializer.
    Tests Requirements: 9.1, 9.2
    """

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            is_active=True
        )

    def test_valid_refresh_token(self):
        """Test token refresh with valid refresh token - Requirement 9.2"""
        refresh = RefreshToken.for_user(self.user)
        data = {'refresh_token': str(refresh)}

        serializer = TokenRefreshSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_invalid_refresh_token(self):
        """Test token refresh with invalid refresh token - Requirement 9.2"""
        data = {'refresh_token': 'invalid_token'}

        serializer = TokenRefreshSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('refresh_token', serializer.errors)
        self.assertIn('Invalid refresh token', str(serializer.errors['refresh_token']))

    def test_expired_refresh_token(self):
        """Test token refresh with expired refresh token - Requirement 9.2"""
        # Create an expired token by manipulating the payload
        refresh = RefreshToken.for_user(self.user)
        # Set expiration to past time
        refresh.payload['exp'] = int((timezone.now() - timedelta(days=1)).timestamp())
        data = {'refresh_token': str(refresh)}

        serializer = TokenRefreshSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('refresh_token', serializer.errors)

    def test_missing_refresh_token(self):
        """Test token refresh with missing refresh token - Requirement 9.2"""
        data = {}

        serializer = TokenRefreshSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('refresh_token', serializer.errors)


class LogoutSerializerTests(TestCase):
    """
    Unit tests for LogoutSerializer.
    Tests Requirements: 9.3
    """

    def test_valid_logout_data(self):
        """Test logout serializer with valid data - Requirement 9.3"""
        data = {'logout_all_devices': False}
        serializer = LogoutSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertFalse(serializer.validated_data['logout_all_devices'])

    def test_logout_all_devices(self):
        """Test logout all devices functionality - Requirement 9.3"""
        data = {'logout_all_devices': True}
        serializer = LogoutSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertTrue(serializer.validated_data['logout_all_devices'])

    def test_default_logout_behavior(self):
        """Test default logout behavior - Requirement 9.3"""
        data = {}
        serializer = LogoutSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertFalse(serializer.validated_data['logout_all_devices'])


class JWTTokenGenerationTests(TestCase):
    """
    Unit tests for JWT token generation and validation.
    Tests Requirements: 9.1, 9.2
    """

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            is_active=True
        )

    def test_access_token_generation(self):
        """Test JWT access token generation - Requirement 9.1"""
        refresh = RefreshToken.for_user(self.user)
        access_token = refresh.access_token

        # Verify token structure
        self.assertIsInstance(access_token, AccessToken)
        self.assertEqual(str(access_token['user_id']), str(self.user.id))
        self.assertIn('token_type', access_token)
        self.assertIn('exp', access_token)
        self.assertIn('iat', access_token)
        self.assertIn('jti', access_token)

    def test_refresh_token_generation(self):
        """Test JWT refresh token generation - Requirement 9.1"""
        refresh = RefreshToken.for_user(self.user)

        # Verify token structure
        self.assertIsInstance(refresh, RefreshToken)
        self.assertEqual(str(refresh['user_id']), str(self.user.id))
        self.assertIn('token_type', refresh)
        self.assertIn('exp', refresh)
        self.assertIn('iat', refresh)
        self.assertIn('jti', refresh)

    def test_token_validation(self):
        """Test JWT token validation - Requirement 9.1"""
        refresh = RefreshToken.for_user(self.user)
        access_token = refresh.access_token

        # Validate access token
        try:
            validated_token = AccessToken(str(access_token))
            self.assertEqual(str(validated_token['user_id']), str(self.user.id))
        except (InvalidToken, TokenError):
            self.fail("Valid access token was rejected")

        # Validate refresh token
        try:
            validated_refresh = RefreshToken(str(refresh))
            self.assertEqual(str(validated_refresh['user_id']), str(self.user.id))
        except (InvalidToken, TokenError):
            self.fail("Valid refresh token was rejected")

    def test_token_expiration(self):
        """Test JWT token expiration handling - Requirement 9.2"""
        refresh = RefreshToken.for_user(self.user)

        # Check that tokens have expiration times
        self.assertIn('exp', refresh)
        self.assertIn('exp', refresh.access_token)

        # Verify expiration times are in the future
        current_time = timezone.now().timestamp()
        self.assertGreater(refresh['exp'], current_time)
        self.assertGreater(refresh.access_token['exp'], current_time)

    def test_token_refresh_functionality(self):
        """Test token refresh functionality - Requirement 9.2"""
        refresh = RefreshToken.for_user(self.user)
        original_access_token = str(refresh.access_token)

        # Generate new access token
        new_access_token = refresh.access_token

        # Verify new token is different but valid
        self.assertNotEqual(str(new_access_token), original_access_token)
        self.assertEqual(str(new_access_token['user_id']), str(self.user.id))

    def test_invalid_token_handling(self):
        """Test invalid token handling - Requirement 9.1"""
        invalid_tokens = [
            'invalid_token',
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid',
            '',
            'Bearer token_without_bearer_prefix'
        ]

        for invalid_token in invalid_tokens:
            with self.subTest(token=invalid_token):
                with self.assertRaises((InvalidToken, TokenError)):
                    AccessToken(invalid_token)


class SessionServiceTests(TestCase):
    """
    Unit tests for SessionService functionality.
    Tests Requirements: 9.1, 9.2, 9.3
    """

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            is_active=True
        )
        self.mock_request = MagicMock()
        self.mock_request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'REMOTE_ADDR': '192.168.1.1'
        }

    def test_create_session(self):
        """Test session creation - Requirement 9.1"""
        token_id = 'test_token_id'
        expires_at = timezone.now() + timedelta(hours=1)

        session = SessionService.create_session(
            user=self.user,
            request=self.mock_request,
            token_id=token_id,
            expires_at=expires_at
        )

        self.assertIsInstance(session, UserSession)
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.token_id, token_id)
        self.assertEqual(session.expires_at, expires_at)
        self.assertTrue(session.is_active)
        self.assertEqual(session.ip_address, '192.168.1.1')

    def test_get_session_by_token_id(self):
        """Test retrieving session by token ID - Requirement 9.1"""
        token_id = 'test_token_id'
        expires_at = timezone.now() + timedelta(hours=1)

        created_session = SessionService.create_session(
            user=self.user,
            request=self.mock_request,
            token_id=token_id,
            expires_at=expires_at
        )

        retrieved_session = SessionService.get_session_by_token_id(token_id)
        self.assertEqual(retrieved_session, created_session)

    def test_get_nonexistent_session(self):
        """Test retrieving non-existent session - Requirement 9.1"""
        session = SessionService.get_session_by_token_id('nonexistent_token')
        self.assertIsNone(session)

    def test_terminate_session(self):
        """Test session termination - Requirement 9.3"""
        token_id = 'test_token_id'
        expires_at = timezone.now() + timedelta(hours=1)

        session = SessionService.create_session(
            user=self.user,
            request=self.mock_request,
            token_id=token_id,
            expires_at=expires_at
        )

        success = SessionService.terminate_session(token_id, reason='test_logout')
        self.assertTrue(success)

        session.refresh_from_db()
        self.assertFalse(session.is_active)
        self.assertEqual(session.logout_reason, 'test_logout')
        self.assertIsNotNone(session.logout_time)

    def test_terminate_all_user_sessions(self):
        """Test terminating all user sessions - Requirement 9.3"""
        # Create multiple sessions
        sessions = []
        for i in range(3):
            token_id = f'test_token_id_{i}'
            expires_at = timezone.now() + timedelta(hours=1)
            session = SessionService.create_session(
                user=self.user,
                request=self.mock_request,
                token_id=token_id,
                expires_at=expires_at
            )
            sessions.append(session)

        terminated_count = SessionService.terminate_all_user_sessions(
            self.user.id,
            reason='password_change'
        )

        self.assertEqual(terminated_count, 3)

        # Verify all sessions are terminated
        for session in sessions:
            session.refresh_from_db()
            self.assertFalse(session.is_active)
            self.assertEqual(session.logout_reason, 'password_change')

    def test_update_session_activity(self):
        """Test updating session activity - Requirement 9.2"""
        token_id = 'test_token_id'
        expires_at = timezone.now() + timedelta(hours=1)

        session = SessionService.create_session(
            user=self.user,
            request=self.mock_request,
            token_id=token_id,
            expires_at=expires_at
        )

        original_activity = session.last_activity

        # Wait a moment and update activity
        import time
        time.sleep(0.1)
        SessionService.update_session_activity(token_id)

        session.refresh_from_db()
        self.assertGreater(session.last_activity, original_activity)

    def test_cleanup_expired_sessions(self):
        """Test cleanup of expired sessions - Requirement 9.2"""
        # Create expired session
        expired_token_id = 'expired_token_id'
        expired_time = timezone.now() - timedelta(hours=1)

        expired_session = SessionService.create_session(
            user=self.user,
            request=self.mock_request,
            token_id=expired_token_id,
            expires_at=expired_time
        )

        # Create active session
        active_token_id = 'active_token_id'
        active_time = timezone.now() + timedelta(hours=1)

        active_session = SessionService.create_session(
            user=self.user,
            request=self.mock_request,
            token_id=active_token_id,
            expires_at=active_time
        )

        cleaned_count = SessionService.cleanup_expired_sessions()
        self.assertEqual(cleaned_count, 1)

        # Verify expired session is terminated
        expired_session.refresh_from_db()
        self.assertFalse(expired_session.is_active)
        self.assertEqual(expired_session.logout_reason, 'expired')

        # Verify active session is still active
        active_session.refresh_from_db()
        self.assertTrue(active_session.is_active)

    def test_get_session_summary(self):
        """Test getting session summary - Requirement 9.1"""
        # Create multiple sessions
        for i in range(3):
            token_id = f'test_token_id_{i}'
            expires_at = timezone.now() + timedelta(hours=1)
            SessionService.create_session(
                user=self.user,
                request=self.mock_request,
                token_id=token_id,
                expires_at=expires_at
            )

        summary = SessionService.get_session_summary(self.user.id)

        self.assertEqual(summary['total_active_sessions'], 3)
        self.assertEqual(len(summary['sessions']), 3)

        # Verify session data structure
        session_data = summary['sessions'][0]
        self.assertIn('token_id', session_data)
        self.assertIn('device_type', session_data)
        self.assertIn('browser', session_data)
        self.assertIn('ip_address', session_data)
        self.assertIn('created_at', session_data)
        self.assertIn('last_activity', session_data)


class LoginHistoryTests(TestCase):
    """
    Unit tests for LoginHistory model and functionality.
    Tests Requirements: 3.4, 9.1
    """

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            is_active=True
        )
        self.mock_request = MagicMock()
        self.mock_request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'REMOTE_ADDR': '192.168.1.1'
        }

    def test_create_successful_login_attempt(self):
        """Test creating successful login history entry - Requirement 3.4"""
        login_entry = LoginHistory.create_login_attempt(
            user=self.user,
            request=self.mock_request,
            success=True,
            token_id='test_token_id'
        )

        self.assertIsInstance(login_entry, LoginHistory)
        self.assertEqual(login_entry.user, self.user)
        self.assertTrue(login_entry.success)
        self.assertEqual(login_entry.ip_address, '192.168.1.1')
        self.assertEqual(login_entry.token_id, 'test_token_id')
        self.assertIsNone(login_entry.failure_reason)

    def test_create_failed_login_attempt(self):
        """Test creating failed login history entry - Requirement 3.4"""
        login_entry = LoginHistory.create_login_attempt(
            user=self.user,
            request=self.mock_request,
            success=False,
            failure_reason='invalid_credentials'
        )

        self.assertIsInstance(login_entry, LoginHistory)
        self.assertEqual(login_entry.user, self.user)
        self.assertFalse(login_entry.success)
        self.assertEqual(login_entry.failure_reason, 'invalid_credentials')
        self.assertIsNone(login_entry.token_id)

    def test_user_agent_parsing(self):
        """Test user agent parsing in login history - Requirement 3.4"""
        login_entry = LoginHistory.create_login_attempt(
            user=self.user,
            request=self.mock_request,
            success=True
        )

        # Verify device information was parsed
        self.assertIn('desktop', login_entry.device_type.lower())
        self.assertIsNotNone(login_entry.browser)
        self.assertIsNotNone(login_entry.operating_system)

    def test_login_history_string_representation(self):
        """Test login history string representation - Requirement 3.4"""
        login_entry = LoginHistory.create_login_attempt(
            user=self.user,
            request=self.mock_request,
            success=True
        )

        str_repr = str(login_entry)
        self.assertIn(self.user.email, str_repr)
        self.assertIn('Success', str_repr)

        # Test failed login representation
        failed_entry = LoginHistory.create_login_attempt(
            user=self.user,
            request=self.mock_request,
            success=False,
            failure_reason='invalid_credentials'
        )

        failed_str_repr = str(failed_entry)
        self.assertIn(self.user.email, failed_str_repr)
        self.assertIn('Failed', failed_str_repr)
        self.assertIn('invalid_credentials', failed_str_repr)

    @patch('authentication.utils.device_detection.detect_new_device')
    def test_new_device_detection(self, mock_detect_new_device):
        """Test new device detection in login history - Requirement 3.4"""
        mock_detect_new_device.return_value = True

        login_entry = LoginHistory.create_login_attempt(
            user=self.user,
            request=self.mock_request,
            success=True
        )

        self.assertTrue(login_entry.is_new_device)
        mock_detect_new_device.assert_called_once_with(
            self.user, '192.168.1.1', self.mock_request.META['HTTP_USER_AGENT']
        )


class AuthenticationIntegrationTests(TestCase):
    """
    Integration tests for authentication flow components.
    Tests Requirements: 3.1, 3.2, 3.3, 3.4, 9.1, 9.2, 9.3
    """

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            is_active=True,
            is_email_verified=True
        )
        cache.clear()  # Clear cache between tests

    def test_complete_authentication_flow(self):
        """Test complete authentication flow - Requirements 3.1, 3.4, 9.1"""
        # Test login serializer
        login_data = {
            'email': 'test@example.com',
            'password': 'TestPassword123!',
            'remember_me': False
        }

        serializer = UserLoginSerializer(data=login_data)
        self.assertTrue(serializer.is_valid())
        authenticated_user = serializer.validated_data['user']

        # Test JWT token generation
        refresh = RefreshToken.for_user(authenticated_user)
        access_token = refresh.access_token

        # Verify tokens are valid
        self.assertEqual(str(access_token['user_id']), str(authenticated_user.id))
        self.assertEqual(str(refresh['user_id']), str(authenticated_user.id))

        # Test session creation
        mock_request = MagicMock()
        mock_request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0 Test Browser',
            'REMOTE_ADDR': '192.168.1.1'
        }

        session = SessionService.create_session(
            user=authenticated_user,
            request=mock_request,
            token_id=str(refresh['jti']),
            expires_at=timezone.now() + timedelta(hours=1)
        )

        self.assertEqual(session.user, authenticated_user)
        self.assertEqual(session.token_id, str(refresh['jti']))
        self.assertTrue(session.is_active)

    def test_failed_authentication_tracking(self):
        """Test failed authentication attempt tracking - Requirements 3.3, 3.4"""
        # Test multiple failed attempts
        for i in range(3):
            login_data = {
                'email': 'test@example.com',
                'password': 'WrongPassword123!',
                'remember_me': False
            }

            serializer = UserLoginSerializer(data=login_data)
            self.assertFalse(serializer.is_valid())

        # Verify failed attempts were tracked
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 3)

        # Test account locking after 5 attempts
        for i in range(2):  # 2 more attempts to reach 5 total
            serializer = UserLoginSerializer(data=login_data)
            self.assertFalse(serializer.is_valid())

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_account_locked())

    def test_token_refresh_flow(self):
        """Test token refresh flow - Requirements 9.1, 9.2"""
        # Generate initial tokens
        refresh = RefreshToken.for_user(self.user)
        original_access_token = str(refresh.access_token)

        # Test token refresh serializer
        refresh_data = {'refresh_token': str(refresh)}
        serializer = TokenRefreshSerializer(data=refresh_data)
        self.assertTrue(serializer.is_valid())

        # Generate new access token
        new_access_token = refresh.access_token

        # Verify new token is different but valid
        self.assertNotEqual(str(new_access_token), original_access_token)
        self.assertEqual(str(new_access_token['user_id']), str(self.user.id))

    def test_logout_flow(self):
        """Test logout flow - Requirements 9.3"""
        # Create session
        refresh = RefreshToken.for_user(self.user)
        mock_request = MagicMock()
        mock_request.META = {
            'HTTP_USER_AGENT': 'Mozilla/5.0 Test Browser',
            'REMOTE_ADDR': '192.168.1.1'
        }

        session = SessionService.create_session(
            user=self.user,
            request=mock_request,
            token_id=str(refresh['jti']),
            expires_at=timezone.now() + timedelta(hours=1)
        )

        # Test logout serializer
        logout_data = {'logout_all_devices': False}
        serializer = LogoutSerializer(data=logout_data)
        self.assertTrue(serializer.is_valid())

        # Test session termination
        success = SessionService.terminate_session(
            str(refresh['jti']),
            reason='manual_logout'
        )
        self.assertTrue(success)

        session.refresh_from_db()
        self.assertFalse(session.is_active)
        self.assertEqual(session.logout_reason, 'manual_logout')