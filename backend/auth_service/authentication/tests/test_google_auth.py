"""
Tests for Google OAuth authentication endpoints.
Tests Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7
"""
import json
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
from allauth.socialaccount.models import SocialApp
from authentication.models import SocialAccount, SocialAccountLinkRequest, UserProfile, PrivacySettings
from authentication.services import GoogleOAuthService, SocialProfileSyncService

User = get_user_model()


class GoogleAuthenticationTests(TestCase):
    """Test Google OAuth authentication endpoints."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()

        # Create Google OAuth app configuration
        self.social_app = SocialApp.objects.create(
            provider='google',
            name='Google OAuth Test',
            client_id='test_client_id',
            secret='test_client_secret'
        )

        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )

    def test_google_auth_status_not_configured(self):
        """Test Google auth status when not configured."""
        # Remove the social app to simulate not configured
        self.social_app.delete()

        url = reverse('authentication:social_auth:google_auth_status')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertFalse(data['google_configured'])
        self.assertEqual(data['status_code'], 'not_configured')

    def test_google_auth_status_configured_anonymous(self):
        """Test Google auth status when configured but user not authenticated."""
        url = reverse('authentication:social_auth:google_auth_status')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data['google_configured'])
        self.assertFalse(data['user_authenticated'])
        self.assertEqual(data['status_code'], 'available')

    def test_google_auth_status_authenticated_no_link(self):
        """Test Google auth status when authenticated but no Google account linked."""
        self.client.force_authenticate(user=self.user)

        url = reverse('authentication:social_auth:google_auth_status')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data['google_configured'])
        self.assertTrue(data['user_authenticated'])
        self.assertFalse(data['google_linked'])
        self.assertEqual(data['status_code'], 'available_for_linking')

    def test_google_auth_status_authenticated_with_link(self):
        """Test Google auth status when authenticated with Google account linked."""
        self.client.force_authenticate(user=self.user)

        # Create a linked Google account
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com',
            first_name='Test',
            last_name='User'
        )

        url = reverse('authentication:social_auth:google_auth_status')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data['google_configured'])
        self.assertTrue(data['user_authenticated'])
        self.assertTrue(data['google_linked'])
        self.assertEqual(data['status_code'], 'linked')
        self.assertIn('google_account_info', data)

    def test_initiate_google_auth_success(self):
        """Test successful Google OAuth initiation."""
        url = reverse('authentication:social_auth:google_oauth_login')
        data = {
            'redirect_uri': 'http://localhost:3000/auth/callback'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('auth_url', response_data)
        self.assertIn('accounts.google.com', response_data['auth_url'])
        self.assertIn('state', response_data)

    def test_initiate_google_auth_invalid_redirect_uri(self):
        """Test Google OAuth initiation with invalid redirect URI."""
        url = reverse('authentication:social_auth:google_oauth_login')
        data = {
            'redirect_uri': 'invalid-uri'
        }

        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid redirect URI', response_data['error'])

    def test_initiate_account_linking_unauthenticated(self):
        """Test account linking initiation without authentication."""
        url = reverse('authentication:social_auth:google_account_link')

        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        response_data = response.json()
        print(f"DEBUG: Response data: {response_data}")  # Debug line
        self.assertFalse(response_data['success'])
        self.assertIn('Authentication required', response_data['error'])

    def test_initiate_account_linking_success(self):
        """Test successful account linking initiation."""
        self.client.force_authenticate(user=self.user)

        url = reverse('authentication:social_auth:google_account_link')
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('auth_url', response_data)
        self.assertIn('verification_token', response_data)

        # Verify link request was created
        self.assertTrue(
            SocialAccountLinkRequest.objects.filter(
                user=self.user,
                provider='google',
                status='pending'
            ).exists()
        )

    def test_initiate_account_linking_already_linked(self):
        """Test account linking when Google account already linked."""
        self.client.force_authenticate(user=self.user)

        # Create existing Google account link
        SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com'
        )

        url = reverse('authentication:social_auth:google_account_link')
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertIn('already linked', response_data['error'])

    def test_unlink_google_account_success(self):
        """Test successful Google account unlinking."""
        self.client.force_authenticate(user=self.user)

        # Create Google account to unlink
        SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com'
        )

        url = reverse('authentication:social_auth:google_account_unlink')
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data['success'])

        # Verify account was unlinked
        self.assertFalse(
            SocialAccount.objects.filter(
                user=self.user,
                provider='google'
            ).exists()
        )

    def test_unlink_google_account_not_linked(self):
        """Test unlinking when no Google account is linked."""
        self.client.force_authenticate(user=self.user)

        url = reverse('authentication:social_auth:google_account_unlink')
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertIn('No Google account found', response_data['error'])

    def test_google_profile_sync_get_preferences(self):
        """Test getting Google profile sync preferences."""
        self.client.force_authenticate(user=self.user)

        url = reverse('authentication:social_auth:google_profile_sync')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('sync_preferences', response_data)

    def test_google_account_management_info(self):
        """Test getting Google account management information."""
        self.client.force_authenticate(user=self.user)

        # Create Google account
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com',
            first_name='Test',
            last_name='User'
        )

        url = reverse('authentication:social_auth:google_account_management')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        self.assertTrue(response_data['success'])

        account_info = response_data['account_management']
        self.assertTrue(account_info['google_configured'])
        self.assertTrue(account_info['account_linked'])
        self.assertIn('google_account', account_info)
        self.assertIn('management_options', account_info)


class GoogleOAuthServiceTests(TestCase):
    """Test Google OAuth service functionality."""

    def setUp(self):
        """Set up test data."""
        self.service = GoogleOAuthService()

        # Create Google OAuth app configuration
        self.social_app = SocialApp.objects.create(
            provider='google',
            name='Google OAuth Test',
            client_id='test_client_id',
            secret='test_client_secret'
        )

        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )

        # Mock Google user info response
        self.mock_google_user_info = {
            'id': '123456789',
            'email': 'test@gmail.com',
            'given_name': 'John',
            'family_name': 'Doe',
            'picture': 'https://example.com/photo.jpg',
            'locale': 'en'
        }

        # Mock token response
        self.mock_token_response = {
            'access_token': 'mock_access_token',
            'refresh_token': 'mock_refresh_token',
            'expires_in': 3600,
            'token_type': 'Bearer'
        }

    @patch('authentication.services.google_oauth_service.requests.post')
    @patch('authentication.services.google_oauth_service.requests.get')
    def test_exchange_code_for_tokens_success(self, mock_get, mock_post):
        """Test successful token exchange with Google."""
        # Mock token exchange response
        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = self.mock_token_response

        # Mock user info response
        mock_get.return_value.ok = True
        mock_get.return_value.json.return_value = self.mock_google_user_info

        result = self.service.exchange_code_for_tokens(
            'test_auth_code',
            'http://localhost:8000/auth/callback'
        )

        self.assertEqual(result['access_token'], 'mock_access_token')
        self.assertEqual(result['refresh_token'], 'mock_refresh_token')
        self.assertEqual(result['user_info']['id'], '123456789')
        self.assertEqual(result['user_info']['email'], 'test@gmail.com')

    @patch('authentication.services.google_oauth_service.requests.post')
    def test_exchange_code_for_tokens_failure(self, mock_post):
        """Test token exchange failure."""
        mock_post.return_value.ok = False
        mock_post.return_value.text = 'Invalid authorization code'

        with self.assertRaises(Exception):
            self.service.exchange_code_for_tokens(
                'invalid_code',
                'http://localhost:8000/auth/callback'
            )

    @patch('authentication.services.google_oauth_service.requests.get')
    def test_get_user_info_success(self, mock_get):
        """Test successful user info retrieval."""
        mock_get.return_value.ok = True
        mock_get.return_value.json.return_value = self.mock_google_user_info

        result = self.service._get_user_info('mock_access_token')

        self.assertEqual(result['id'], '123456789')
        self.assertEqual(result['email'], 'test@gmail.com')
        self.assertEqual(result['given_name'], 'John')

    @patch('authentication.services.google_oauth_service.requests.get')
    def test_get_user_info_failure(self, mock_get):
        """Test user info retrieval failure."""
        mock_get.return_value.ok = False
        mock_get.return_value.text = 'Invalid token'

        with self.assertRaises(Exception):
            self.service._get_user_info('invalid_token')

    def test_authenticate_or_create_user_existing_social_account(self):
        """Test authentication with existing social account."""
        # Create existing social account
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com',
            first_name='John',
            last_name='Doe'
        )

        token_data = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            'expires_in': 3600,
            'user_info': self.mock_google_user_info
        }

        user, returned_social_account, is_new = self.service.authenticate_or_create_user(token_data)

        self.assertEqual(user, self.user)
        self.assertEqual(returned_social_account, social_account)
        self.assertFalse(is_new)

        # Verify tokens were updated
        social_account.refresh_from_db()
        self.assertEqual(social_account.access_token, 'new_access_token')

    def test_authenticate_or_create_user_existing_user_new_social(self):
        """Test linking social account to existing user."""
        token_data = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 3600,
            'user_info': {
                'id': '123456789',
                'email': 'test@example.com',  # Same as existing user
                'given_name': 'John',
                'family_name': 'Doe'
            }
        }

        user, social_account, is_new = self.service.authenticate_or_create_user(token_data)

        self.assertEqual(user, self.user)
        self.assertFalse(is_new)
        self.assertEqual(social_account.provider_id, '123456789')
        self.assertEqual(social_account.user, self.user)

    def test_authenticate_or_create_user_new_user(self):
        """Test creating new user from Google account."""
        token_data = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 3600,
            'user_info': {
                'id': '987654321',
                'email': 'newuser@gmail.com',
                'given_name': 'Jane',
                'family_name': 'Smith'
            }
        }

        user, social_account, is_new = self.service.authenticate_or_create_user(token_data)

        self.assertTrue(is_new)
        self.assertEqual(user.email, 'newuser@gmail.com')
        self.assertEqual(user.first_name, 'Jane')
        self.assertEqual(user.last_name, 'Smith')
        self.assertTrue(user.is_email_verified)
        self.assertEqual(social_account.provider_id, '987654321')

    def test_initiate_account_linking_success(self):
        """Test successful account linking initiation."""
        user_info = {
            'id': '123456789',
            'email': 'test@gmail.com',
            'given_name': 'John',
            'family_name': 'Doe'
        }

        link_request = self.service.initiate_account_linking(self.user, '123456789', user_info)

        self.assertEqual(link_request.user, self.user)
        self.assertEqual(link_request.provider, 'google')
        self.assertEqual(link_request.provider_id, '123456789')
        self.assertEqual(link_request.status, 'pending')
        self.assertTrue(link_request.verification_token)

    def test_initiate_account_linking_already_linked(self):
        """Test account linking when Google account already linked to another user."""
        # Create another user with the Google account
        other_user = User.objects.create_user(
            email='other@example.com',
            password='testpass123'
        )

        SocialAccount.objects.create(
            user=other_user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com'
        )

        user_info = {
            'id': '123456789',
            'email': 'test@gmail.com'
        }

        with self.assertRaises(Exception):
            self.service.initiate_account_linking(self.user, '123456789', user_info)

    def test_complete_account_linking_success(self):
        """Test successful account linking completion."""
        # Create link request
        link_request = SocialAccountLinkRequest.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            provider_email='test@gmail.com',
            verification_token='test_token'
        )

        token_data = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'expires_in': 3600,
            'user_info': self.mock_google_user_info
        }

        social_account = self.service.complete_account_linking('test_token', token_data)

        self.assertEqual(social_account.user, self.user)
        self.assertEqual(social_account.provider_id, '123456789')

        # Verify link request was completed
        link_request.refresh_from_db()
        self.assertEqual(link_request.status, 'completed')

    def test_complete_account_linking_expired(self):
        """Test account linking with expired request."""
        # Create expired link request
        expired_time = timezone.now() - timezone.timedelta(hours=2)
        link_request = SocialAccountLinkRequest.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            provider_email='test@gmail.com',
            verification_token='expired_token',
            expires_at=expired_time
        )

        token_data = {
            'access_token': 'access_token',
            'user_info': self.mock_google_user_info
        }

        with self.assertRaises(Exception):
            self.service.complete_account_linking('expired_token', token_data)

    @patch('authentication.services.google_oauth_service.requests.post')
    def test_refresh_access_token_success(self, mock_post):
        """Test successful token refresh."""
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com',
            access_token='old_token',
            refresh_token='refresh_token'
        )

        mock_post.return_value.ok = True
        mock_post.return_value.json.return_value = {
            'access_token': 'new_access_token',
            'expires_in': 3600
        }

        result = self.service.refresh_access_token(social_account)

        self.assertTrue(result)
        social_account.refresh_from_db()
        self.assertEqual(social_account.access_token, 'new_access_token')

    @patch('authentication.services.google_oauth_service.requests.post')
    def test_refresh_access_token_failure(self, mock_post):
        """Test token refresh failure."""
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com',
            access_token='old_token',
            refresh_token='refresh_token'
        )

        mock_post.return_value.ok = False
        mock_post.return_value.text = 'Invalid refresh token'

        result = self.service.refresh_access_token(social_account)

        self.assertFalse(result)

    def test_handle_authentication_failure(self):
        """Test authentication failure handling."""
        result = self.service.handle_authentication_failure('access_denied', 'User cancelled')

        self.assertIn('message', result)
        self.assertIn('action', result)
        self.assertIn('fallback_url', result)
        self.assertEqual(result['action'], 'retry_or_fallback')

    @patch('authentication.services.google_oauth_service.requests.post')
    def test_unlink_google_account_success(self, mock_post):
        """Test successful Google account unlinking."""
        social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com',
            access_token='access_token'
        )

        mock_post.return_value.ok = True

        result = self.service.unlink_google_account(self.user)

        self.assertTrue(result)
        self.assertFalse(
            SocialAccount.objects.filter(
                user=self.user,
                provider='google'
            ).exists()
        )

    def test_unlink_google_account_not_found(self):
        """Test unlinking when no Google account exists."""
        result = self.service.unlink_google_account(self.user)

        self.assertFalse(result)


class SocialProfileSyncServiceTests(TestCase):
    """Test social profile synchronization functionality."""

    def setUp(self):
        """Set up test data."""
        self.service = SocialProfileSyncService()

        # Create test user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        # Create user profile
        self.profile = UserProfile.objects.create(user=self.user)

        # Create privacy settings
        self.privacy_settings = PrivacySettings.objects.create(
            user=self.user,
            allow_social_profile_sync=True
        )

        # Create social account
        self.social_account = SocialAccount.objects.create(
            user=self.user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com',
            first_name='John',
            last_name='Doe',
            profile_picture_url='https://example.com/photo.jpg',
            extra_data={
                'locale': 'en',
                'timezone': 'America/New_York'
            }
        )

    def test_sync_profile_from_social_success(self):
        """Test successful profile synchronization."""
        result = self.service.sync_profile_from_social(self.social_account)

        self.assertTrue(result['success'])
        self.assertIn('updated_fields', result)

        # Verify user was updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'John')
        self.assertEqual(self.user.last_name, 'Doe')

    def test_sync_profile_disabled_by_privacy(self):
        """Test profile sync when disabled by privacy settings."""
        self.privacy_settings.allow_social_profile_sync = False
        self.privacy_settings.save()

        result = self.service.sync_profile_from_social(self.social_account)

        self.assertFalse(result['success'])
        self.assertIn('privacy settings', result['error'])

    def test_sync_user_basic_info(self):
        """Test syncing basic user information."""
        # Clear existing data
        self.user.first_name = ''
        self.user.last_name = ''
        self.user.save()

        updated_fields = self.service._sync_user_basic_info(
            self.user, self.social_account, force_update=False
        )

        self.assertIn('user.first_name', updated_fields)
        self.assertIn('user.last_name', updated_fields)

        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'John')
        self.assertEqual(self.user.last_name, 'Doe')

    def test_sync_user_profile_info(self):
        """Test syncing user profile information."""
        updated_fields = self.service._sync_user_profile_info(
            self.user, self.social_account, force_update=False
        )

        self.assertIn('profile.profile_picture_url', updated_fields)

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.profile_picture_url, 'https://example.com/photo.jpg')

    def test_get_sync_preferences(self):
        """Test getting sync preferences."""
        preferences = self.service.get_sync_preferences(self.user)

        self.assertTrue(preferences['sync_enabled'])
        self.assertEqual(len(preferences['connected_accounts']), 1)
        self.assertIn('google', preferences['last_sync_times'])
        self.assertIn('available_sync_fields', preferences)

    def test_update_sync_preferences(self):
        """Test updating sync preferences."""
        result = self.service.update_sync_preferences(
            self.user,
            {'sync_enabled': False}
        )

        self.assertTrue(result['success'])
        self.assertIn('allow_social_profile_sync', result['updated_fields'])

        self.privacy_settings.refresh_from_db()
        self.assertFalse(self.privacy_settings.allow_social_profile_sync)

    def test_manual_sync_from_provider(self):
        """Test manual sync from specific provider."""
        result = self.service.manual_sync_from_provider(self.user, 'google')

        self.assertTrue(result['success'])
        self.assertIn('updated_fields', result)

    def test_manual_sync_provider_not_found(self):
        """Test manual sync when provider not found."""
        result = self.service.manual_sync_from_provider(self.user, 'facebook')

        self.assertFalse(result['success'])
        self.assertIn('No active facebook account', result['error'])


class GoogleOAuthCallbackTests(TestCase):
    """Test Google OAuth callback handling."""

    def setUp(self):
        """Set up test data."""
        self.client = APIClient()

        # Create Google OAuth app configuration
        self.social_app = SocialApp.objects.create(
            provider='google',
            name='Google OAuth Test',
            client_id='test_client_id',
            secret='test_client_secret'
        )

        self.callback_url = reverse('authentication:social_auth:google_oauth_callback')

    @patch('authentication.services.google_oauth_service.GoogleOAuthService.exchange_code_for_tokens')
    @patch('authentication.services.google_oauth_service.GoogleOAuthService.authenticate_or_create_user')
    @patch('authentication.services.social_profile_sync_service.SocialProfileSyncService.sync_profile_from_social')
    def test_oauth_callback_success_new_user(self, mock_sync, mock_auth, mock_exchange):
        """Test successful OAuth callback for new user."""
        # Mock token exchange
        mock_exchange.return_value = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'user_info': {
                'id': '123456789',
                'email': 'newuser@gmail.com',
                'given_name': 'Jane',
                'family_name': 'Smith'
            }
        }

        # Mock user creation
        new_user = User.objects.create_user(
            email='newuser@gmail.com',
            first_name='Jane',
            last_name='Smith'
        )
        social_account = SocialAccount.objects.create(
            user=new_user,
            provider='google',
            provider_id='123456789',
            email='newuser@gmail.com'
        )
        mock_auth.return_value = (new_user, social_account, True)

        # Mock profile sync
        mock_sync.return_value = None

        response = self.client.get(self.callback_url, {
            'code': 'test_auth_code',
            'state': 'test_state'
        })

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertTrue(response_data['is_new_user'])
        self.assertIn('tokens', response_data)
        self.assertIn('user', response_data)

    def test_oauth_callback_error_handling(self):
        """Test OAuth callback error handling."""
        response = self.client.get(self.callback_url, {
            'error': 'access_denied',
            'error_description': 'User denied access'
        })

        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error'], 'access_denied')
        self.assertIn('fallback_url', response_data)

    def test_oauth_callback_missing_code(self):
        """Test OAuth callback with missing authorization code."""
        response = self.client.get(self.callback_url)

        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error'], 'invalid_request')

    @patch('authentication.services.google_oauth_service.GoogleOAuthService.exchange_code_for_tokens')
    @patch('authentication.services.google_oauth_service.GoogleOAuthService.complete_account_linking')
    @patch('authentication.services.social_profile_sync_service.SocialProfileSyncService.sync_profile_from_social')
    def test_oauth_callback_account_linking(self, mock_sync, mock_complete_linking, mock_exchange):
        """Test OAuth callback for account linking flow."""
        # Create user and link request
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        link_request = SocialAccountLinkRequest.objects.create(
            user=user,
            provider='google',
            provider_id='123456789',
            provider_email='test@gmail.com',
            verification_token='test_token'
        )

        # Mock token exchange
        mock_exchange.return_value = {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token',
            'user_info': {
                'id': '123456789',
                'email': 'test@gmail.com',
                'given_name': 'John',
                'family_name': 'Doe'
            }
        }

        # Mock successful linking
        social_account = SocialAccount.objects.create(
            user=user,
            provider='google',
            provider_id='123456789',
            email='test@gmail.com'
        )
        mock_complete_linking.return_value = social_account

        # Mock profile sync
        mock_sync.return_value = None

        response = self.client.get(self.callback_url, {
            'code': 'test_auth_code',
            'state': 'link_test_token'
        })

        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('Google account linked successfully', response_data['message'])