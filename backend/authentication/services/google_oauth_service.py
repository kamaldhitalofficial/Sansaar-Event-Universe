import logging
import secrets
import requests
from typing import Dict, Optional, Tuple, Any
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from allauth.socialaccount.models import SocialApp, SocialToken
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount import app_settings
from authentication.models import SocialAccount, SocialAccountLinkRequest
from authentication.services.email_service import EmailService

User = get_user_model()
logger = logging.getLogger(__name__)


class GoogleOAuthService:
    """Service for handling Google OAuth authentication and account management."""

    PROVIDER_NAME = 'google'
    GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo'

    def __init__(self):
        self.email_service = EmailService()

    def exchange_code_for_tokens(self, authorization_code: str, redirect_uri: str) -> Dict[str, Any]:
        """
        Exchange authorization code for access and refresh tokens.

        Args:
            authorization_code: The authorization code from Google
            redirect_uri: The redirect URI used in the OAuth flow

        Returns:
            Dict containing token information and user data

        Raises:
            ValidationError: If token exchange fails
        """
        try:
            # Get Google OAuth app configuration
            social_app = SocialApp.objects.get(provider=self.PROVIDER_NAME)

            # Prepare token exchange request
            token_data = {
                'client_id': social_app.client_id,
                'client_secret': social_app.secret,
                'code': authorization_code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri,
            }

            # Exchange code for tokens
            token_response = requests.post(
                'https://oauth2.googleapis.com/token',
                data=token_data,
                timeout=30
            )

            if not token_response.ok:
                logger.error(f"Token exchange failed: {token_response.text}")
                raise ValidationError("Failed to exchange authorization code for tokens")

            token_info = token_response.json()

            # Get user information using access token
            user_info = self._get_user_info(token_info['access_token'])

            return {
                'access_token': token_info['access_token'],
                'refresh_token': token_info.get('refresh_token'),
                'expires_in': token_info.get('expires_in'),
                'token_type': token_info.get('token_type', 'Bearer'),
                'user_info': user_info
            }

        except SocialApp.DoesNotExist:
            logger.error("Google OAuth app not configured")
            raise ValidationError("Google OAuth not properly configured")
        except requests.RequestException as e:
            logger.error(f"Network error during token exchange: {e}")
            raise ValidationError("Network error during authentication")
        except Exception as e:
            logger.error(f"Unexpected error during token exchange: {e}")
            raise ValidationError("Authentication failed")

    def _get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Google using access token.

        Args:
            access_token: Google OAuth access token

        Returns:
            Dict containing user information
        """
        headers = {'Authorization': f'Bearer {access_token}'}

        response = requests.get(
            self.GOOGLE_USERINFO_URL,
            headers=headers,
            timeout=30
        )

        if not response.ok:
            logger.error(f"Failed to get user info: {response.text}")
            raise ValidationError("Failed to retrieve user information")

        return response.json()

    def authenticate_or_create_user(self, token_data: Dict[str, Any]) -> Tuple[User, SocialAccount, bool]:
        """
        Authenticate existing user or create new user with Google account.

        Args:
            token_data: Token and user information from Google

        Returns:
            Tuple of (User, SocialAccount, created) where created indicates if user was new
        """
        user_info = token_data['user_info']
        google_id = user_info['id']
        email = user_info['email']

        with transaction.atomic():
            # Check if social account already exists
            try:
                social_account = SocialAccount.objects.get(
                    provider=self.PROVIDER_NAME,
                    provider_id=google_id
                )
                # Update tokens and profile info
                self._update_social_account_tokens(social_account, token_data)
                self._sync_profile_from_google(social_account, user_info)
                social_account.record_login()

                return social_account.user, social_account, False

            except SocialAccount.DoesNotExist:
                pass

            # Check if user exists with this email
            try:
                existing_user = User.objects.get(email=email)
                # Create social account for existing user
                social_account = self._create_social_account(
                    existing_user, google_id, token_data
                )
                return existing_user, social_account, False

            except User.DoesNotExist:
                # Create new user and social account
                user = self._create_user_from_google(user_info)
                social_account = self._create_social_account(
                    user, google_id, token_data
                )
                return user, social_account, True

    def _create_user_from_google(self, user_info: Dict[str, Any]) -> User:
        """Create a new user from Google user information."""
        user_data = {
            'email': user_info['email'],
            'first_name': user_info.get('given_name', ''),
            'last_name': user_info.get('family_name', ''),
            'is_active': True,  # Social accounts are pre-verified
            'is_email_verified': True,  # Google emails are verified
        }

        user = User.objects.create_user(**user_data)
        logger.info(f"Created new user from Google: {user.email}")
        return user

    def _create_social_account(self, user: User, google_id: str, token_data: Dict[str, Any]) -> SocialAccount:
        """Create a social account for the user."""
        user_info = token_data['user_info']

        social_account = SocialAccount.objects.create(
            user=user,
            provider=self.PROVIDER_NAME,
            provider_id=google_id,
            email=user_info['email'],
            first_name=user_info.get('given_name', ''),
            last_name=user_info.get('family_name', ''),
            profile_picture_url=user_info.get('picture'),
            access_token=token_data['access_token'],
            refresh_token=token_data.get('refresh_token', ''),
            extra_data=user_info
        )

        # Set token expiration if provided
        if token_data.get('expires_in'):
            social_account.token_expires_at = (
                    timezone.now() + timezone.timedelta(seconds=token_data['expires_in'])
            )
            social_account.save(update_fields=['token_expires_at'])

        social_account.record_login()
        logger.info(f"Created social account for user: {user.email}")
        return social_account

    def _update_social_account_tokens(self, social_account: SocialAccount, token_data: Dict[str, Any]):
        """Update tokens for existing social account."""
        social_account.update_tokens(
            access_token=token_data['access_token'],
            refresh_token=token_data.get('refresh_token'),
            expires_in=token_data.get('expires_in')
        )

    def _sync_profile_from_google(self, social_account: SocialAccount, user_info: Dict[str, Any]):
        """Sync profile information from Google."""
        social_account.update_profile_info(
            first_name=user_info.get('given_name', ''),
            last_name=user_info.get('family_name', ''),
            profile_picture_url=user_info.get('picture'),
            extra_data=user_info
        )

        # Optionally sync to user model if user allows it
        user = social_account.user
        if not user.first_name and user_info.get('given_name'):
            user.first_name = user_info['given_name']
        if not user.last_name and user_info.get('family_name'):
            user.last_name = user_info['family_name']

        if user.first_name or user.last_name:
            user.save(update_fields=['first_name', 'last_name'])

    def initiate_account_linking(self, user: User, google_id: str,
                                 user_info: Dict[str, Any]) -> SocialAccountLinkRequest:
        """
        Initiate account linking process for existing user.

        Args:
            user: Existing user who wants to link Google account
            google_id: Google user ID
            user_info: Google user information

        Returns:
            SocialAccountLinkRequest instance
        """
        # Check if this Google account is already linked to another user
        existing_social = SocialAccount.objects.filter(
            provider=self.PROVIDER_NAME,
            provider_id=google_id
        ).first()

        if existing_social:
            raise ValidationError("This Google account is already linked to another user")

        # Check if user already has a Google account linked
        existing_link = SocialAccount.objects.filter(
            user=user,
            provider=self.PROVIDER_NAME
        ).first()

        if existing_link:
            raise ValidationError("User already has a Google account linked")

        # Create link request
        verification_token = secrets.token_urlsafe(32)

        link_request = SocialAccountLinkRequest.objects.create(
            user=user,
            provider=self.PROVIDER_NAME,
            provider_id=google_id,
            provider_email=user_info['email'],
            verification_token=verification_token,
            temp_social_data=user_info
        )

        # Send verification email
        self._send_account_linking_email(user, link_request)

        logger.info(f"Initiated account linking for user: {user.email}")
        return link_request

    def complete_account_linking(self, verification_token: str, token_data: Dict[str, Any]) -> SocialAccount:
        """
        Complete account linking process.

        Args:
            verification_token: Token from the linking email
            token_data: OAuth token data

        Returns:
            Created SocialAccount instance
        """
        try:
            link_request = SocialAccountLinkRequest.objects.get(
                verification_token=verification_token,
                status='pending'
            )
        except SocialAccountLinkRequest.DoesNotExist:
            raise ValidationError("Invalid or expired linking request")

        if link_request.is_expired():
            link_request.status = 'expired'
            link_request.save()
            raise ValidationError("Linking request has expired")

        with transaction.atomic():
            # Create the social account
            social_account = self._create_social_account(
                link_request.user,
                link_request.provider_id,
                token_data
            )

            # Mark link request as completed
            link_request.complete_linking()

            logger.info(f"Completed account linking for user: {link_request.user.email}")
            return social_account

    def _send_account_linking_email(self, user: User, link_request: SocialAccountLinkRequest):
        """Send account linking verification email."""
        try:
            # This would typically include a link to verify the account linking
            # For now, we'll just log it
            logger.info(
                f"Account linking email would be sent to {user.email} with token {link_request.verification_token}")

            # In a real implementation, you would send an email with a verification link
            # self.email_service.send_account_linking_email(user, link_request)

        except Exception as e:
            logger.error(f"Failed to send account linking email: {e}")

    def refresh_access_token(self, social_account: SocialAccount) -> bool:
        """
        Refresh the access token for a social account.

        Args:
            social_account: SocialAccount instance

        Returns:
            True if refresh was successful, False otherwise
        """
        if not social_account.refresh_token:
            logger.warning(f"No refresh token available for {social_account}")
            return False

        try:
            social_app = SocialApp.objects.get(provider=self.PROVIDER_NAME)

            refresh_data = {
                'client_id': social_app.client_id,
                'client_secret': social_app.secret,
                'refresh_token': social_account.refresh_token,
                'grant_type': 'refresh_token',
            }

            response = requests.post(
                'https://oauth2.googleapis.com/token',
                data=refresh_data,
                timeout=30
            )

            if response.ok:
                token_info = response.json()
                social_account.update_tokens(
                    access_token=token_info['access_token'],
                    refresh_token=token_info.get('refresh_token', social_account.refresh_token),
                    expires_in=token_info.get('expires_in')
                )
                logger.info(f"Refreshed tokens for {social_account}")
                return True
            else:
                logger.error(f"Token refresh failed: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error refreshing token: {e}")
            return False

    def handle_authentication_failure(self, error_code: str, error_description: str = None) -> Dict[str, str]:
        """
        Handle Google authentication failures with appropriate fallback.

        Args:
            error_code: OAuth error code
            error_description: Optional error description

        Returns:
            Dict with error information and suggested actions
        """
        fallback_actions = {
            'access_denied': {
                'message': 'Google authentication was cancelled. You can try again or use email/password login.',
                'action': 'retry_or_fallback',
                'fallback_url': '/auth/login/'
            },
            'invalid_request': {
                'message': 'There was an issue with the authentication request. Please try again.',
                'action': 'retry',
                'fallback_url': '/auth/google/'
            },
            'server_error': {
                'message': 'Google authentication is temporarily unavailable. Please use email/password login.',
                'action': 'fallback',
                'fallback_url': '/auth/login/'
            },
            'temporarily_unavailable': {
                'message': 'Google authentication is temporarily unavailable. Please try again later.',
                'action': 'retry_later',
                'fallback_url': '/auth/login/'
            }
        }

        error_info = fallback_actions.get(error_code, {
            'message': 'Google authentication failed. Please use email/password login.',
            'action': 'fallback',
            'fallback_url': '/auth/login/'
        })

        logger.warning(f"Google auth failure: {error_code} - {error_description}")
        return error_info

    def unlink_google_account(self, user: User) -> bool:
        """
        Unlink Google account from user.

        Args:
            user: User instance

        Returns:
            True if unlinking was successful
        """
        try:
            social_account = SocialAccount.objects.get(
                user=user,
                provider=self.PROVIDER_NAME
            )

            # Revoke tokens with Google if possible
            if social_account.access_token:
                try:
                    requests.post(
                        f'https://oauth2.googleapis.com/revoke?token={social_account.access_token}',
                        timeout=10
                    )
                except requests.RequestException:
                    # Continue with unlinking even if revocation fails
                    pass

            social_account.delete()
            logger.info(f"Unlinked Google account for user: {user.email}")
            return True

        except SocialAccount.DoesNotExist:
            logger.warning(f"No Google account to unlink for user: {user.email}")
            return False
        except Exception as e:
            logger.error(f"Error unlinking Google account: {e}")
            return False