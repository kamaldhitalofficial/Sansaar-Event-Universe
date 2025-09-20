import logging
from typing import Dict, Any
from django.conf import settings
from django.contrib.auth import login
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.views.generic import View
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.services import GoogleOAuthService, SocialProfileSyncService
from authentication.models import SocialAccount, SocialAccountLinkRequest

# User data will be serialized inline

logger = logging.getLogger(__name__)


class GoogleOAuthCallbackView(View):
    """Handle Google OAuth callback and token exchange."""

    def __init__(self):
        super().__init__()
        self.google_service = GoogleOAuthService()
        self.profile_sync_service = SocialProfileSyncService()

    @method_decorator(csrf_exempt)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        """Handle GET request from Google OAuth redirect."""
        return self._handle_oauth_callback(request)

    def post(self, request):
        """Handle POST request with authorization code."""
        return self._handle_oauth_callback(request)

    def _handle_oauth_callback(self, request):
        """Process OAuth callback from Google."""
        try:
            # Get authorization code and state from request
            auth_code = request.GET.get('code') or request.POST.get('code')
            error = request.GET.get('error') or request.POST.get('error')
            error_description = request.GET.get('error_description') or request.POST.get('error_description')
            state = request.GET.get('state') or request.POST.get('state')

            # Handle OAuth errors
            if error:
                return self._handle_oauth_error(error, error_description)

            if not auth_code:
                return self._handle_oauth_error('invalid_request', 'No authorization code provided')

            # Get redirect URI from session or use default
            redirect_uri = request.session.get('oauth_redirect_uri', self._get_default_redirect_uri(request))

            # Exchange code for tokens
            token_data = self.google_service.exchange_code_for_tokens(auth_code, redirect_uri)

            # Check if this is an account linking request
            if state and state.startswith('link_'):
                return self._handle_account_linking(request, token_data, state)

            # Authenticate or create user
            user, social_account, is_new_user = self.google_service.authenticate_or_create_user(token_data)

            # Sync profile information
            if social_account:
                self.profile_sync_service.sync_profile_from_social(social_account)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            # Prepare response data
            user_data = {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_active': user.is_active,
                'is_email_verified': user.is_email_verified,
                'date_joined': user.date_joined.isoformat()
            }

            response_data = {
                'success': True,
                'user': user_data,
                'tokens': {
                    'access': access_token,
                    'refresh': refresh_token
                },
                'is_new_user': is_new_user,
                'social_account': {
                    'provider': social_account.provider,
                    'provider_id': social_account.provider_id,
                    'email': social_account.email
                }
            }

            # For web requests, redirect to frontend with tokens
            if self._is_web_request(request):
                frontend_url = self._build_frontend_redirect_url(response_data)
                return HttpResponseRedirect(frontend_url)

            # For API requests, return JSON response
            return JsonResponse(response_data, status=200)

        except Exception as e:
            logger.error(f"Google OAuth callback error: {e}")
            return self._handle_oauth_error('server_error', str(e))

    def _handle_account_linking(self, request, token_data, state):
        """Handle account linking flow."""
        try:
            # Extract verification token from state
            verification_token = state.replace('link_', '')

            # Complete account linking
            social_account = self.google_service.complete_account_linking(verification_token, token_data)

            # Sync profile information
            self.profile_sync_service.sync_profile_from_social(social_account)

            response_data = {
                'success': True,
                'message': 'Google account linked successfully',
                'social_account': {
                    'provider': social_account.provider,
                    'provider_id': social_account.provider_id,
                    'email': social_account.email
                }
            }

            # Redirect to frontend with success message
            if self._is_web_request(request):
                frontend_url = self._build_frontend_redirect_url(response_data, path='/account/social')
                return HttpResponseRedirect(frontend_url)

            return JsonResponse(response_data, status=200)

        except Exception as e:
            logger.error(f"Account linking error: {e}")
            return self._handle_oauth_error('linking_failed', str(e))

    def _handle_oauth_error(self, error_code, error_description=None):
        """Handle OAuth errors with appropriate fallback."""
        error_info = self.google_service.handle_authentication_failure(error_code, error_description)

        response_data = {
            'success': False,
            'error': error_code,
            'message': error_info['message'],
            'action': error_info['action'],
            'fallback_url': error_info['fallback_url']
        }

        # For web requests, redirect to frontend with error
        if hasattr(self, 'request') and self._is_web_request(self.request):
            frontend_url = self._build_frontend_redirect_url(response_data, path='/auth/error')
            return HttpResponseRedirect(frontend_url)

        return JsonResponse(response_data, status=400)

    def _is_web_request(self, request):
        """Check if this is a web browser request vs API request."""
        accept_header = request.META.get('HTTP_ACCEPT', '')
        return 'text/html' in accept_header

    def _get_default_redirect_uri(self, request):
        """Get default redirect URI for OAuth."""
        scheme = 'https' if request.is_secure() else 'http'
        host = request.get_host()
        path = reverse('google_oauth_callback')
        return f"{scheme}://{host}{path}"

    def _build_frontend_redirect_url(self, data, path='/auth/callback'):
        """Build frontend redirect URL with data."""
        frontend_base = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')

        # Convert data to query parameters
        params = []
        if data.get('success'):
            params.append('success=true')
            if data.get('tokens'):
                params.append(f"access_token={data['tokens']['access']}")
                params.append(f"refresh_token={data['tokens']['refresh']}")
            if data.get('is_new_user'):
                params.append('new_user=true')
        else:
            params.append('success=false')
            params.append(f"error={data.get('error', 'unknown')}")
            params.append(f"message={data.get('message', 'Authentication failed')}")

        query_string = '&'.join(params)
        return f"{frontend_base}{path}?{query_string}"


@api_view(['POST'])
@permission_classes([AllowAny])
def initiate_google_auth(request):
    """Initiate Google OAuth flow."""
    try:
        # Get redirect URI from request or use default
        redirect_uri = request.data.get('redirect_uri')
        if not redirect_uri:
            redirect_uri = request.build_absolute_uri(reverse('google_oauth_callback'))

        # Store redirect URI in session
        request.session['oauth_redirect_uri'] = redirect_uri

        # Build Google OAuth URL
        from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
        from allauth.socialaccount.models import SocialApp

        try:
            social_app = SocialApp.objects.get(provider='google')
        except SocialApp.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Google OAuth not configured'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Build authorization URL
        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={social_app.client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"scope=openid email profile&"
            f"response_type=code&"
            f"access_type=offline&"
            f"prompt=consent"
        )

        return Response({
            'success': True,
            'auth_url': auth_url,
            'redirect_uri': redirect_uri
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error initiating Google auth: {e}")
        return Response({
            'success': False,
            'error': 'Failed to initiate Google authentication'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def initiate_account_linking(request):
    """Initiate Google account linking for existing user."""
    try:
        # This endpoint would typically be called by authenticated users
        # For now, we'll accept email and verification token
        email = request.data.get('email')
        verification_token = request.data.get('verification_token')

        if not email or not verification_token:
            return Response({
                'success': False,
                'error': 'Email and verification token required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify the linking request exists
        try:
            link_request = SocialAccountLinkRequest.objects.get(
                verification_token=verification_token,
                status='pending'
            )
        except SocialAccountLinkRequest.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Invalid or expired linking request'
            }, status=status.HTTP_400_BAD_REQUEST)

        if link_request.is_expired():
            link_request.status = 'expired'
            link_request.save()
            return Response({
                'success': False,
                'error': 'Linking request has expired'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Build redirect URI
        redirect_uri = request.build_absolute_uri(reverse('google_oauth_callback'))

        # Build authorization URL with linking state
        from allauth.socialaccount.models import SocialApp

        social_app = SocialApp.objects.get(provider='google')

        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={social_app.client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"scope=openid email profile&"
            f"response_type=code&"
            f"access_type=offline&"
            f"prompt=consent&"
            f"state=link_{verification_token}"
        )

        return Response({
            'success': True,
            'auth_url': auth_url,
            'message': 'Complete the Google authentication to link your account'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error initiating account linking: {e}")
        return Response({
            'success': False,
            'error': 'Failed to initiate account linking'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def google_auth_status(request):
    """Get Google authentication status and fallback options."""
    try:
        # Check if Google OAuth is properly configured
        from allauth.socialaccount.models import SocialApp

        try:
            social_app = SocialApp.objects.get(provider='google')
            google_configured = bool(social_app.client_id and social_app.secret)
        except SocialApp.DoesNotExist:
            google_configured = False

        # Check if user has Google account linked (if authenticated)
        google_linked = False
        if request.user.is_authenticated:
            google_linked = SocialAccount.objects.filter(
                user=request.user,
                provider='google',
                is_active=True
            ).exists()

        return Response({
            'google_configured': google_configured,
            'google_linked': google_linked,
            'fallback_options': {
                'email_password': True,
                'password_reset': True,
                'registration': True
            },
            'status_message': 'Google authentication is available' if google_configured else 'Google authentication not configured'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error checking Google auth status: {e}")
        return Response({
            'google_configured': False,
            'google_linked': False,
            'fallback_options': {
                'email_password': True,
                'password_reset': True,
                'registration': True
            },
            'error': 'Unable to check authentication status'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def unlink_google_account(request):
    """Unlink Google account from user."""
    if not request.user.is_authenticated:
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        google_service = GoogleOAuthService()
        success = google_service.unlink_google_account(request.user)

        if success:
            return Response({
                'success': True,
                'message': 'Google account unlinked successfully'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'success': False,
                'error': 'No Google account found to unlink'
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Error unlinking Google account: {e}")
        return Response({
            'success': False,
            'error': 'Failed to unlink Google account'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)