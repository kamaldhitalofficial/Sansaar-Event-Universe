import logging
import secrets
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
from rest_framework.permissions import AllowAny, IsAuthenticated
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

            # Get user info from token data to validate linking request
            user_info = token_data.get('user_info', {})
            google_id = user_info.get('id')
            google_email = user_info.get('email')

            if not google_id or not google_email:
                return self._handle_oauth_error('invalid_user_data', 'Unable to get user information from Google')

            # Update the linking request with Google account details
            try:
                link_request = SocialAccountLinkRequest.objects.get(
                    verification_token=verification_token,
                    status='pending'
                )

                if link_request.is_expired():
                    link_request.status = 'expired'
                    link_request.save()
                    return self._handle_oauth_error('linking_expired', 'Linking request has expired')

                # Update the link request with Google account details
                link_request.provider_id = google_id
                link_request.provider_email = google_email
                link_request.temp_social_data = user_info
                link_request.save()

            except SocialAccountLinkRequest.DoesNotExist:
                return self._handle_oauth_error('invalid_linking_token', 'Invalid or expired linking request')

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
                    'email': social_account.email,
                    'linked_at': social_account.created_at.isoformat()
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
        path = reverse('authentication:social_auth:google_oauth_callback')
        return f"{scheme}://{host}{path}"

    def _build_frontend_redirect_url(self, data, path='/auth/callback'):
        """Build frontend redirect URL with data."""
        frontend_base = getattr(settings, 'FRONTEND_URL', 'http://localhost:5173')

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
    """Initiate Google OAuth flow with proper redirect handling."""
    try:
        # Get redirect URI from request or use default
        redirect_uri = request.data.get('redirect_uri')
        if not redirect_uri:
            redirect_uri = request.build_absolute_uri(reverse('authentication:social_auth:google_oauth_callback'))

        # Validate redirect URI format
        from urllib.parse import urlparse
        parsed_uri = urlparse(redirect_uri)
        if not parsed_uri.scheme or not parsed_uri.netloc:
            return Response({
                'success': False,
                'error': 'Invalid redirect URI format'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Store redirect URI in session
        request.session['oauth_redirect_uri'] = redirect_uri

        # Get additional parameters
        state = request.data.get('state', '')
        prompt = request.data.get('prompt', 'consent')  # consent, select_account, none

        # Build Google OAuth URL
        from allauth.socialaccount.models import SocialApp

        try:
            social_app = SocialApp.objects.get(provider='google')
            if not social_app.client_id or not social_app.secret:
                return Response({
                    'success': False,
                    'error': 'Google OAuth not properly configured'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except SocialApp.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Google OAuth not configured'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Build authorization URL with proper parameters
        auth_params = {
            'client_id': social_app.client_id,
            'redirect_uri': redirect_uri,
            'scope': 'openid email profile',
            'response_type': 'code',
            'access_type': 'offline',
            'prompt': prompt
        }

        if state:
            auth_params['state'] = state

        # Generate random state for CSRF protection if not provided
        if not state:
            import secrets
            csrf_state = secrets.token_urlsafe(32)
            auth_params['state'] = csrf_state
            request.session['oauth_state'] = csrf_state

        # Build URL
        from urllib.parse import urlencode
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(auth_params)}"

        return Response({
            'success': True,
            'auth_url': auth_url,
            'redirect_uri': redirect_uri,
            'state': auth_params.get('state'),
            'expires_in': 600  # OAuth flow should complete within 10 minutes
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
    """Initiate Google account linking for existing authenticated user."""
    if not request.user.is_authenticated:
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        google_service = GoogleOAuthService()

        # Check if user already has a Google account linked
        existing_google = SocialAccount.objects.filter(
            user=request.user,
            provider='google',
            is_active=True
        ).first()

        if existing_google:
            return Response({
                'success': False,
                'error': 'Google account already linked to this user'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Create a linking request
        verification_token = secrets.token_urlsafe(32)
        link_request = SocialAccountLinkRequest.objects.create(
            user=request.user,
            provider='google',
            provider_id='',  # Will be filled during OAuth callback
            provider_email='',  # Will be filled during OAuth callback
            verification_token=verification_token
        )

        # Build redirect URI
        redirect_uri = request.build_absolute_uri(reverse('authentication:social_auth:google_oauth_callback'))

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
            f"state=link_{link_request.verification_token}"
        )

        return Response({
            'success': True,
            'auth_url': auth_url,
            'verification_token': link_request.verification_token,
            'message': 'Complete the Google authentication to link your account'
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error initiating account linking: {e}")
        return Response({
            'success': False,
            'error': 'Failed to initiate account linking'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def google_auth_status(request):
    """Get comprehensive Google authentication status and fallback options."""
    try:
        # Check if Google OAuth is properly configured
        from allauth.socialaccount.models import SocialApp

        google_configured = False
        config_details = {}

        try:
            social_app = SocialApp.objects.get(provider='google')
            google_configured = bool(social_app.client_id and social_app.secret)
            config_details = {
                'client_id_configured': bool(social_app.client_id),
                'client_secret_configured': bool(social_app.secret),
                'app_name': social_app.name
            }
        except SocialApp.DoesNotExist:
            config_details = {
                'client_id_configured': False,
                'client_secret_configured': False,
                'app_name': None
            }

        # Initialize response data
        response_data = {
            'google_configured': google_configured,
            'configuration_details': config_details,
            'fallback_options': {
                'email_password': True,
                'password_reset': True,
                'registration': True,
                'mfa_available': True
            },
            'endpoints': {
                'login_initiation': '/api/auth/google/login/',
                'callback': '/api/auth/google/callback/',
                'status': '/api/auth/google/status/'
            }
        }

        # Add user-specific information if authenticated
        if request.user.is_authenticated:
            google_account = SocialAccount.objects.filter(
                user=request.user,
                provider='google',
                is_active=True
            ).first()

            response_data.update({
                'user_authenticated': True,
                'google_linked': bool(google_account),
                'endpoints': {
                    **response_data['endpoints'],
                    'account_linking': '/api/auth/google/link/',
                    'account_unlinking': '/api/auth/google/unlink/',
                    'profile_sync': '/api/auth/google/sync/',
                    'account_management': '/api/auth/google/manage/'
                }
            })

            if google_account:
                response_data['google_account_info'] = {
                    'email': google_account.email,
                    'linked_at': google_account.created_at.isoformat(),
                    'last_login': google_account.last_login_at.isoformat() if google_account.last_login_at else None,
                    'token_status': 'expired' if google_account.is_token_expired() else 'valid'
                }
        else:
            response_data.update({
                'user_authenticated': False,
                'google_linked': False
            })

        # Set appropriate status message
        if not google_configured:
            response_data['status_message'] = 'Google authentication not configured'
            response_data['status_code'] = 'not_configured'
        elif not request.user.is_authenticated:
            response_data['status_message'] = 'Google authentication available for login'
            response_data['status_code'] = 'available'
        elif response_data.get('google_linked'):
            response_data['status_message'] = 'Google account linked and active'
            response_data['status_code'] = 'linked'
        else:
            response_data['status_message'] = 'Google authentication available for linking'
            response_data['status_code'] = 'available_for_linking'

        return Response(response_data, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error checking Google auth status: {e}")
        return Response({
            'google_configured': False,
            'google_linked': False,
            'user_authenticated': request.user.is_authenticated,
            'fallback_options': {
                'email_password': True,
                'password_reset': True,
                'registration': True
            },
            'status_message': 'Unable to check authentication status',
            'status_code': 'error',
            'error': 'Service temporarily unavailable'
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


@api_view(['GET', 'POST'])
def google_profile_sync(request):
    """Manage Google profile synchronization with privacy controls."""
    if not request.user.is_authenticated:
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    profile_sync_service = SocialProfileSyncService()

    if request.method == 'GET':
        # Get current sync preferences and status
        try:
            sync_preferences = profile_sync_service.get_sync_preferences(request.user)
            return Response({
                'success': True,
                'sync_preferences': sync_preferences
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting sync preferences: {e}")
            return Response({
                'success': False,
                'error': 'Failed to get sync preferences'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elif request.method == 'POST':
        # Update sync preferences or trigger manual sync
        action = request.data.get('action')

        if action == 'update_preferences':
            try:
                preferences = request.data.get('preferences', {})
                result = profile_sync_service.update_sync_preferences(request.user, preferences)

                if result.get('success'):
                    return Response({
                        'success': True,
                        'message': 'Sync preferences updated successfully',
                        'updated_fields': result.get('updated_fields', [])
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'success': False,
                        'error': result.get('error', 'Failed to update preferences')
                    }, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                logger.error(f"Error updating sync preferences: {e}")
                return Response({
                    'success': False,
                    'error': 'Failed to update sync preferences'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif action == 'manual_sync':
            try:
                result = profile_sync_service.manual_sync_from_provider(request.user, 'google')

                if result.get('success'):
                    return Response({
                        'success': True,
                        'message': 'Profile synced successfully from Google',
                        'updated_fields': result.get('updated_fields', []),
                        'sync_timestamp': result.get('sync_timestamp')
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'success': False,
                        'error': result.get('error', 'Failed to sync profile')
                    }, status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                logger.error(f"Error during manual sync: {e}")
                return Response({
                    'success': False,
                    'error': 'Failed to sync profile'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        else:
            return Response({
                'success': False,
                'error': 'Invalid action. Use "update_preferences" or "manual_sync"'
            }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def google_account_management(request):
    """Get comprehensive Google account management information."""
    if not request.user.is_authenticated:
        return Response({
            'success': False,
            'error': 'Authentication required'
        }, status=status.HTTP_401_UNAUTHORIZED)

    try:
        # Get Google account information
        google_account = SocialAccount.objects.filter(
            user=request.user,
            provider='google',
            is_active=True
        ).first()

        # Get sync preferences
        profile_sync_service = SocialProfileSyncService()
        sync_preferences = profile_sync_service.get_sync_preferences(request.user)

        # Check authentication status
        from allauth.socialaccount.models import SocialApp

        try:
            social_app = SocialApp.objects.get(provider='google')
            google_configured = bool(social_app.client_id and social_app.secret)
        except SocialApp.DoesNotExist:
            google_configured = False

        account_info = {
            'google_configured': google_configured,
            'account_linked': bool(google_account),
            'sync_preferences': sync_preferences,
            'management_options': {
                'can_link': not bool(google_account) and google_configured,
                'can_unlink': bool(google_account),
                'can_sync': bool(google_account),
                'can_update_preferences': True
            }
        }

        if google_account:
            account_info['google_account'] = {
                'email': google_account.email,
                'first_name': google_account.first_name,
                'last_name': google_account.last_name,
                'profile_picture_url': google_account.profile_picture_url,
                'connected_at': google_account.created_at.isoformat(),
                'last_login': google_account.last_login_at.isoformat() if google_account.last_login_at else None,
                'last_sync': google_account.updated_at.isoformat(),
                'token_expired': google_account.is_token_expired()
            }

        return Response({
            'success': True,
            'account_management': account_info
        }, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"Error getting account management info: {e}")
        return Response({
            'success': False,
            'error': 'Failed to get account management information'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)