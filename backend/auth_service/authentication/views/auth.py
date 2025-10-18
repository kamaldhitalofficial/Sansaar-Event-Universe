"""
Google OAuth 2.0 authentication views.

This module provides API views for Google OAuth 2.0 authentication,
including login initiation, callback handling, and account management.
"""
from django.conf import settings
from django.contrib.auth import login
from django.shortcuts import redirect
from django.urls import reverse
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from allauth.socialaccount.models import SocialAccount, SocialApp
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from drf_spectacular.utils import extend_schema, OpenApiResponse
import logging

logger = logging.getLogger(__name__)


class GoogleOAuthLoginView(APIView):
    """
    Initiate Google OAuth 2.0 login process.

    This view redirects users to Google's OAuth consent screen
    to begin the authentication process.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Initiate Google OAuth login",
        description="Redirects to Google OAuth consent screen to begin authentication",
        responses={
            302: OpenApiResponse(description="Redirect to Google OAuth consent screen"),
            400: OpenApiResponse(description="OAuth configuration error"),
        }
    )
    def get(self, request):
        """Redirect to Google OAuth consent screen."""
        try:
            # Get Google OAuth app configuration
            google_app = SocialApp.objects.get(provider='google')

            # Build OAuth authorization URL
            oauth_adapter = GoogleOAuth2Adapter(request)
            client = OAuth2Client(
                request,
                google_app.client_id,
                google_app.secret,
                oauth_adapter.access_token_method,
                oauth_adapter.access_token_url,
                callback_url=request.build_absolute_uri(reverse('authentication:social_auth:google_oauth_callback')),
                scope=oauth_adapter.get_scope(request)
            )

            # Get authorization URL
            authorization_url, state = client.get_authorization_url(
                oauth_adapter.authorize_url,
                state=oauth_adapter.get_state(request)
            )

            # Store state in session for security
            request.session['oauth_state'] = state

            return redirect(authorization_url)

        except SocialApp.DoesNotExist:
            logger.error("Google OAuth app not configured")
            return Response(
                {'error': 'Google OAuth not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"OAuth initiation error: {str(e)}")
            return Response(
                {'error': 'OAuth initiation failed'},
                status=status.HTTP_400_BAD_REQUEST
            )


class GoogleOAuthCallbackView(APIView):
    """
    Handle Google OAuth 2.0 callback.

    This view processes the callback from Google OAuth,
    exchanges the authorization code for tokens, and
    creates or authenticates the user.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Handle Google OAuth callback",
        description="Process OAuth callback and authenticate user",
        responses={
            200: OpenApiResponse(description="Authentication successful"),
            400: OpenApiResponse(description="Authentication failed"),
        }
    )
    def get(self, request):
        """Process Google OAuth callback."""
        try:
            # Get authorization code and state from callback
            code = request.GET.get('code')
            state = request.GET.get('state')
            error = request.GET.get('error')

            if error:
                logger.warning(f"OAuth error: {error}")
                return Response(
                    {'error': f'OAuth error: {error}'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if not code:
                return Response(
                    {'error': 'Authorization code not provided'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Verify state parameter for security
            stored_state = request.session.get('oauth_state')
            if not stored_state or stored_state != state:
                logger.warning("OAuth state mismatch")
                return Response(
                    {'error': 'Invalid state parameter'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Exchange code for tokens using allauth
            google_app = SocialApp.objects.get(provider='google')
            oauth_adapter = GoogleOAuth2Adapter(request)
            client = OAuth2Client(
                request,
                google_app.client_id,
                google_app.secret,
                oauth_adapter.access_token_method,
                oauth_adapter.access_token_url,
                callback_url=request.build_absolute_uri(reverse('authentication:social_auth:google_oauth_callback'))
            )

            # Get access token
            access_token = client.get_access_token(code)

            # Get user info from Google
            user_info = oauth_adapter.get_user_info(access_token['access_token'])

            # Create or get user account
            user = self._get_or_create_user(user_info, access_token)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            # Clean up session
            if 'oauth_state' in request.session:
                del request.session['oauth_state']

            return Response({
                'message': 'Authentication successful',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                },
                'tokens': {
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                }
            })

        except SocialApp.DoesNotExist:
            logger.error("Google OAuth app not configured")
            return Response(
                {'error': 'Google OAuth not configured'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"OAuth callback error: {str(e)}")
            return Response(
                {'error': 'Authentication failed'},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _get_or_create_user(self, user_info, access_token):
        """Get or create user from Google user info."""
        from authentication.models import User

        email = user_info.get('email')
        if not email:
            raise ValueError("Email not provided by Google")

        # Try to get existing user
        try:
            user = User.objects.get(email=email)
            # Update user info from Google if needed
            if not user.first_name and user_info.get('given_name'):
                user.first_name = user_info['given_name']
            if not user.last_name and user_info.get('family_name'):
                user.last_name = user_info['family_name']
            user.save()
        except User.DoesNotExist:
            # Create new user
            user = User.objects.create_user(
                email=email,
                first_name=user_info.get('given_name', ''),
                last_name=user_info.get('family_name', ''),
                is_email_verified=True  # Google accounts are pre-verified
            )

        # Create or update social account
        social_account, created = SocialAccount.objects.get_or_create(
            user=user,
            provider='google',
            defaults={
                'uid': user_info.get('id'),
                'extra_data': user_info
            }
        )

        if not created:
            # Update existing social account
            social_account.extra_data = user_info
            social_account.save()

        return user


class GoogleAccountConnectView(APIView):
    """
    Connect Google account to existing authenticated user.

    This view allows authenticated users to link their
    Google account to their existing account.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Connect Google account",
        description="Link Google account to existing user account",
        responses={
            200: OpenApiResponse(description="Account linked successfully"),
            400: OpenApiResponse(description="Account linking failed"),
        }
    )
    def post(self, request):
        """Connect Google account to current user."""
        # This would implement the account linking flow
        # For now, return a placeholder response
        return Response({
            'message': 'Google account linking not yet implemented',
            'redirect_url': '/accounts/google/login/'
        })


class GoogleAccountDisconnectView(APIView):
    """
    Disconnect Google account from authenticated user.

    This view allows users to unlink their Google account
    from their existing account.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Disconnect Google account",
        description="Unlink Google account from user account",
        responses={
            200: OpenApiResponse(description="Account disconnected successfully"),
            400: OpenApiResponse(description="Account disconnection failed"),
        }
    )
    def post(self, request):
        """Disconnect Google account from current user."""
        try:
            social_account = SocialAccount.objects.get(
                user=request.user,
                provider='google'
            )
            social_account.delete()

            return Response({
                'message': 'Google account disconnected successfully'
            })

        except SocialAccount.DoesNotExist:
            return Response(
                {'error': 'No Google account connected'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Account disconnection error: {str(e)}")
            return Response(
                {'error': 'Account disconnection failed'},
                status=status.HTTP_400_BAD_REQUEST
            )