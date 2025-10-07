from .models import OAuthState, OAuthToken
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from .serializers import RegisterSerializer, LoginSerializer, ResendVerificationSerializer
import logging, secrets, requests
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout


User = get_user_model()

logger = logging.getLogger(__name__)

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


def send_verification_email(user, request):
    verification_url = f"{request.scheme}://{request.get_host()}/api/auth/verify-email/?token={user.email_verification_token}"
    
    subject = 'Verify Your Email Address'
    message = f"""
    Hello {user.username},
    
    Thank you for registering! Please verify your email address by clicking the link below:
    
    {verification_url}
    
    This link will expire in 24 hours.
    
    If you didn't create an account, please ignore this email.
    
    Best regards,
    Your App Team
    """
    
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )
    
    user.email_verification_sent_at = timezone.now()
    user.save()


@method_decorator(ratelimit(key='ip', rate='100/h', method='POST'), name='dispatch')
class RegisterView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            
            # Send verification email
            try:
                send_verification_email(user, request)
            except Exception as e:
                user.delete()
                return Response(
                    {'error': 'Failed to send verification email. Please try again.'},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            return Response({
                'message': 'Registration successful! Please check your email to verify your account.',
                'email': user.email
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(ratelimit(key='ip', rate='100/h', method='POST'), name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email'].lower()
        password = serializer.validated_data['password']
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'error': 'Invalid credentials.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if account is locked
        if user.is_locked():
            remaining_time = (user.locked_until - timezone.now()).seconds // 60
            return Response(
                {'error': f'Account is locked due to multiple failed login attempts. Try again in {remaining_time} minutes.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check if email is verified
        if not user.is_email_verified:
            return Response(
                {'error': 'Please verify your email address before logging in.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Authenticate user
        auth_user = authenticate(request, username=email, password=password)
        
        if auth_user is not None:
            # Reset failed attempts on successful login
            user.reset_failed_login()
            
            # Generate JWT tokens
            tokens = get_tokens_for_user(auth_user)
            
            return Response({
                'message': 'Login successful!',
                'tokens': tokens,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                }
            }, status=status.HTTP_200_OK)
        else:
            # Increment failed login attempts
            user.increment_failed_login()
            
            remaining_attempts = 5 - user.failed_login_attempts
            if remaining_attempts > 0:
                return Response(
                    {'error': f'Invalid credentials. {remaining_attempts} attempts remaining.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )
            else:
                return Response(
                    {'error': 'Account has been locked due to multiple failed login attempts.'},
                    status=status.HTTP_403_FORBIDDEN
                )


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        token = request.query_params.get('token')
        
        if not token:
            return Response(
                {'error': 'Verification token is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(email_verification_token=token)
        except User.DoesNotExist:
            return Response(
                {'error': 'Invalid verification token.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if token has expired
        if user.email_verification_sent_at:
            expiry_time = user.email_verification_sent_at + timedelta(hours=24)
            if timezone.now() > expiry_time:
                return Response(
                    {'error': 'Verification link has expired. Please request a new one.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        if user.is_email_verified:
            return Response(
                {'message': 'Email already verified.'},
                status=status.HTTP_200_OK
            )
        
        user.is_email_verified = True
        user.save()
        
        return Response(
            {'message': 'Email verified successfully! You can now login.'},
            status=status.HTTP_200_OK
        )


@method_decorator(ratelimit(key='ip', rate='100/h', method='POST'), name='dispatch')
class ResendVerificationView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ResendVerificationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email'].lower()
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'error': 'No user found with this email.'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if user.is_email_verified:
            return Response(
                {'message': 'Email is already verified.'},
                status=status.HTTP_200_OK
            )
        
        # Regenerate token
        import uuid
        user.email_verification_token = uuid.uuid4()
        user.save()
        
        # Send new verification email
        send_verification_email(user, request)
        
        return Response(
            {'message': 'Verification email sent successfully!'},
            status=status.HTTP_200_OK
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response(
                {'message': 'Logout successful!'},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'error': 'Invalid token.'},
                status=status.HTTP_400_BAD_REQUEST
            )


class RefreshTokenView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            return Response(
                {'error': 'Refresh token is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            token = RefreshToken(refresh_token)
            
            # This automatically blacklists old token and creates new one
            # due to ROTATE_REFRESH_TOKENS setting
            return Response({
                'access': str(token.access_token),
                'refresh': str(token)
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {'error': 'Invalid or expired refresh token.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        

class GoogleOAuthService:
    def __init__(self):
        self.client_id = settings.GOOGLE_OAUTH_CLIENT_ID
        self.client_secret = settings.GOOGLE_OAUTH_CLIENT_SECRET
        self.redirect_uri = settings.GOOGLE_OAUTH_REDIRECT_URI
        self.scope = 'openid email profile'
        self.auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
        self.token_url = 'https://oauth2.googleapis.com/token'
        self.userinfo_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
    
    def generate_auth_url(self):
        """Generate Google OAuth authorization URL"""
        state = secrets.token_urlsafe(32)
        
        # Store state for verification
        OAuthState.objects.create(state=state)
        
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope,
            'response_type': 'code',
            'state': state,
            'access_type': 'offline',
            'prompt': 'consent'
        }
        
        auth_url = f"{self.auth_url}?" + "&".join([f"{k}={v}" for k, v in params.items()])
        return auth_url, state
    
    def verify_state(self, state):
        """Verify OAuth state parameter"""
        try:
            oauth_state = OAuthState.objects.get(state=state, used=False)
            if oauth_state.is_expired():
                oauth_state.delete()
                return False
            
            oauth_state.used = True
            oauth_state.save()
            return True
        except OAuthState.DoesNotExist:
            return False
    
    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri,
        }
        
        response = requests.post(self.token_url, data=data)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Token exchange failed: {response.text}")
            return None
    
    def get_user_info(self, access_token):
        """Get user information from Google"""
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(self.userinfo_url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"User info fetch failed: {response.text}")
            return None
    
    def refresh_token(self, refresh_token):
        """Refresh OAuth token"""
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
        }
        
        response = requests.post(self.token_url, data=data)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Token refresh failed: {response.text}")
            return None
    
    def revoke_token(self, token):
        """Revoke OAuth token"""
        revoke_url = f"https://oauth2.googleapis.com/revoke?token={token}"
        response = requests.post(revoke_url)
        return response.status_code == 200
    
    def create_or_update_user(self, user_info, token_data):
        """Create or update user from Google OAuth data"""
        email = user_info.get('email')
        google_id = user_info.get('id')
        
        if not email or not google_id:
            raise ValueError("Missing required user information")
        
        # Check if user exists with this Google ID
        try:
            user = User.objects.get(google_id=google_id)
            # Update existing OAuth user
            user.email = email
            user.first_name = user_info.get('given_name', '')
            user.last_name = user_info.get('family_name', '')
            user.profile_picture = user_info.get('picture', '')
            user.is_email_verified = user_info.get('verified_email', False)
            user.save()
        except User.DoesNotExist:
            # Check if user exists with this email
            try:
                user = User.objects.get(email=email)
                # Link existing account to Google OAuth
                user.connect_google_oauth(
                    google_id=google_id,
                    profile_picture=user_info.get('picture', '')
                )
            except User.DoesNotExist:
                # Create new user
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    first_name=user_info.get('given_name', ''),
                    last_name=user_info.get('family_name', ''),
                    google_id=google_id,
                    profile_picture=user_info.get('picture', ''),
                    oauth_provider='google',
                    is_oauth_user=True,
                    is_email_verified=user_info.get('verified_email', False),
                    oauth_connected_at=timezone.now()
                )
        
        # Store or update OAuth token
        expires_at = timezone.now() + timedelta(seconds=token_data.get('expires_in', 3600))
        
        oauth_token, created = OAuthToken.objects.get_or_create(
            user=user,
            defaults={
                'access_token': token_data['access_token'],
                'refresh_token': token_data.get('refresh_token'),
                'token_type': token_data.get('token_type', 'Bearer'),
                'expires_at': expires_at,
                'scope': token_data.get('scope', ''),
                'provider': 'google'
            }
        )
        
        if not created:
            # Update existing token
            oauth_token.access_token = token_data['access_token']
            if token_data.get('refresh_token'):
                oauth_token.refresh_token = token_data['refresh_token']
            oauth_token.token_type = token_data.get('token_type', 'Bearer')
            oauth_token.expires_at = expires_at
            oauth_token.scope = token_data.get('scope', '')
            oauth_token.save()
        
        return user
    

@require_http_methods(["GET"])
def google_oauth_login(request):
    """Initiate Google OAuth login"""
    try:
        oauth_service = GoogleOAuthService()
        auth_url, state = oauth_service.generate_auth_url()
        
        # Store state in session for additional security
        request.session['oauth_state'] = state
        
        return redirect(auth_url)
    except Exception as e:
        logger.error(f"OAuth login initiation failed: {str(e)}")
        messages.error(request, "Failed to initiate Google login. Please try again.")
        return redirect('accounts:login')

@csrf_exempt
@require_http_methods(["GET"])
def google_oauth_callback(request):
    """Handle Google OAuth callback"""
    try:
        code = request.GET.get('code')
        state = request.GET.get('state')
        error = request.GET.get('error')
        
        # Handle OAuth errors
        if error:
            error_description = request.GET.get('error_description', 'Unknown error')
            logger.error(f"OAuth error: {error} - {error_description}")
            messages.error(request, f"Google authentication failed: {error_description}")
            return redirect('accounts:login')
        
        if not code or not state:
            messages.error(request, "Invalid OAuth response. Please try again.")
            return redirect('accounts:login')
        
        oauth_service = GoogleOAuthService()
        
        # Verify state parameter
        if not oauth_service.verify_state(state):
            messages.error(request, "Invalid OAuth state. Possible security issue.")
            return redirect('accounts:login')
        
        # Exchange code for token
        token_data = oauth_service.exchange_code_for_token(code)
        if not token_data:
            messages.error(request, "Failed to obtain access token from Google.")
            return redirect('accounts:login')
        
        # Get user information
        user_info = oauth_service.get_user_info(token_data['access_token'])
        if not user_info:
            messages.error(request, "Failed to get user information from Google.")
            return redirect('accounts:login')
        
        # Create or update user
        user = oauth_service.create_or_update_user(user_info, token_data)
        
        # Log the user in
        login(request, user)
        
        # Clear OAuth state from session
        request.session.pop('oauth_state', None)
        
        messages.success(request, f"Welcome, {user.first_name or user.username}!")
        
        # Redirect to next page or dashboard
        next_url = request.session.pop('next', None) or reverse('dashboard')
        return redirect(next_url)
        
    except Exception as e:
        logger.error(f"OAuth callback failed: {str(e)}")
        messages.error(request, "Authentication failed. Please try again.")
        return redirect('accounts:login')

@login_required
@require_http_methods(["POST"])
def connect_google_oauth(request):
    """Connect existing account to Google OAuth"""
    try:
        if request.user.is_oauth_user and request.user.oauth_provider == 'google':
            return JsonResponse({
                'error': 'Account is already connected to Google'
            }, status=400)
        
        oauth_service = GoogleOAuthService()
        auth_url, state = oauth_service.generate_auth_url()
        
        # Store connection intent in session
        request.session['oauth_connect_mode'] = True
        request.session['oauth_state'] = state
        
        return JsonResponse({
            'auth_url': auth_url
        })
        
    except Exception as e:
        logger.error(f"OAuth connection failed: {str(e)}")
        return JsonResponse({
            'error': 'Failed to initiate Google connection'
        }, status=500)

@login_required
@require_http_methods(["POST"])
def disconnect_google_oauth(request):
    """Disconnect Google OAuth from account"""
    try:
        user = request.user
        
        if not user.is_oauth_user or user.oauth_provider != 'google':
            return JsonResponse({
                'error': 'Account is not connected to Google'
            }, status=400)
        
        # Check if user has a password (for security)
        if not user.has_usable_password():
            return JsonResponse({
                'error': 'Cannot disconnect Google account. Please set a password first.'
            }, status=400)
        
        oauth_service = GoogleOAuthService()
        
        # Revoke token if it exists
        try:
            oauth_token = user.oauth_token
            if oauth_token.access_token:
                oauth_service.revoke_token(oauth_token.access_token)
            oauth_token.delete()
        except OAuthToken.DoesNotExist:
            pass
        
        # Disconnect OAuth from user
        user.disconnect_oauth()
        
        return JsonResponse({
            'message': 'Google account disconnected successfully'
        })
        
    except Exception as e:
        logger.error(f"OAuth disconnection failed: {str(e)}")
        return JsonResponse({
            'error': 'Failed to disconnect Google account'
        }, status=500)

@require_http_methods(["GET"])
def oauth_status(request):
    """Get OAuth connection status"""
    if not request.user.is_authenticated:
        return JsonResponse({
            'connected': False,
            'provider': None
        })
    
    return JsonResponse({
        'connected': request.user.is_oauth_user,
        'provider': request.user.oauth_provider,
        'connected_at': request.user.oauth_connected_at.isoformat() if request.user.oauth_connected_at else None,
        'profile_picture': request.user.profile_picture
    })