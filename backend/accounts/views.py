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

User = get_user_model()


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