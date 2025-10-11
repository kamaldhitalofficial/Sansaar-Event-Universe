from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.shortcuts import render
from django.utils.html import strip_tags
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from datetime import timedelta
import logging

from .serializers import (
    UserRegistrationSerializer, 
    UserProfileSerializer, 
    EmailVerificationSerializer,
    ResendVerificationSerializer
)

User = get_user_model()
logger = logging.getLogger(__name__)


class UserRegistrationView(generics.CreateAPIView):
    """
    Class-based view for user registration.
    
    POST /api/auth/register/
    Creates a new user account and sends email verification.
    """
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]
    
    def create(self, request, *args, **kwargs):
        """
        Handle user registration with comprehensive error handling.
        Uses database transaction to ensure user is only created if email verification can be sent.
        """
        try:
            # Validate the incoming data
            serializer = self.get_serializer(data=request.data)
            
            if not serializer.is_valid():
                return Response({
                    'success': False,
                    'message': 'Registration failed due to validation errors.',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Use transaction to ensure atomicity
            with transaction.atomic():
                # Create the user
                user = serializer.save()
                
                # Send verification email
                verification_sent = send_verification_email_helper(user)
                
                # If email verification failed to send, raise exception to rollback transaction
                if not verification_sent:
                    logger.warning(f"Email verification failed for {user.email}, rolling back user creation")
                    raise Exception("Failed to send verification email")
                
                # Prepare response data
                user_data = UserProfileSerializer(user).data
                
                return Response({
                    'success': True,
                    'message': 'User registered successfully. Please check your email for verification instructions.',
                    'data': {
                        'user': user_data,
                        'email_verification_sent': verification_sent
                    }
                }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            
            # Determine appropriate error message based on the exception
            if "Failed to send verification email" in str(e):
                return Response({
                    'success': False,
                    'message': 'Registration failed. Unable to send verification email. Please try again later.',
                    'errors': {'email': ['Email service is currently unavailable. Please try again later.']}
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
            else:
                return Response({
                    'success': False,
                    'message': 'An error occurred during registration. Please try again.',
                    'errors': {'general': [str(e)]}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def verify_email(request):
    """
    Function-based view for email verification.
    
    GET /api/auth/verify-email/?token=<token> (for email links)
    POST /api/auth/verify-email/ (for API calls with token in body)
    Verifies a user's email using the token sent via email.
    """
    try:
        # Get token from query params (GET) or request body (POST)
        if request.method == 'GET':
            token = request.GET.get('token')
            if not token:
                # Render error page for email link clicks
                context = {
                    'error_message': 'Token parameter is required.',
                    'site_name': 'Sansaar Event Universe',
                    'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
                }
                return render(request, 'authentications/verification_error.html', context)
        else:  # POST method
            # Validate the incoming data
            serializer = EmailVerificationSerializer(data=request.data)
            
            if not serializer.is_valid():
                return Response({
                    'success': False,
                    'message': 'Invalid verification data.',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            token = serializer.validated_data['token']
        
        # Find user with the token
        try:
            user = User.objects.get(
                email_verification_token=token,
                is_email_verified=False
            )
        except User.DoesNotExist:
            if request.method == 'GET':
                # Render error page for email link clicks
                context = {
                    'error_message': 'Invalid or expired verification token.',
                    'site_name': 'Sansaar Event Universe',
                    'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
                }
                return render(request, 'authentications/verification_error.html', context)
            else:
                return Response({
                    'success': False,
                    'message': 'Invalid or expired verification token.',
                    'errors': {'token': ['Token not found or already used.']}
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if token has expired
        if user.email_verification_sent_at:
            expire_time = user.email_verification_sent_at + timedelta(
                hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS
            )
            if timezone.now() > expire_time:
                if request.method == 'GET':
                    # Render error page for email link clicks
                    context = {
                        'error_message': 'Verification token has expired. Please request a new one.',
                        'site_name': 'Sansaar Event Universe',
                        'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
                    }
                    return render(request, 'authentications/verification_error.html', context)
                else:
                    return Response({
                        'success': False,
                        'message': 'Verification token has expired. Please request a new one.',
                        'errors': {'token': ['Token has expired.']}
                    }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify the email
        user.verify_email()
        
        logger.info(f"Email verified for user {user.email}")
        
        # Handle response based on request method
        if request.method == 'GET':
            # Render HTML page for email link clicks
            context = {
                'user': user,
                'site_name': 'Sansaar Event Universe',
            }
            return render(request, 'authentications/verification_success.html', context)
        else:
            # Return JSON response for API calls
            return Response({
                'success': True,
                'message': 'Email verified successfully. Your account is now active.',
                'data': {
                    'user': UserProfileSerializer(user).data
                }
            }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Email verification error: {str(e)}")
        return Response({
            'success': False,
            'message': 'An error occurred during email verification. Please try again.',
            'errors': {'general': [str(e)]}
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def resend_verification_email(request):
    """
    Function-based view for resending email verification.
    
    GET /api/auth/resend-verification/ - Show resend form (HTML)
    POST /api/auth/resend-verification/ - Process resend request (JSON/HTML)
    """
    if request.method == 'GET':
        # Show the resend verification form
        context = {
            'site_name': 'Sansaar Event Universe',
            'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
        }
        return render(request, 'authentications/resend_verification.html', context)
    
    # Handle POST request
    try:
        # Check if it's a JSON request (API) or form request (HTML)
        if request.content_type == 'application/json':
            # Handle JSON API request
            serializer = ResendVerificationSerializer(data=request.data)
            
            if not serializer.is_valid():
                return Response({
                    'success': False,
                    'message': 'Invalid email data.',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            email = serializer.validated_data['email']
        else:
            # Handle HTML form request
            email = request.POST.get('email', '').strip().lower()
            if not email:
                context = {
                    'site_name': 'Sansaar Event Universe',
                    'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
                    'message': 'Email address is required.',
                    'success': False,
                    'email': email,
                }
                return render(request, 'authentications/resend_verification.html', context)
        
        # Get the user
        try:
            user = User.objects.get(email=email, is_email_verified=False)
        except User.DoesNotExist:
            error_message = 'No unverified account found with this email address.'
            
            if request.content_type == 'application/json':
                return Response({
                    'success': False,
                    'message': error_message,
                    'errors': {'email': ['Account not found or already verified.']}
                }, status=status.HTTP_404_NOT_FOUND)
            else:
                context = {
                    'site_name': 'Sansaar Event Universe',
                    'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
                    'message': error_message,
                    'success': False,
                    'email': email,
                }
                return render(request, 'authentications/resend_verification.html', context)
        
        # Generate new verification token and update timestamp
        user.generate_verification_token()
        user.save()
        
        # Send verification email using the helper function
        verification_sent = send_verification_email_helper(user)
        
        if not verification_sent:
            error_message = 'Failed to send verification email. Please try again later.'
            
            if request.content_type == 'application/json':
                return Response({
                    'success': False,
                    'message': error_message,
                    'errors': {'email': ['Email service is currently unavailable.']}
                }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
            else:
                context = {
                    'site_name': 'Sansaar Event Universe',
                    'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
                    'message': error_message,
                    'success': False,
                    'email': email,
                }
                return render(request, 'authentications/resend_verification.html', context)
        
        logger.info(f"Verification email resent successfully to {user.email}")
        
        success_message = 'Verification email sent successfully! Please check your inbox.'
        
        if request.content_type == 'application/json':
            return Response({
                'success': True,
                'message': success_message,
                'data': {
                    'email_sent': True,
                    'email': user.email
                }
            }, status=status.HTTP_200_OK)
        else:
            context = {
                'site_name': 'Sansaar Event Universe',
                'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
                'message': success_message,
                'success': True,
                'email': email,
            }
            return render(request, 'authentications/resend_verification.html', context)
        
    except Exception as e:
        logger.error(f"Resend verification error: {str(e)}")
        error_message = 'An error occurred while resending verification email. Please try again.'
        
        if request.content_type == 'application/json':
            return Response({
                'success': False,
                'message': error_message,
                'errors': {'general': [str(e)]}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            context = {
                'site_name': 'Sansaar Event Universe',
                'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
                'message': error_message,
                'success': False,
                'email': request.POST.get('email', ''),
            }
            return render(request, 'authentications/resend_verification.html', context)


def send_verification_email_helper(user):
    """
    Helper function to send verification email.
    Returns True if email was sent successfully, False otherwise.
    """
    try:
        # Check if email configuration is properly set
        if not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD:
            logger.error("Email configuration is incomplete. EMAIL_HOST_USER or EMAIL_HOST_PASSWORD not set.")
            return False
        
        # Generate verification URL that users can click in email
        verification_url = f"http://127.0.0.1:8000/api/auth/verify-email/?token={user.email_verification_token}"
        
        # Email context
        context = {
            'user': user,
            'verification_url': verification_url,
            'site_name': 'Sansaar Event Universe',
            'expire_hours': settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS,
        }
        
        # Render email templates
        html_message = render_to_string('authentications/verification_email.html', context)
        plain_message = render_to_string('authentications/verification_email.txt', context)
        
        # Send email
        send_mail(
            subject='Verify Your Email Address - Sansaar Event Universe',
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
        
        logger.info(f"Verification email sent successfully to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {str(e)}")
        return False
