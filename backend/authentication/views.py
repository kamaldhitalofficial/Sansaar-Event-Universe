"""
Authentication views for user registration, login, and account management.
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .serializers import UserRegistrationSerializer
import logging
import hashlib

User = get_user_model()
logger = logging.getLogger(__name__)


def get_client_ip(request):
    """
    Get the client's IP address from the request.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_rate_limited(request, action='registration', limit=5, window=3600):
    """
    Check if the request is rate limited based on IP address.

    Args:
        request: Django request object
        action: Action being rate limited (e.g., 'registration', 'login')
        limit: Maximum number of attempts allowed
        window: Time window in seconds

    Returns:
        tuple: (is_limited, attempts_remaining, reset_time)
    """
    ip_address = get_client_ip(request)
    cache_key = f"rate_limit_{action}_{ip_address}"

    # Get current attempts
    attempts = cache.get(cache_key, 0)

    if attempts >= limit:
        # Get TTL for reset time
        ttl = cache.ttl(cache_key)
        reset_time = timezone.now().timestamp() + ttl if ttl > 0 else None
        return True, 0, reset_time

    return False, limit - attempts, None


def increment_rate_limit(request, action='registration', window=3600):
    """
    Increment the rate limit counter for the given action and IP.
    """
    ip_address = get_client_ip(request)
    cache_key = f"rate_limit_{action}_{ip_address}"

    # Increment counter
    current_attempts = cache.get(cache_key, 0)
    cache.set(cache_key, current_attempts + 1, window)


@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    """
    Register a new user with comprehensive validation and rate limiting.

    Expected payload:
    {
        "email": "user@example.com",
        "password": "SecurePassword123!",
        "password_confirm": "SecurePassword123!",
        "first_name": "John",  # optional
        "last_name": "Doe"     # optional
    }
    """
    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'registration', limit=5, window=3600  # 5 attempts per hour
    )

    if is_limited:
        logger.warning(f"Registration rate limit exceeded for IP: {get_client_ip(request)}")
        return Response({
            'error': 'Too many registration attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    # Validate and create user
    serializer = UserRegistrationSerializer(data=request.data)

    if serializer.is_valid():
        try:
            # Create user
            user = serializer.save()

            # Log successful registration
            logger.info(f"User registration successful: {user.email} from IP: {get_client_ip(request)}")

            # TODO: Send email verification (will be implemented in task 6)
            # For now, we'll just return success response

            return Response({
                'message': 'Registration successful. Please check your email to verify your account.',
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_email_verified': user.is_email_verified,
                    'date_joined': user.date_joined.isoformat()
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            # Increment rate limit on any error to prevent abuse
            increment_rate_limit(request, 'registration')

            logger.error(f"User registration failed: {str(e)} for IP: {get_client_ip(request)}")
            return Response({
                'error': 'Registration failed. Please try again.',
                'code': 'REGISTRATION_FAILED'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    else:
        # Increment rate limit on validation errors to prevent spam
        increment_rate_limit(request, 'registration')

        # Log validation errors
        logger.warning(f"Registration validation failed for IP: {get_client_ip(request)}, errors: {serializer.errors}")

        return Response({
            'error': 'Validation failed',
            'code': 'VALIDATION_ERROR',
            'details': serializer.errors,
            'attempts_remaining': attempts_remaining - 1
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
def registration_status(request):
    """
    Check registration rate limit status for the current IP.
    """
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'registration', limit=5, window=3600
    )

    return Response({
        'rate_limited': is_limited,
        'attempts_remaining': attempts_remaining,
        'reset_time': reset_time,
        'limit': 5,
        'window': 3600
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def check_email_availability(request):
    """
    Check if an email address is available for registration.

    Expected payload:
    {
        "email": "user@example.com"
    }
    """
    from .services.registration import RegistrationService
    from django.core.validators import EmailValidator
    from django.core.exceptions import ValidationError

    email = request.data.get('email', '').strip().lower()

    if not email:
        return Response({
            'error': 'Email address is required',
            'code': 'EMAIL_REQUIRED'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Validate email format
    validator = EmailValidator()
    try:
        validator(email)
    except ValidationError:
        return Response({
            'error': 'Invalid email format',
            'code': 'INVALID_EMAIL_FORMAT'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Check availability
    is_available = RegistrationService.check_email_availability(email)

    return Response({
        'email': email,
        'available': is_available,
        'message': 'Email is available' if is_available else 'Email is already registered'
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification_email(request):
    """
    Resend verification email for a registered user.

    Expected payload:
    {
        "email": "user@example.com"
    }
    """
    from .services.registration import RegistrationService

    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'resend_verification', limit=3, window=3600  # 3 attempts per hour
    )

    if is_limited:
        logger.warning(f"Resend verification rate limit exceeded for IP: {get_client_ip(request)}")
        return Response({
            'error': 'Too many resend attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    email = request.data.get('email', '').strip().lower()

    if not email:
        increment_rate_limit(request, 'resend_verification')
        return Response({
            'error': 'Email address is required',
            'code': 'EMAIL_REQUIRED'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Attempt to resend verification email
    success, message = RegistrationService.resend_verification_email(email)

    if not success:
        increment_rate_limit(request, 'resend_verification')
        return Response({
            'error': message,
            'code': 'RESEND_FAILED'
        }, status=status.HTTP_400_BAD_REQUEST)

    logger.info(f"Verification email resend requested for: {email} from IP: {get_client_ip(request)}")

    return Response({
        'message': message,
        'email': email
    })
