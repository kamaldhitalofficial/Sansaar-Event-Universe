"""
Registration views for user registration and email verification.
"""
import logging
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes
from ..serializers.registration import UserRegistrationSerializer

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


@extend_schema(
    operation_id='register_user',
    summary='Register New User',
    description="""
    Register a new user account with comprehensive validation and security features.
    
    **Security Features:**
    - Rate limiting: 5 registration attempts per hour per IP
    - Email validation and disposable email detection
    - Strong password requirements with entropy checking
    - Profanity and fake name pattern detection
    - Automatic email verification sending
    
    **Password Requirements:**
    - Minimum 8 characters, maximum 128 characters
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one number (0-9)
    - At least one special character (!@#$%^&*(),.?":{}|<>)
    - Must not contain common patterns or weak passwords
    - Minimum entropy threshold of 50 bits
    
    **Email Validation:**
    - Valid email format required
    - Disposable email domains are blocked
    - Suspicious domain patterns are detected
    - Email uniqueness is enforced
    
    **After Registration:**
    - User account is created but inactive until email verification
    - Verification email is automatically sent
    - User profile is automatically created
    - Registration event is logged for security
    
    Rate limited to prevent abuse and spam registrations.
    """,
    tags=['Register'],
    request=UserRegistrationSerializer,
    examples=[
        OpenApiExample(
            'Complete Registration',
            value={
                'email': 'john.doe@example.com',
                'password': 'SecurePassword123!',
                'password_confirm': 'SecurePassword123!',
                'first_name': 'John',
                'last_name': 'Doe'
            }
        ),
        OpenApiExample(
            'Minimal Registration',
            value={
                'email': 'user@example.com',
                'password': 'MySecurePass456!',
                'password_confirm': 'MySecurePass456!'
            }
        )
    ],
    responses={
        201: OpenApiExample(
            'Registration Successful',
            value={
                'message': 'Registration successful. Please check your email to verify your account.',
                'user': {
                    'id': '123e4567-e89b-12d3-a456-426614174000',
                    'email': 'john.doe@example.com',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'is_email_verified': False,
                    'date_joined': '2024-01-15T10:30:00Z'
                },
                'verification_email_sent': True
            }
        ),
        400: OpenApiExample(
            'Validation Error',
            value={
                'error': 'Validation failed',
                'code': 'VALIDATION_ERROR',
                'details': {
                    'email': ['A user with this email already exists.'],
                    'password': ['Password must contain at least one uppercase letter.']
                },
                'attempts_remaining': 4
            }
        ),
        429: OpenApiExample(
            'Rate Limited',
            value={
                'error': 'Too many registration attempts. Please try again later.',
                'code': 'RATE_LIMIT_EXCEEDED',
                'reset_time': 1640995200
            }
        )
    }
)
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
            # Create user and send verification email
            user = serializer.save(request=request)

            # Get verification info from user attributes set by serializer
            verification_sent = getattr(user, '_verification_sent', False)
            email_message = getattr(user, '_verification_message', '')

            # Log successful registration
            logger.info(f"User registration successful: {user.email} from IP: {get_client_ip(request)}")

            response_data = {
                'message': 'Registration successful. Please check your email to verify your account.',
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_email_verified': user.is_email_verified,
                    'date_joined': user.date_joined.isoformat()
                },
                'verification_email_sent': verification_sent
            }

            # Add email status message if verification email failed
            if not verification_sent:
                response_data['email_warning'] = email_message

            return Response(response_data, status=status.HTTP_201_CREATED)

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


@extend_schema(
    operation_id='registration_status',
    summary='Check Registration Rate Limits',
    description="""
    Check current registration rate limit status for the requesting IP address.
    
    **Rate Limit Information:**
    - Current limit: 5 registration attempts per hour per IP
    - Remaining attempts before rate limiting
    - Reset time when limits will be cleared
    - Time window for rate limiting
    
    **Use Cases:**
    - Frontend rate limit display
    - User experience improvement
    - Registration form validation
    - API client rate limit handling
    
    **Security Features:**
    - IP-based rate limiting
    - Transparent limit communication
    - Abuse prevention
    - Fair usage enforcement
    
    This endpoint helps clients understand and respect rate limits.
    """,
    tags=['Register'],
    responses={
        200: OpenApiExample(
            'Rate Limit Status',
            value={
                'rate_limited': False,
                'attempts_remaining': 3,
                'reset_time': None,
                'limit': 5,
                'window': 3600
            }
        )
    }
)
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


@extend_schema(
    operation_id='check_email_availability',
    summary='Check Email Availability',
    description="""
    Check if an email address is available for registration.
    
    **Validation Process:**
    1. Validates email format using Django's EmailValidator
    2. Checks if email is already registered in the system
    3. Returns availability status
    
    **Use Cases:**
    - Real-time email validation during registration form filling
    - Pre-registration email checking
    - User experience improvement with instant feedback
    
    **Security Features:**
    - Email format validation
    - No sensitive information disclosure
    - Rate limiting protection
    
    This endpoint helps users know immediately if their desired email is available
    before completing the full registration process.
    """,
    tags=['Email'],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {
                    'type': 'string',
                    'format': 'email',
                    'description': 'Email address to check for availability'
                }
            },
            'required': ['email']
        }
    },
    responses={
        200: {
            'description': 'Email availability check result',
            'examples': {
                'application/json': {
                    'email': 'newuser@example.com',
                    'available': True,
                    'message': 'Email is available'
                }
            }
        },
        400: {
            'description': 'Invalid email format',
            'examples': {
                'application/json': {
                    'error': 'Invalid email format',
                    'code': 'INVALID_EMAIL_FORMAT'
                }
            }
        }
    }
)
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
    from ..services.registration import RegistrationService
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


@extend_schema(
    operation_id='verify_email',
    summary='Verify Email Address',
    description="""
    Verify user email address using verification token sent via email.
    
    **Verification Process:**
    1. Validates the verification token
    2. Checks token expiration (typically 24-48 hours)
    3. Activates the user account
    4. Marks email as verified
    5. Enables full account access
    
    **Token Security:**
    - UUID-based tokens for security
    - Time-limited validity
    - Single-use tokens
    - Secure token generation
    
    **After Verification:**
    - User account becomes active
    - User can login normally
    - Email verification status is updated
    - Welcome processes can be triggered
    
    **Error Handling:**
    - Expired token detection
    - Invalid token handling
    - Already verified account handling
    - Clear error messages for users
    
    This endpoint is typically accessed via email links sent to users during registration.
    """,
    tags=['Email'],
    parameters=[
        OpenApiParameter(
            name='token',
            type=OpenApiTypes.UUID,
            location=OpenApiParameter.PATH,
            description='Email verification token (UUID format)',
            required=True
        )
    ],
    responses={
        200: OpenApiExample(
            'Verification Successful',
            value={
                'message': 'Email verified successfully. Your account is now active.',
                'user': {
                    'id': '123e4567-e89b-12d3-a456-426614174000',
                    'email': 'user@example.com',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'is_email_verified': True,
                    'is_active': True
                }
            }
        ),
        400: OpenApiExample(
            'Invalid Token',
            value={
                'error': 'Invalid or expired verification token',
                'code': 'VERIFICATION_FAILED'
            }
        ),
        400: OpenApiExample(
            'Already Verified',
            value={
                'error': 'Email is already verified',
                'code': 'ALREADY_VERIFIED'
            }
        )
    }
)
@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    """
    Verify user email using verification token.

    URL: /auth/verify-email/<token>/
    """
    from ..services.email_service import EmailService

    try:
        # Verify email using token
        success, user, message = EmailService.verify_email(token)

        if success:
            logger.info(f"Email verification successful for user: {user.email} from IP: {get_client_ip(request)}")

            return Response({
                'message': message,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_email_verified': user.is_email_verified,
                    'is_active': user.is_active
                }
            }, status=status.HTTP_200_OK)
        else:
            logger.warning(f"Email verification failed for token: {token} from IP: {get_client_ip(request)}")

            return Response({
                'error': message,
                'code': 'VERIFICATION_FAILED'
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Email verification error for token {token}: {str(e)}")
        return Response({
            'error': 'Verification failed. Please try again.',
            'code': 'VERIFICATION_ERROR'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='resend_verification_email',
    summary='Resend Verification Email',
    description="""
    Resend email verification for a registered user who hasn't verified their email yet.
    
    **Verification Process:**
    1. Validates the provided email address
    2. Checks if user exists and needs verification
    3. Generates new verification token
    4. Sends verification email with new token
    5. Updates verification attempt tracking
    
    **Rate Limiting:**
    - 3 resend attempts per hour per IP
    - Prevents email spam and abuse
    - Reasonable limits for legitimate users
    
    **Security Features:**
    - Email validation and existence checking
    - Rate limiting protection
    - Secure token generation
    - Audit trail of resend attempts
    
    **Use Cases:**
    - User didn't receive original verification email
    - Verification email expired
    - Email delivery issues
    - User experience improvement
    
    **Error Handling:**
    - Already verified accounts
    - Non-existent email addresses
    - Rate limit exceeded
    - Email delivery failures
    
    This endpoint helps users who have registration issues with email verification.
    """,
    tags=['Email'],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'email': {
                    'type': 'string',
                    'format': 'email',
                    'description': 'Email address to resend verification to'
                }
            },
            'required': ['email']
        }
    },
    responses={
        200: {
            'description': 'Verification email sent successfully',
            'examples': {
                'application/json': {
                    'message': 'Verification email sent successfully. Please check your inbox.',
                    'email': 'user@example.com'
                }
            }
        },
        400: {
            'description': 'Email already verified or rate limited',
            'examples': {
                'application/json': {
                    'error': 'Too many resend attempts. Please try again later.',
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'reset_time': 1640995200
                }
            }
        }
    }
)
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
    from ..services.registration import RegistrationService

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
        }, status=status.HTTP_400_BAD_REQUEST)

    email = request.data.get('email', '').strip().lower()

    if not email:
        increment_rate_limit(request, 'resend_verification')
        return Response({
            'error': 'Email address is required',
            'code': 'EMAIL_REQUIRED'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Attempt to resend verification email
    from ..services.email_service import EmailService
    success, message = EmailService.resend_verification_email(email)

    if not success:
        # Only increment rate limit if it's not already rate limited
        if "recently sent" not in message.lower():
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