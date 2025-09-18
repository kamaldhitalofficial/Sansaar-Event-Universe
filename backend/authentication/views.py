"""
Authentication views for user registration, login, and account management.
"""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
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
            # Create user and send verification email
            user, verification_sent, email_message = serializer.save(request=request)

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


@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    """
    Verify user email using verification token.

    URL: /auth/verify-email/<token>/
    """
    from .services.email_service import EmailService

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
        }, status=status.HTTP_400_BAD_REQUEST)

    email = request.data.get('email', '').strip().lower()

    if not email:
        increment_rate_limit(request, 'resend_verification')
        return Response({
            'error': 'Email address is required',
            'code': 'EMAIL_REQUIRED'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Attempt to resend verification email
    from .services.email_service import EmailService
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


@api_view(['POST'])
@permission_classes([AllowAny])
def login_user(request):
    """
    Authenticate user and return JWT tokens.

    Expected payload:
    {
        "email": "user@example.com",
        "password": "SecurePassword123!",
        "remember_me": false  # optional
    }
    """
    from .serializers import UserLoginSerializer
    from .services.session_service import SessionService
    from .models import LoginHistory
    from .utils.device_detection import is_suspicious_login, log_security_event
    from rest_framework_simplejwt.tokens import RefreshToken
    from datetime import timedelta

    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'login', limit=10, window=3600  # 10 attempts per hour
    )

    if is_limited:
        logger.warning(f"Login rate limit exceeded for IP: {get_client_ip(request)}")
        return Response({
            'error': 'Too many login attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    serializer = UserLoginSerializer(data=request.data)

    if serializer.is_valid():
        try:
            user = serializer.validated_data['user']
            remember_me = serializer.validated_data.get('remember_me', False)

            # Check for suspicious login patterns
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            is_suspicious, suspicious_reasons = is_suspicious_login(user, ip_address, user_agent)

            # Generate JWT tokens using SimpleJWT
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token

            token_data = {
                'access_token': str(access_token),
                'refresh_token': str(refresh),
                'token_type': 'Bearer',
                'expires_in': settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
                'token_id': str(refresh.jti)
            }

            # Calculate session expiration
            if remember_me:
                expires_at = timezone.now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
            else:
                expires_at = timezone.now() + (settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'] * 2)

            # Create session record
            session = SessionService.create_session(
                user=user,
                request=request,
                token_id=token_data['token_id'],
                expires_at=expires_at
            )

            # Create login history entry
            login_entry = LoginHistory.create_login_attempt(
                user=user,
                request=request,
                success=True,
                token_id=token_data['token_id']
            )

            # Mark as suspicious if detected
            if is_suspicious:
                login_entry.is_suspicious = True
                login_entry.save(update_fields=['is_suspicious'])

                # Log security event
                log_security_event(
                    user=user,
                    event_type='suspicious_login',
                    details=f"Suspicious login detected: {', '.join(suspicious_reasons)}",
                    ip_address=ip_address
                )

            logger.info(f"Successful login for user: {user.email} from IP: {ip_address}")

            # Prepare response
            response_data = {
                'message': 'Login successful',
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_email_verified': user.is_email_verified,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                },
                'tokens': token_data,
                'session': {
                    'id': str(session.id),
                    'device_type': session.device_type,
                    'browser': session.browser,
                    'is_new_device': login_entry.is_new_device
                }
            }

            # Add warning for suspicious login
            if is_suspicious:
                response_data['security_warning'] = {
                    'message': 'Unusual login activity detected. If this was not you, please secure your account.',
                    'reasons': suspicious_reasons
                }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            # Increment rate limit on any error
            increment_rate_limit(request, 'login')

            logger.error(f"Login failed with error: {str(e)} for IP: {get_client_ip(request)}")
            return Response({
                'error': 'Login failed. Please try again.',
                'code': 'LOGIN_FAILED'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    else:
        # Increment rate limit on validation errors
        increment_rate_limit(request, 'login')

        # Create failed login history if we can identify the user
        email = request.data.get('email', '').lower().strip()
        if email:
            try:
                user = User.objects.get(email=email)
                LoginHistory.create_login_attempt(
                    user=user,
                    request=request,
                    success=False,
                    failure_reason='invalid_credentials'
                )
            except User.DoesNotExist:
                pass  # Don't create history for non-existent users

        logger.warning(f"Login validation failed for IP: {get_client_ip(request)}, errors: {serializer.errors}")

        return Response({
            'error': 'Invalid credentials or validation failed',
            'code': 'VALIDATION_ERROR',
            'details': serializer.errors,
            'attempts_remaining': attempts_remaining - 1
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def logout_user(request):
    """
    Logout user and invalidate tokens.

    Expected payload:
    {
        "logout_all_devices": false  # optional
    }
    """
    from .serializers import LogoutSerializer
    from .services.session_service import SessionService
    from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
    from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

    serializer = LogoutSerializer(data=request.data)

    if serializer.is_valid():
        logout_all_devices = serializer.validated_data.get('logout_all_devices', False)

        # Get current token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return Response({
                'error': 'Authorization header required',
                'code': 'AUTH_REQUIRED'
            }, status=status.HTTP_401_UNAUTHORIZED)

        token = auth_header.split(' ')[1]

        # Get token info using SimpleJWT
        try:
            untyped_token = UntypedToken(token)
            token_id = str(untyped_token.jti)
            user_id = str(untyped_token['user_id'])
        except (InvalidToken, TokenError):
            return Response({
                'error': 'Invalid token',
                'code': 'INVALID_TOKEN'
            }, status=status.HTTP_401_UNAUTHORIZED)

        if logout_all_devices:
            # Terminate all user sessions
            terminated_count = SessionService.terminate_all_user_sessions(
                user_id,
                reason='logout_all_devices'
            )

            # Blacklist current token
            try:
                refresh_token = RefreshToken(token)
                refresh_token.blacklist()
            except (InvalidToken, TokenError):
                pass  # Token might already be invalid

            logger.info(f"User {user_id} logged out from all devices ({terminated_count} sessions)")

            return Response({
                'message': f'Successfully logged out from all devices ({terminated_count} sessions)',
                'sessions_terminated': terminated_count
            })
        else:
            # Blacklist current token
            try:
                refresh_token = RefreshToken(token)
                refresh_token.blacklist()
            except (InvalidToken, TokenError):
                pass  # Token might already be invalid

            # Terminate current session
            SessionService.terminate_session(token_id, reason='manual_logout')

            logger.info(f"User {user_id} logged out from current device")

            return Response({
                'message': 'Successfully logged out'
            })

    else:
        return Response({
            'error': 'Invalid logout request',
            'code': 'VALIDATION_ERROR',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request):
    """
    Refresh access token using refresh token.

    Expected payload:
    {
        "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
    }
    """
    from .serializers import TokenRefreshSerializer
    from .services.session_service import SessionService
    from rest_framework_simplejwt.tokens import RefreshToken
    from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

    serializer = TokenRefreshSerializer(data=request.data)

    if serializer.is_valid():
        refresh_token = serializer.validated_data['refresh_token']

        # Refresh the access token using SimpleJWT
        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = refresh.access_token

            result = {
                'access_token': str(new_access_token),
                'token_type': 'Bearer',
                'expires_in': settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()
            }

            # Update session activity
            token_id = str(refresh.jti)
            SessionService.update_session_activity(token_id)

            logger.info(f"Token refreshed for user")

            return Response({
                'message': 'Token refreshed successfully',
                'tokens': result
            })

        except (InvalidToken, TokenError) as e:
            return Response({
                'error': 'Invalid or expired refresh token',
                'code': 'TOKEN_REFRESH_FAILED'
            }, status=status.HTTP_401_UNAUTHORIZED)

    else:
        return Response({
            'error': 'Invalid refresh token request',
            'code': 'VALIDATION_ERROR',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_user_sessions(request):
    """
    Get active sessions for the current user.
    """
    from .services.session_service import SessionService
    from rest_framework_simplejwt.tokens import UntypedToken
    from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

    user_id = str(request.user.id)

    # Get current token to identify current session
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    current_token_id = None

    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            untyped_token = UntypedToken(token)
            current_token_id = str(untyped_token.jti)
        except (InvalidToken, TokenError):
            pass

    # Get session summary
    summary = SessionService.get_session_summary(user_id)

    # Mark current session
    for session in summary['sessions']:
        if session['token_id'] == current_token_id:
            session['is_current'] = True

    return Response(summary)


@api_view(['POST'])
def terminate_session(request):
    """
    Terminate a specific session.

    Expected payload:
    {
        "token_id": "session_token_id_to_terminate"
    }
    """
    from .services.session_service import SessionService

    token_id = request.data.get('token_id')

    if not token_id:
        return Response({
            'error': 'Token ID is required',
            'code': 'TOKEN_ID_REQUIRED'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Verify the session belongs to the current user
    session = SessionService.get_session_by_token_id(token_id)
    if not session or session.user.id != request.user.id:
        return Response({
            'error': 'Session not found or access denied',
            'code': 'SESSION_NOT_FOUND'
        }, status=status.HTTP_404_NOT_FOUND)

    # Terminate the session
    success = SessionService.terminate_session(token_id, reason='manual_termination')

    if success:
        return Response({
            'message': 'Session terminated successfully'
        })
    else:
        return Response({
            'error': 'Failed to terminate session',
            'code': 'TERMINATION_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
