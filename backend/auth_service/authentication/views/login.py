"""
Login views for user login, logout, and token management.
"""
import logging
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes
from ..serializers.login import (
    UserLoginSerializer,
    TokenRefreshSerializer,
    LogoutSerializer
)

User = get_user_model()
logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get the client's IP address from the request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_rate_limited(request, action='login', limit=10, window=3600):
    """
    Check if the request is rate limited based on IP address.

    Args:
        request: Django request object
        action: Action being rate limited
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


def increment_rate_limit(request, action='login', window=3600):
    """Increment the rate limit counter for the given action and IP."""
    ip_address = get_client_ip(request)
    cache_key = f"rate_limit_{action}_{ip_address}"

    # Increment counter
    current_attempts = cache.get(cache_key, 0)
    cache.set(cache_key, current_attempts + 1, window)


@extend_schema(
    operation_id='login_user',
    summary='User Login',
    description="""
    Authenticate user and return JWT access and refresh tokens.
    
    **Security Features:**
    - Rate limiting: 10 login attempts per hour per IP
    - Account lockout protection after multiple failed attempts
    - Suspicious login detection and logging
    - Session tracking and device fingerprinting
    - Automatic failed attempt tracking and reset
    
    **Authentication Process:**
    1. Validates email and password credentials
    2. Checks account status (active, email verified, not locked)
    3. Generates JWT access and refresh tokens
    4. Creates session record for tracking
    5. Logs login attempt for security monitoring
    6. Detects and flags suspicious login patterns
    
    **Token Information:**
    - Access Token: Short-lived token for API authentication
    - Refresh Token: Long-lived token for obtaining new access tokens
    - Token Type: Bearer (use in Authorization header)
    - Expires In: Access token lifetime in seconds
    
    **Remember Me Feature:**
    - When enabled, extends refresh token lifetime
    - Provides longer session duration
    - Useful for trusted devices
    
    **Security Monitoring:**
    - Tracks login location, device, and browser
    - Detects unusual login patterns
    - Logs security events for audit
    - Provides warnings for suspicious activity
    """,
    tags=['Login'],
    request=UserLoginSerializer,
    examples=[
        OpenApiExample(
            'Standard Login',
            value={
                'email': 'user@example.com',
                'password': 'SecurePassword123!',
                'remember_me': False
            }
        ),
        OpenApiExample(
            'Remember Me Login',
            value={
                'email': 'user@example.com',
                'password': 'SecurePassword123!',
                'remember_me': True
            }
        )
    ],
    responses={
        200: {
            'description': 'Login successful',
            'examples': {
                'application/json': {
                    'message': 'Login successful',
                    'user': {
                        'id': '123e4567-e89b-12d3-a456-426614174000',
                        'email': 'user@example.com',
                        'first_name': 'John',
                        'last_name': 'Doe',
                        'is_email_verified': True,
                        'last_login': '2024-01-15T10:30:00Z'
                    },
                    'tokens': {
                        'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                        'refresh_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                        'token_type': 'Bearer',
                        'expires_in': 3600,
                        'token_id': 'abc123def456'
                    },
                    'session': {
                        'id': '456e7890-e12b-34d5-a678-901234567890',
                        'device_type': 'desktop',
                        'browser': 'Chrome',
                        'is_new_device': False
                    }
                }
            }
        },
        400: {
            'description': 'Invalid credentials or validation error',
            'examples': {
                'application/json': {
                    'error': 'Invalid credentials or validation failed',
                    'code': 'VALIDATION_ERROR',
                    'details': {
                        'non_field_errors': ['Invalid email or password.']
                    },
                    'attempts_remaining': 9
                }
            }
        },
        429: {
            'description': 'Rate limited',
            'examples': {
                'application/json': {
                    'error': 'Too many login attempts. Please try again later.',
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'reset_time': 1640995200
                }
            }
        }
    }
)
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
    from ..services.session_service import SessionService
    from ..models import LoginHistory
    from ..utils.device_detection import is_suspicious_login, log_security_event
    from rest_framework_simplejwt.tokens import RefreshToken

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

            # Check if user has MFA enabled
            from ..services import MFAService

            if MFAService.user_has_active_mfa(user):
                # Check if device is trusted
                if not MFAService.is_trusted_device(user, request):
                    # MFA required - return partial login response
                    logger.info(f"MFA required for user: {user.email} from IP: {ip_address}")

                    # Generate temporary token for MFA verification
                    refresh = RefreshToken.for_user(user)
                    access_token = refresh.access_token

                    # Set shorter expiration for MFA token (5 minutes)
                    access_token.set_exp(lifetime=timezone.timedelta(minutes=5))

                    return Response({
                        'message': 'MFA verification required',
                        'mfa_required': True,
                        'user': {
                            'id': str(user.id),
                            'email': user.email,
                            'first_name': user.first_name,
                            'last_name': user.last_name,
                        },
                        'mfa_token': str(access_token),
                        'token_type': 'Bearer',
                        'expires_in': 300  # 5 minutes
                    }, status=status.HTTP_200_OK)

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


@extend_schema(
    operation_id='user_logout',
    summary='User Logout',
    description="""
    Logout user and invalidate JWT tokens.
    
    **Logout Options:**
    - **Single Device**: Logout from current device only (default)
    - **All Devices**: Logout from all devices and terminate all sessions
    
    **What happens during logout:**
    1. Current access token is blacklisted
    2. Current refresh token is invalidated
    3. Session record is terminated
    4. Optional: All user sessions are terminated
    
    **Security Features:**
    - Token blacklisting prevents reuse
    - Session cleanup for security
    - Audit trail of logout events
    - Device-specific or global logout options
    
    After logout, the user will need to login again to access protected endpoints.
    """,
    tags=['Login'],
    request=LogoutSerializer,
    examples=[
        OpenApiExample(
            'Single Device Logout',
            value={
                'logout_all_devices': False
            }
        ),
        OpenApiExample(
            'All Devices Logout',
            value={
                'logout_all_devices': True
            }
        )
    ],
    responses={
        200: OpenApiExample(
            'Single Device Logout Success',
            value={
                'message': 'Successfully logged out'
            }
        ),
        200: OpenApiExample(
            'All Devices Logout Success',
            value={
                'message': 'Successfully logged out from all devices (3 sessions)',
                'sessions_terminated': 3
            }
        ),
        401: OpenApiExample(
            'Invalid Token',
            value={
                'error': 'Invalid token',
                'code': 'INVALID_TOKEN'
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """
    Logout user and invalidate tokens.

    Expected payload:
    {
        "logout_all_devices": false  # optional
    }
    """
    from ..services.session_service import SessionService
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


@extend_schema(
    operation_id='refresh_user_token',
    summary='Refresh Access Token',
    description="""
    Refresh access token using a valid refresh token.
    
    **Token Refresh Process:**
    1. Validates the provided refresh token
    2. Generates a new access token
    3. Updates session activity timestamp
    4. Returns new access token with expiration info
    
    **When to use:**
    - When access token expires (typically after 1 hour)
    - To maintain user session without re-login
    - For seamless user experience in long-running applications
    
    **Security Features:**
    - Refresh token validation using SimpleJWT
    - Session activity tracking
    - Automatic token rotation (optional)
    - Secure token generation
    
    **Note:** Refresh tokens have longer lifetime than access tokens but will eventually expire.
    When refresh token expires, user must login again.
    """,
    tags=['Login'],
    request=TokenRefreshSerializer,
    examples=[
        OpenApiExample(
            'Refresh Token Request',
            value={
                'refresh_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTY0MDk5NTIwMCwidXNlcl9pZCI6MX0.example_signature'
            }
        )
    ],
    responses={
        200: OpenApiExample(
            'Token Refresh Success',
            value={
                'message': 'Token refreshed successfully',
                'tokens': {
                    'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
                    'token_type': 'Bearer',
                    'expires_in': 3600
                }
            }
        ),
        401: OpenApiExample(
            'Invalid Refresh Token',
            value={
                'error': 'Invalid or expired refresh token',
                'code': 'TOKEN_REFRESH_FAILED'
            }
        )
    }
)
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
    from ..services.session_service import SessionService
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