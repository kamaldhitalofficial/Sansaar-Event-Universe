"""
Session management views for user session tracking and management.
"""
import logging
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

logger = logging.getLogger(__name__)


@extend_schema(
    operation_id='get_user_sessions',
    summary='Get Active Sessions',
    description="""
    Get all active sessions for the current user across all devices.
    
    **Session Information Includes:**
    - Session ID and creation time
    - Device type (desktop, mobile, tablet)
    - Browser and operating system
    - IP address and location (if available)
    - Last activity timestamp
    - Current session indicator
    
    **Security Features:**
    - Only shows sessions for the authenticated user
    - Identifies current session for context
    - Provides device fingerprinting information
    - Shows session activity patterns
    
    **Use Cases:**
    - Security monitoring and review
    - Identifying unauthorized access
    - Managing active sessions
    - Device and location tracking
    - Session cleanup and management
    
    **Privacy:**
    - Only user's own sessions are visible
    - Sensitive information is filtered
    - Location data is approximate
    - IP addresses may be masked for privacy
    
    This endpoint helps users monitor their account security and manage active sessions.
    """,
    tags=['Sessions'],
    responses={
        200: OpenApiExample(
            'Active Sessions',
            value={
                'total_sessions': 3,
                'active_sessions': 2,
                'sessions': [
                    {
                        'id': '123e4567-e89b-12d3-a456-426614174000',
                        'token_id': 'abc123def456',
                        'device_type': 'desktop',
                        'browser': 'Chrome 120.0',
                        'os': 'macOS',
                        'ip_address': '192.168.1.100',
                        'location': 'San Francisco, CA',
                        'created_at': '2024-01-15T10:30:00Z',
                        'last_activity': '2024-01-15T14:45:00Z',
                        'is_current': True,
                        'is_active': True
                    },
                    {
                        'id': '456e7890-e12b-34d5-a678-901234567890',
                        'token_id': 'def456ghi789',
                        'device_type': 'mobile',
                        'browser': 'Safari Mobile',
                        'os': 'iOS 17.2',
                        'ip_address': '10.0.0.50',
                        'location': 'New York, NY',
                        'created_at': '2024-01-14T08:15:00Z',
                        'last_activity': '2024-01-15T12:20:00Z',
                        'is_current': False,
                        'is_active': True
                    }
                ]
            }
        )
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_sessions(request):
    """
    Get active sessions for the current user.
    """
    from ..services.session_service import SessionService
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


@extend_schema(
    operation_id='terminate_session',
    summary='Terminate Session',
    description="""
    Terminate a specific session by token ID.
    
    **Termination Process:**
    1. Validates the token ID belongs to the current user
    2. Blacklists the associated JWT tokens
    3. Marks the session as terminated
    4. Logs the termination event
    5. Prevents further use of the session
    
    **Security Features:**
    - User can only terminate their own sessions
    - Immediate token invalidation
    - Audit trail of session terminations
    - Prevents unauthorized session access
    
    **Use Cases:**
    - Logging out from a specific device
    - Security response to suspicious activity
    - Managing sessions after device loss/theft
    - Cleaning up old or unused sessions
    
    **Important Notes:**
    - Terminated sessions cannot be reactivated
    - User will need to login again on that device
    - Current session can be terminated (will require re-login)
    - Session termination is immediate and irreversible
    
    This is useful for security management and controlling access across devices.
    """,
    tags=['Sessions'],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'token_id': {
                    'type': 'string',
                    'description': 'Token ID of the session to terminate'
                }
            },
            'required': ['token_id']
        }
    },
    responses={
        200: OpenApiExample(
            'Session Terminated',
            value={
                'message': 'Session terminated successfully'
            }
        ),
        400: OpenApiExample(
            'Missing Token ID',
            value={
                'error': 'Token ID is required',
                'code': 'TOKEN_ID_REQUIRED'
            }
        ),
        404: OpenApiExample(
            'Session Not Found',
            value={
                'error': 'Session not found or access denied',
                'code': 'SESSION_NOT_FOUND'
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def terminate_session(request):
    """
    Terminate a specific session.

    Expected payload:
    {
        "token_id": "session_token_id_to_terminate"
    }
    """
    from ..services.session_service import SessionService

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