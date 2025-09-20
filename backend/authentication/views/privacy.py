"""
Privacy views for privacy settings and consent management API endpoints.
"""
import logging
from django.core.cache import cache
from django.utils import timezone
from django.http import HttpResponse
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from ..serializers.privacy import (
    PrivacySettingsSerializer,
    PrivacySettingsUpdateSerializer,
    ConsentManagementSerializer,
    PrivacyTemplateSerializer,
    PrivacySettingsHistorySerializer,
    DataExportRequestSerializer,
    AccountDeletionRequestSerializer,
    PrivacyComplianceReportSerializer
)
from ..services.privacy_service import PrivacyService

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get the client's IP address from the request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_rate_limited(request, action='privacy_update', limit=20, window=3600):
    """
    Check if the request is rate limited based on user ID.

    Args:
        request: Django request object
        action: Action being rate limited
        limit: Maximum number of attempts allowed
        window: Time window in seconds

    Returns:
        tuple: (is_limited, attempts_remaining, reset_time)
    """
    user_id = str(request.user.id)
    cache_key = f"rate_limit_{action}_{user_id}"

    # Get current attempts
    attempts = cache.get(cache_key, 0)

    if attempts >= limit:
        # Get TTL for reset time
        ttl = cache.ttl(cache_key)
        reset_time = timezone.now().timestamp() + ttl if ttl > 0 else None
        return True, 0, reset_time

    return False, limit - attempts, None


def increment_rate_limit(request, action='privacy_update', window=3600):
    """Increment the rate limit counter for the given action and user."""
    user_id = str(request.user.id)
    cache_key = f"rate_limit_{action}_{user_id}"

    # Increment counter
    current_attempts = cache.get(cache_key, 0)
    cache.set(cache_key, current_attempts + 1, window)


@extend_schema(
    tags=['Privacy Management'],
    summary='Get Privacy Settings',
    description='''
    Retrieve the current privacy settings for the authenticated user.
    
    This endpoint returns comprehensive privacy settings including:
    - GDPR consent status (data processing, marketing, analytics)
    - Data sharing controls and preferences
    - Profile visibility settings
    - Communication preferences
    - Security and privacy features
    - Compliance status and privacy score
    - Consent renewal requirements
    
    The response includes computed fields like privacy score and GDPR compliance status.
    ''',
    responses={
        200: OpenApiExample(
            'Success Response',
            value={
                'message': 'Privacy settings retrieved successfully',
                'privacy_settings': {
                    'data_processing_consent': 'granted',
                    'marketing_consent': 'denied',
                    'analytics_consent': 'granted',
                    'data_sharing_level': 'essential',
                    'profile_searchable': True,
                    'profile_indexable': False,
                    'email_notifications': True,
                    'marketing_emails': False,
                    'privacy_score': 75,
                    'is_gdpr_compliant': True,
                    'needs_consent_renewal': False
                }
            }
        ),
        401: OpenApiExample(
            'Unauthorized',
            value={'detail': 'Authentication credentials were not provided.'}
        )
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_privacy_settings(request):
    """
    Get the current user's privacy settings.

    Returns comprehensive privacy settings and compliance status.
    """
    try:
        privacy_settings = PrivacyService.get_or_create_privacy_settings(request.user)
        serializer = PrivacySettingsSerializer(privacy_settings, context={'request': request})

        logger.info(f"Privacy settings retrieved for user: {request.user.email}")

        return Response({
            'message': 'Privacy settings retrieved successfully',
            'privacy_settings': serializer.data
        })

    except Exception as e:
        logger.error(f"Failed to retrieve privacy settings for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to retrieve privacy settings',
            'code': 'PRIVACY_RETRIEVAL_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    methods=['PUT'],
    operation_id='update_privacy_settings_put',
    summary='Update Privacy Settings (Full Update)',
)
@extend_schema(
    methods=['PATCH'],
    operation_id='update_privacy_settings_patch',
    summary='Update Privacy Settings (Partial Update)',
    description="""
    Update the current user's privacy settings.
    
    This endpoint supports both full updates (PUT) and partial updates (PATCH).
    You can update various privacy controls including:
    
    **Data Sharing Controls:**
    - data_sharing_level: Level of data sharing (none/essential/analytics/marketing/full)
    - allow_data_export: Allow user to export their data (GDPR requirement)
    - allow_account_deletion: Allow user to request account deletion (GDPR requirement)
    
    **Profile Visibility:**
    - profile_searchable: Allow profile to appear in search results
    - profile_indexable: Allow search engines to index profile
    - show_online_status: Show when user is online
    - show_last_seen: Show when user was last active
    
    **Communication Preferences:**
    - email_notifications: Receive email notifications
    - sms_notifications: Receive SMS notifications
    - push_notifications: Receive push notifications
    - marketing_emails: Receive marketing emails
    - newsletter_subscription: Subscribe to newsletter
    - communication_frequency: Frequency of communications
    
    **Security Features:**
    - two_factor_required: Require two-factor authentication
    - login_notifications: Notify about new login attempts
    - suspicious_activity_alerts: Alert about suspicious activity
    - data_breach_notifications: Notify about data breaches (cannot be disabled)
    
    **Data Retention:**
    - auto_delete_inactive_data: Automatically delete data after inactivity
    - data_retention_period_months: Months to retain data (1-120)
    
    **Third-party Integration:**
    - allow_social_login: Allow login through social media
    - share_with_partners: Share data with trusted partners
    - allow_api_access: Allow third-party API access
    
    Rate limited to 20 updates per hour per user.
    Changes are logged for audit purposes and GDPR compliance.
    """,
    tags=['Privacy Management'],
    request=PrivacySettingsUpdateSerializer,
    examples=[
        OpenApiExample(
            'Strict Privacy Settings',
            value={
                'data_sharing_level': 'none',
                'profile_searchable': False,
                'profile_indexable': False,
                'marketing_emails': False,
                'share_with_partners': False,
                'allow_api_access': False
            }
        ),
        OpenApiExample(
            'Communication Preferences',
            value={
                'email_notifications': True,
                'sms_notifications': False,
                'push_notifications': True,
                'marketing_emails': False,
                'communication_frequency': 'important_only'
            }
        )
    ],
    responses={
        200: OpenApiExample(
            'Success Response',
            value={
                'message': 'Privacy settings updated successfully',
                'privacy_settings': {
                    'data_sharing_level': 'none',
                    'profile_searchable': False,
                    'privacy_score': 85
                }
            }
        ),
        400: OpenApiExample(
            'Validation Error',
            value={
                'error': 'Privacy settings validation failed',
                'code': 'VALIDATION_ERROR',
                'details': {
                    'data_breach_notifications': ['Data breach notifications cannot be disabled due to legal requirements.']
                }
            }
        ),
        429: OpenApiExample(
            'Rate Limited',
            value={
                'error': 'Too many privacy update attempts. Please try again later.',
                'code': 'RATE_LIMIT_EXCEEDED'
            }
        )
    }
)
@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_privacy_settings(request):
    """
    Update the current user's privacy settings.

    Supports both full updates (PUT) and partial updates (PATCH).
    All changes are logged for audit purposes.
    """
    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'privacy_update', limit=20, window=3600  # 20 updates per hour
    )

    if is_limited:
        logger.warning(f"Privacy update rate limit exceeded for user: {request.user.email}")
        return Response({
            'error': 'Too many privacy update attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    try:
        privacy_settings = PrivacyService.get_or_create_privacy_settings(request.user)

        # Use partial update for PATCH, full update for PUT
        partial = request.method == 'PATCH'

        serializer = PrivacySettingsUpdateSerializer(
            privacy_settings,
            data=request.data,
            partial=partial,
            context={'request': request}
        )

        if serializer.is_valid():
            updated_privacy_settings = serializer.save()

            # Return updated privacy settings
            response_serializer = PrivacySettingsSerializer(
                updated_privacy_settings,
                context={'request': request}
            )

            logger.info(f"Privacy settings updated for user: {request.user.email}")

            return Response({
                'message': 'Privacy settings updated successfully',
                'privacy_settings': response_serializer.data
            })
        else:
            # Increment rate limit on validation errors
            increment_rate_limit(request, 'privacy_update')

            logger.warning(f"Privacy settings validation failed for user {request.user.email}: {serializer.errors}")

            return Response({
                'error': 'Privacy settings validation failed',
                'code': 'VALIDATION_ERROR',
                'details': serializer.errors,
                'attempts_remaining': attempts_remaining - 1
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        # Increment rate limit on any error
        increment_rate_limit(request, 'privacy_update')

        logger.error(f"Privacy settings update failed for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Privacy settings update failed. Please try again.',
            'code': 'PRIVACY_UPDATE_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='manage_consent',
    summary='Manage User Consent',
    description="""
    Grant or withdraw consent for specific data processing activities.
    
    **Consent Types:**
    - **data_processing**: Required for basic service operation (cannot be withdrawn)
    - **marketing**: Marketing communications and promotional content
    - **analytics**: Usage analytics and service improvement
    
    **Actions:**
    - **grant**: Grant consent for the specified type
    - **withdraw**: Withdraw consent for the specified type
    
    **Important Notes:**
    - Data processing consent cannot be withdrawn as it's required for service operation
    - Marketing and analytics consent can be freely granted or withdrawn
    - All consent changes are logged with timestamps for GDPR compliance
    - Withdrawing marketing consent stops all promotional communications
    - Withdrawing analytics consent stops usage tracking (may affect service quality)
    
    **GDPR Compliance:**
    - Consent must be freely given, specific, informed, and unambiguous
    - Users can withdraw consent at any time
    - Consent withdrawal is processed immediately
    - All consent changes are audited and logged
    
    Rate limited to 10 consent changes per hour per user.
    """,
    tags=['Privacy Management'],
    request=ConsentManagementSerializer,
    examples=[
        OpenApiExample(
            'Grant Marketing Consent',
            value={
                'consent_type': 'marketing',
                'action': 'grant',
                'reason': 'User wants to receive promotional emails'
            }
        ),
        OpenApiExample(
            'Withdraw Analytics Consent',
            value={
                'consent_type': 'analytics',
                'action': 'withdraw',
                'reason': 'Privacy concerns'
            }
        )
    ],
    responses={
        200: OpenApiExample(
            'Consent Updated',
            value={
                'message': 'Consent updated successfully',
                'consent_status': {
                    'consent_type': 'marketing',
                    'status': 'granted',
                    'updated_at': '2024-01-15T10:30:00Z'
                }
            }
        ),
        400: OpenApiExample(
            'Invalid Request',
            value={
                'error': 'Consent management failed',
                'code': 'CONSENT_ERROR',
                'details': {
                    'consent_type': 'Data processing consent cannot be withdrawn as it is required for service operation.'
                }
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def manage_consent(request):
    """
    Grant or withdraw consent for specific data processing activities.

    Expected payload:
    {
        "consent_type": "data_processing|marketing|analytics",
        "action": "grant|withdraw",
        "reason": "Optional reason for consent change"
    }
    """
    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'consent_management', limit=10, window=3600  # 10 changes per hour
    )

    if is_limited:
        logger.warning(f"Consent management rate limit exceeded for user: {request.user.email}")
        return Response({
            'error': 'Too many consent management attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    serializer = ConsentManagementSerializer(data=request.data)

    if serializer.is_valid():
        consent_type = serializer.validated_data['consent_type']
        action = serializer.validated_data['action']
        reason = serializer.validated_data.get('reason', '')

        try:
            success, privacy_settings, errors = PrivacyService.manage_consent(
                user=request.user,
                consent_type=consent_type,
                action=action,
                reason=reason,
                request=request
            )

            if success:
                # Get updated consent status
                consent_field = f"{consent_type}_consent"
                consent_date_field = f"{consent_type}_consent_date"

                logger.info(f"Consent {action}ed for user {request.user.email}: {consent_type}")

                return Response({
                    'message': 'Consent updated successfully',
                    'consent_status': {
                        'consent_type': consent_type,
                        'status': getattr(privacy_settings, consent_field),
                        'updated_at': getattr(privacy_settings, consent_date_field).isoformat() if getattr(privacy_settings, consent_date_field) else None
                    }
                })
            else:
                increment_rate_limit(request, 'consent_management')

                return Response({
                    'error': 'Consent management failed',
                    'code': 'CONSENT_ERROR',
                    'details': errors
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            increment_rate_limit(request, 'consent_management')

            logger.error(f"Consent management error for user {request.user.email}: {str(e)}")
            return Response({
                'error': 'Consent management failed. Please try again.',
                'code': 'CONSENT_MANAGEMENT_ERROR'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        increment_rate_limit(request, 'consent_management')

        return Response({
            'error': 'Invalid consent management request',
            'code': 'VALIDATION_ERROR',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    operation_id='apply_privacy_template',
    summary='Apply Privacy Template',
    description="""
    Apply a predefined privacy template to quickly configure privacy settings.
    
    **Available Templates:**
    
    **Strict Template:**
    - No data sharing with third parties
    - Profile not searchable or indexable
    - No online status or last seen visibility
    - No marketing emails or newsletters
    - Two-factor authentication required
    - Auto-delete inactive data after 12 months
    - Maximum privacy protection
    
    **Balanced Template (Recommended):**
    - Essential data sharing only
    - Profile searchable but not indexable
    - No online status visibility
    - No marketing communications
    - Standard security settings
    - Data retained for 24 months
    - Good balance of privacy and functionality
    
    **Open Template:**
    - Analytics data sharing enabled
    - Profile fully searchable and indexable
    - Online status and activity visible
    - Marketing emails and newsletters enabled
    - Partner data sharing allowed
    - API access permitted
    - Maximum functionality with reduced privacy
    
    **Important Notes:**
    - Templates override current settings
    - All changes are logged for audit purposes
    - You can modify individual settings after applying a template
    - Templates are designed for common privacy preferences
    - GDPR compliance is maintained across all templates
    
    Rate limited to 5 template applications per hour per user.
    """,
    tags=['Privacy Management'],
    request=PrivacyTemplateSerializer,
    examples=[
        OpenApiExample(
            'Apply Strict Template',
            value={'template_name': 'strict'}
        ),
        OpenApiExample(
            'Apply Balanced Template',
            value={'template_name': 'balanced'}
        )
    ],
    responses={
        200: OpenApiExample(
            'Template Applied',
            value={
                'message': 'Privacy template applied successfully',
                'template_name': 'strict',
                'privacy_settings': {
                    'data_sharing_level': 'none',
                    'profile_searchable': False,
                    'privacy_score': 95
                }
            }
        ),
        400: OpenApiExample(
            'Invalid Template',
            value={
                'error': 'Privacy template application failed',
                'code': 'TEMPLATE_ERROR',
                'details': {
                    'template_name': 'Invalid template name: invalid_template'
                }
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def apply_privacy_template(request):
    """
    Apply a predefined privacy template.

    Expected payload:
    {
        "template_name": "strict|balanced|open"
    }
    """
    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'template_application', limit=5, window=3600  # 5 applications per hour
    )

    if is_limited:
        logger.warning(f"Template application rate limit exceeded for user: {request.user.email}")
        return Response({
            'error': 'Too many template application attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    serializer = PrivacyTemplateSerializer(data=request.data)

    if serializer.is_valid():
        template_name = serializer.validated_data['template_name']

        try:
            success, privacy_settings, errors = PrivacyService.apply_privacy_template(
                user=request.user,
                template_name=template_name,
                request=request
            )

            if success:
                # Return updated privacy settings
                response_serializer = PrivacySettingsSerializer(
                    privacy_settings,
                    context={'request': request}
                )

                logger.info(f"Privacy template '{template_name}' applied for user: {request.user.email}")

                return Response({
                    'message': 'Privacy template applied successfully',
                    'template_name': template_name,
                    'privacy_settings': response_serializer.data
                })
            else:
                increment_rate_limit(request, 'template_application')

                return Response({
                    'error': 'Privacy template application failed',
                    'code': 'TEMPLATE_ERROR',
                    'details': errors
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            increment_rate_limit(request, 'template_application')

            logger.error(f"Template application error for user {request.user.email}: {str(e)}")
            return Response({
                'error': 'Privacy template application failed. Please try again.',
                'code': 'TEMPLATE_APPLICATION_ERROR'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        increment_rate_limit(request, 'template_application')

        return Response({
            'error': 'Invalid template application request',
            'code': 'VALIDATION_ERROR',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    operation_id='export_user_data',
    summary='Export User Data',
    description="""
    Export user data for GDPR compliance (Right to Data Portability).
    
    **Export Options:**
    - **export_format**: Choose between JSON or XML format
    - **include_history**: Include privacy settings change history
    - **include_privacy_settings**: Include current privacy settings
    
    **Exported Data Includes:**
    - User account information (email, name, dates)
    - Profile information (bio, contact details, preferences)
    - Privacy settings and consent status
    - Change history and audit trail (if requested)
    - Export metadata (timestamp, format, options)
    
    **Data Formats:**
    - **JSON**: Structured JSON format (recommended)
    - **XML**: XML format for legacy systems
    
    **GDPR Compliance:**
    - Provides complete data portability
    - Includes all personal data held by the system
    - Machine-readable format for easy import
    - Audit trail of data processing activities
    - Secure download with user authentication
    
    **Security Features:**
    - User must be authenticated to export their data
    - Rate limited to prevent abuse
    - Export requests are logged for audit
    - Data is provided in secure, structured format
    
    Rate limited to 3 exports per day per user.
    """,
    tags=['Privacy Management'],
    request=DataExportRequestSerializer,
    examples=[
        OpenApiExample(
            'Export All Data as JSON',
            value={
                'export_format': 'json',
                'include_history': True,
                'include_privacy_settings': True
            }
        ),
        OpenApiExample(
            'Export Basic Data as XML',
            value={
                'export_format': 'xml',
                'include_history': False,
                'include_privacy_settings': True
            }
        )
    ],
    responses={
        200: OpenApiExample(
            'Data Export File',
            value='Binary file download with user data'
        ),
        400: OpenApiExample(
            'Invalid Request',
            value={
                'error': 'Data export failed',
                'code': 'EXPORT_ERROR',
                'details': {
                    'export_format': 'Invalid export format. Must be "json" or "xml"'
                }
            }
        ),
        429: OpenApiExample(
            'Rate Limited',
            value={
                'error': 'Too many export attempts. Please try again later.',
                'code': 'RATE_LIMIT_EXCEEDED'
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def export_user_data(request):
    """
    Export user data for GDPR compliance.

    Expected payload:
    {
        "export_format": "json|xml",
        "include_history": true|false,
        "include_privacy_settings": true|false
    }
    """
    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'data_export', limit=3, window=86400  # 3 exports per day
    )

    if is_limited:
        logger.warning(f"Data export rate limit exceeded for user: {request.user.email}")
        return Response({
            'error': 'Too many export attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    serializer = DataExportRequestSerializer(data=request.data)

    if serializer.is_valid():
        export_format = serializer.validated_data['export_format']
        include_history = serializer.validated_data['include_history']
        include_privacy_settings = serializer.validated_data['include_privacy_settings']

        try:
            success, data, errors = PrivacyService.export_user_data(
                user=request.user,
                export_format=export_format,
                include_history=include_history,
                include_privacy_settings=include_privacy_settings
            )

            if success:
                # Create file response
                content_type = 'application/json' if export_format == 'json' else 'application/xml'
                filename = f"user_data_{request.user.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.{export_format}"

                response = HttpResponse(data, content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="{filename}"'

                logger.info(f"Data exported for user {request.user.email} in {export_format} format")

                return response
            else:
                increment_rate_limit(request, 'data_export')

                return Response({
                    'error': 'Data export failed',
                    'code': 'EXPORT_ERROR',
                    'details': errors
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            increment_rate_limit(request, 'data_export')

            logger.error(f"Data export error for user {request.user.email}: {str(e)}")
            return Response({
                'error': 'Data export failed. Please try again.',
                'code': 'DATA_EXPORT_ERROR'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        increment_rate_limit(request, 'data_export')

        return Response({
            'error': 'Invalid data export request',
            'code': 'VALIDATION_ERROR',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    operation_id='request_account_deletion',
    summary='Request Account Deletion',
    description="""
    Request account deletion (Right to be Forgotten) for GDPR compliance.
    
    **Deletion Options:**
    - **Scheduled Deletion**: 30-day grace period (default, recommended)
    - **Immediate Deletion**: Permanent deletion without grace period
    
    **Scheduled Deletion Process:**
    1. Account is deactivated immediately
    2. User receives confirmation email
    3. 30-day grace period begins
    4. User can reactivate account during grace period
    5. After 30 days, account and data are permanently deleted
    
    **Immediate Deletion Process:**
    1. Account and all data are deleted immediately
    2. Action cannot be undone
    3. User loses access immediately
    4. All associated data is permanently removed
    
    **What Gets Deleted:**
    - User account and authentication data
    - Profile information and uploaded files
    - Privacy settings and consent history
    - Session data and login history
    - All personal data associated with the account
    
    **Data Retention:**
    - Some data may be retained for legal compliance
    - Anonymized analytics data may be retained
    - Audit logs may be retained for security purposes
    - Financial records may be retained per legal requirements
    
    **Security Requirements:**
    - User must type "DELETE MY ACCOUNT" to confirm
    - Action is logged for audit purposes
    - User receives email confirmation
    - Rate limited to prevent accidental deletions
    
    **Important Notes:**
    - This action affects all services and applications
    - Deleted accounts cannot be recovered
    - Consider data export before deletion
    - Some data may be retained for legal compliance
    
    Rate limited to 2 deletion requests per day per user.
    """,
    tags=['Privacy Management'],
    request=AccountDeletionRequestSerializer,
    examples=[
        OpenApiExample(
            'Schedule Account Deletion',
            value={
                'confirmation_text': 'DELETE MY ACCOUNT',
                'reason': 'No longer need the service',
                'delete_immediately': False
            }
        ),
        OpenApiExample(
            'Immediate Account Deletion',
            value={
                'confirmation_text': 'DELETE MY ACCOUNT',
                'reason': 'Privacy concerns',
                'delete_immediately': True
            }
        )
    ],
    responses={
        200: OpenApiExample(
            'Deletion Scheduled',
            value={
                'message': 'Account scheduled for deletion on 2024-02-15. You can reactivate before this date.',
                'deletion_type': 'scheduled',
                'deletion_date': '2024-02-15T10:30:00Z'
            }
        ),
        200: OpenApiExample(
            'Immediate Deletion',
            value={
                'message': 'Account deleted immediately',
                'deletion_type': 'immediate'
            }
        ),
        400: OpenApiExample(
            'Invalid Confirmation',
            value={
                'error': 'Account deletion failed',
                'code': 'DELETION_ERROR',
                'details': {
                    'confirmation_text': 'You must type "DELETE MY ACCOUNT" to confirm deletion.'
                }
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_account_deletion(request):
    """
    Request account deletion (Right to be Forgotten).

    Expected payload:
    {
        "confirmation_text": "DELETE MY ACCOUNT",
        "reason": "Optional reason for deletion",
        "delete_immediately": false
    }
    """
    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'account_deletion', limit=2, window=86400  # 2 requests per day
    )

    if is_limited:
        logger.warning(f"Account deletion rate limit exceeded for user: {request.user.email}")
        return Response({
            'error': 'Too many deletion requests. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    serializer = AccountDeletionRequestSerializer(data=request.data)

    if serializer.is_valid():
        reason = serializer.validated_data.get('reason', '')
        delete_immediately = serializer.validated_data['delete_immediately']

        try:
            success, message, errors = PrivacyService.request_account_deletion(
                user=request.user,
                reason=reason,
                delete_immediately=delete_immediately,
                request=request
            )

            if success:
                logger.info(f"Account deletion requested for user {request.user.email}: {'immediate' if delete_immediately else 'scheduled'}")

                return Response({
                    'message': message,
                    'deletion_type': 'immediate' if delete_immediately else 'scheduled'
                })
            else:
                increment_rate_limit(request, 'account_deletion')

                return Response({
                    'error': 'Account deletion failed',
                    'code': 'DELETION_ERROR',
                    'details': errors
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            increment_rate_limit(request, 'account_deletion')

            logger.error(f"Account deletion error for user {request.user.email}: {str(e)}")
            return Response({
                'error': 'Account deletion failed. Please try again.',
                'code': 'ACCOUNT_DELETION_ERROR'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        increment_rate_limit(request, 'account_deletion')

        return Response({
            'error': 'Invalid account deletion request',
            'code': 'VALIDATION_ERROR',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    operation_id='get_privacy_history',
    summary='Get Privacy Settings History',
    description="""
    Retrieve the history of privacy settings changes for audit purposes.
    
    **History Information Includes:**
    - All privacy settings changes with timestamps
    - User who made each change
    - IP address and user agent for each change
    - Reason for each change (if provided)
    - Old and new values for changed fields
    - Action type (create, update, consent granted/withdrawn, etc.)
    
    **Use Cases:**
    - GDPR compliance and audit requirements
    - User transparency about data processing
    - Security monitoring and investigation
    - Consent management verification
    - Privacy settings troubleshooting
    
    **Security Features:**
    - Users can only view their own history
    - Sensitive information is appropriately masked
    - Access is logged for audit purposes
    - Rate limited to prevent abuse
    
    **Pagination:**
    - Returns up to 50 most recent entries by default
    - Ordered by most recent changes first
    - Additional pagination available via query parameters
    
    This endpoint supports GDPR transparency requirements by providing users
    with complete visibility into how their privacy settings have changed over time.
    """,
    tags=['Privacy Management'],
    parameters=[
        OpenApiParameter(
            name='limit',
            type=OpenApiTypes.INT,
            location=OpenApiParameter.QUERY,
            description='Maximum number of history entries to return (default: 50, max: 100)'
        )
    ],
    responses={
        200: OpenApiExample(
            'Privacy History',
            value={
                'message': 'Privacy history retrieved successfully',
                'history': [
                    {
                        'action': 'update',
                        'action_display': 'Settings Updated',
                        'changed_fields': ['marketing_emails', 'data_sharing_level'],
                        'old_values': {'marketing_emails': True, 'data_sharing_level': 'analytics'},
                        'new_values': {'marketing_emails': False, 'data_sharing_level': 'essential'},
                        'changed_at': '2024-01-15T10:30:00Z',
                        'reason': 'Privacy settings updated by user',
                        'ip_address': '192.168.1.1'
                    }
                ],
                'total_entries': 25
            }
        )
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_privacy_history(request):
    """
    Get privacy settings change history for the current user.
    """
    try:
        # Get limit from query parameters
        limit = request.GET.get('limit', 50)
        try:
            limit = int(limit)
            limit = min(max(limit, 1), 100)  # Clamp between 1 and 100
        except (ValueError, TypeError):
            limit = 50

        history = PrivacyService.get_privacy_history(request.user, limit=limit)
        serializer = PrivacySettingsHistorySerializer(history, many=True)

        logger.info(f"Privacy history retrieved for user: {request.user.email}")

        return Response({
            'message': 'Privacy history retrieved successfully',
            'history': serializer.data,
            'total_entries': len(serializer.data)
        })

    except Exception as e:
        logger.error(f"Failed to retrieve privacy history for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to retrieve privacy history',
            'code': 'HISTORY_RETRIEVAL_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='get_privacy_compliance_report',
    summary='Get Privacy Compliance Report',
    description="""
    Generate a comprehensive privacy compliance report for the current user.
    
    **Report Includes:**
    - GDPR compliance status and score
    - CCPA compliance status
    - Privacy score (0-100) based on current settings
    - Consent status for all data processing activities
    - Last privacy settings review date
    - Consent renewal requirements
    - Identified compliance issues
    - Personalized recommendations for improvement
    
    **Compliance Checks:**
    - Data processing consent status
    - Marketing consent validity
    - Analytics consent status
    - Data export and deletion rights
    - Breach notification settings
    - Consent age and renewal requirements
    
    **Privacy Score Calculation:**
    - Data sharing restrictions (30 points)
    - Profile visibility controls (25 points)
    - Communication preferences (20 points)
    - Security features enabled (15 points)
    - Data retention settings (10 points)
    
    **Use Cases:**
    - Personal privacy assessment
    - GDPR compliance verification
    - Privacy settings optimization
    - Regulatory audit preparation
    - User education and awareness
    
    This report helps users understand their current privacy posture
    and provides actionable recommendations for improvement.
    """,
    tags=['Privacy Management'],
    responses={
        200: OpenApiExample(
            'Compliance Report',
            value={
                'message': 'Privacy compliance report generated successfully',
                'report': {
                    'user_email': 'user@example.com',
                    'gdpr_compliant': True,
                    'ccpa_compliant': True,
                    'privacy_score': 75,
                    'consent_status': {
                        'data_processing': {'status': 'granted', 'date': '2024-01-01T00:00:00Z'},
                        'marketing': {'status': 'denied', 'date': '2024-01-01T00:00:00Z'},
                        'analytics': {'status': 'granted', 'date': '2024-01-01T00:00:00Z'}
                    },
                    'last_review_date': '2024-01-15T10:30:00Z',
                    'needs_consent_renewal': False,
                    'compliance_issues': [],
                    'recommendations': ['Consider enabling two-factor authentication']
                }
            }
        )
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_privacy_compliance_report(request):
    """
    Generate a privacy compliance report for the current user.
    """
    try:
        report = PrivacyService.get_privacy_compliance_report(request.user)

        if 'error' in report:
            return Response({
                'error': 'Failed to generate compliance report',
                'code': 'REPORT_GENERATION_FAILED',
                'details': report
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.info(f"Privacy compliance report generated for user: {request.user.email}")

        return Response({
            'message': 'Privacy compliance report generated successfully',
            'report': report
        })

    except Exception as e:
        logger.error(f"Failed to generate compliance report for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to generate compliance report',
            'code': 'REPORT_GENERATION_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='complete_privacy_review',
    summary='Complete Privacy Review',
    description="""
    Mark privacy settings as reviewed by the user.
    
    **Purpose:**
    - Updates the last review timestamp
    - Demonstrates user engagement with privacy settings
    - Helps with GDPR compliance requirements
    - Resets consent renewal notifications
    
    **When to Use:**
    - After user reviews and confirms their privacy settings
    - During periodic privacy checkups
    - After applying privacy templates
    - Following privacy policy updates
    
    **Effects:**
    - Updates settings_last_reviewed timestamp
    - Logs the review action for audit purposes
    - May affect consent renewal requirements
    - Demonstrates active privacy management
    
    **GDPR Compliance:**
    - Shows user is actively managing their privacy
    - Provides audit trail of privacy engagement
    - Supports consent validity requirements
    - Demonstrates transparency and user control
    
    This action is logged for audit purposes and helps maintain
    GDPR compliance by showing active user engagement with privacy settings.
    """,
    tags=['Privacy Management'],
    responses={
        200: OpenApiExample(
            'Review Completed',
            value={
                'message': 'Privacy review completed successfully',
                'review_date': '2024-01-15T10:30:00Z'
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def complete_privacy_review(request):
    """
    Mark privacy settings as reviewed by the user.
    """
    try:
        success, privacy_settings, errors = PrivacyService.complete_privacy_review(
            user=request.user,
            request=request
        )

        if success:
            logger.info(f"Privacy review completed for user: {request.user.email}")

            return Response({
                'message': 'Privacy review completed successfully',
                'review_date': privacy_settings.settings_last_reviewed.isoformat()
            })
        else:
            return Response({
                'error': 'Failed to complete privacy review',
                'code': 'REVIEW_COMPLETION_FAILED',
                'details': errors
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    except Exception as e:
        logger.error(f"Failed to complete privacy review for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to complete privacy review',
            'code': 'REVIEW_COMPLETION_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)