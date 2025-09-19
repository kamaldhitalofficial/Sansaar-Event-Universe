"""
Profile views for user profile management API endpoints.
"""
import logging
from django.core.cache import cache
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes
from ..serializers.profile import (
    UserProfileSerializer,
    UserProfileUpdateSerializer,
    UserProfileHistorySerializer,
    ProfileCompletionSerializer,
    ProfileVisibilitySerializer
)
from ..services.profile_service import ProfileService

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Get the client's IP address from the request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def is_rate_limited(request, action='profile_update', limit=10, window=3600):
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


def increment_rate_limit(request, action='profile_update', window=3600):
    """Increment the rate limit counter for the given action and user."""
    user_id = str(request.user.id)
    cache_key = f"rate_limit_{action}_{user_id}"

    # Increment counter
    current_attempts = cache.get(cache_key, 0)
    cache.set(cache_key, current_attempts + 1, window)


@extend_schema(
    tags=['Profile'],
    summary='Get Current User Profile',
    description='''
    Retrieve the complete profile information for the currently authenticated user.
    
    This endpoint returns all profile data including:
    - Personal information (name, bio, date of birth, etc.)
    - Contact information (phone, address)
    - Social links (website, LinkedIn, Twitter)
    - Privacy settings
    - Communication preferences
    - Profile completion status and suggestions
    
    The response includes computed fields like display name, age, and completion percentage.
    ''',
    responses={
        200: OpenApiExample(
            'Success Response',
            value={
                'message': 'Profile retrieved successfully',
                'profile': {
                    'email': 'user@example.com',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'display_name': 'John Doe',
                    'bio': 'Software developer passionate about technology',
                    'date_of_birth': '1990-01-01',
                    'age': 34,
                    'gender': 'M',
                    'phone_number': '+1234567890',
                    'city': 'New York',
                    'country': 'USA',
                    'profile_picture_url': 'https://example.com/media/profile_pictures/user_123.jpg',
                    'website_url': 'https://johndoe.com',
                    'linkedin_url': 'https://linkedin.com/in/johndoe',
                    'twitter_handle': '@johndoe',
                    'profile_visibility': 'public',
                    'email_visibility': 'private',
                    'phone_visibility': 'private',
                    'preferred_communication': 'email',
                    'marketing_emails': False,
                    'event_notifications': True,
                    'security_alerts': True,
                    'profile_completion_percentage': 85,
                    'completion_suggestions': ['Add your profile picture', 'Complete your address'],
                    'created_at': '2024-01-01T00:00:00Z',
                    'updated_at': '2024-01-15T10:30:00Z'
                }
            }
        ),
        401: OpenApiExample(
            'Unauthorized',
            value={'detail': 'Authentication credentials were not provided.'}
        ),
        500: OpenApiExample(
            'Server Error',
            value={
                'error': 'Failed to retrieve profile',
                'code': 'PROFILE_RETRIEVAL_FAILED'
            }
        )
    }
)
@extend_schema(
    operation_id='get_user_profile',
    summary='Get User Profile',
    description="""
    Retrieve the complete profile information for the authenticated user.
    
    This endpoint returns all profile data including:
    - Personal information (name, bio, date of birth, etc.)
    - Contact information (phone, address)
    - Social links (website, LinkedIn, Twitter)
    - Privacy settings
    - Communication preferences
    - Profile completion status and suggestions
    
    The response includes computed fields like display name, age, and completion percentage.
    """,
    tags=['Profile'],
    responses={
        200: OpenApiExample(
            'Success Response',
            value={
                'message': 'Profile retrieved successfully',
                'profile': {
                    'email': 'user@example.com',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'display_name': 'John Doe',
                    'bio': 'Software developer passionate about technology',
                    'date_of_birth': '1990-01-01',
                    'age': 34,
                    'gender': 'M',
                    'phone_number': '+1234567890',
                    'profile_picture_url': 'https://example.com/media/profile_pictures/user_123.jpg',
                    'profile_completion_percentage': 85,
                    'completion_suggestions': ['Add your location', 'Upload a profile picture'],
                    'created_at': '2024-01-01T00:00:00Z',
                    'updated_at': '2024-01-15T10:30:00Z'
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
def get_profile(request):
    """
    Get the current user's profile information.

    Returns complete profile data for the authenticated user.
    """
    try:
        profile = ProfileService.get_or_create_profile(request.user)
        serializer = UserProfileSerializer(profile, context={'request': request})

        logger.info(f"Profile retrieved for user: {request.user.email}")

        return Response({
            'message': 'Profile retrieved successfully',
            'profile': serializer.data
        })

    except Exception as e:
        logger.error(f"Failed to retrieve profile for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to retrieve profile',
            'code': 'PROFILE_RETRIEVAL_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='update_profile_data',
    summary='Update User Profile',
    description="""
    Update the current user's profile information.
    
    This endpoint supports both full updates (PUT) and partial updates (PATCH).
    You can update any combination of profile fields including:
    
    **Personal Information:**
    - bio: Brief description about yourself (max 500 characters)
    - date_of_birth: Date of birth in YYYY-MM-DD format
    - gender: Gender identity (M/F/O/P)
    
    **Contact Information:**
    - phone_number: Phone number with country code (e.g., +1234567890)
    - street_address, city, state_province, postal_code, country: Address fields
    
    **Social Links:**
    - website_url: Personal or professional website
    - linkedin_url: LinkedIn profile URL
    - twitter_handle: Twitter handle (with or without @)
    
    **Privacy Settings:**
    - profile_visibility: Who can see your profile (public/private/friends)
    - email_visibility: Who can see your email (public/private/friends)
    - phone_visibility: Who can see your phone (public/private/friends)
    
    **Communication Preferences:**
    - preferred_communication: Preferred method (email/sms/push/none)
    - marketing_emails: Receive marketing emails (true/false)
    - event_notifications: Receive event notifications (true/false)
    - security_alerts: Receive security alerts (true/false)
    
    Rate limited to 10 updates per hour per user.
    """,
    tags=['Profile'],
    request=UserProfileUpdateSerializer,
    examples=[
        OpenApiExample(
            'Update Basic Info',
            value={
                'bio': 'Updated bio about myself',
                'phone_number': '+1234567890',
                'city': 'New York',
                'country': 'United States'
            }
        ),
        OpenApiExample(
            'Update Privacy Settings',
            value={
                'profile_visibility': 'private',
                'email_visibility': 'friends',
                'phone_visibility': 'private'
            }
        )
    ],
    responses={
        200: OpenApiExample(
            'Success Response',
            value={
                'message': 'Profile updated successfully',
                'profile': {
                    'bio': 'Updated bio about myself',
                    'phone_number': '+1234567890',
                    'profile_completion_percentage': 90
                }
            }
        ),
        400: OpenApiExample(
            'Validation Error',
            value={
                'error': 'Profile validation failed',
                'code': 'VALIDATION_ERROR',
                'details': {
                    'phone_number': ['Phone number must include country code (e.g., +1234567890).']
                }
            }
        ),
        429: OpenApiExample(
            'Rate Limited',
            value={
                'error': 'Too many profile update attempts. Please try again later.',
                'code': 'RATE_LIMIT_EXCEEDED',
                'reset_time': 1640995200
            }
        )
    }
)
@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser, JSONParser])
def update_profile(request):
    """
    Update the current user's profile information.

    Supports both full updates (PUT) and partial updates (PATCH).
    Handles file uploads for profile pictures.
    """
    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'profile_update', limit=10, window=3600  # 10 updates per hour
    )

    if is_limited:
        logger.warning(f"Profile update rate limit exceeded for user: {request.user.email}")
        return Response({
            'error': 'Too many profile update attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    try:
        profile = ProfileService.get_or_create_profile(request.user)

        # Use partial update for PATCH, full update for PUT
        partial = request.method == 'PATCH'

        serializer = UserProfileUpdateSerializer(
            profile,
            data=request.data,
            partial=partial,
            context={'request': request}
        )

        if serializer.is_valid():
            updated_profile = serializer.save()

            # Return updated profile data
            response_serializer = UserProfileSerializer(
                updated_profile,
                context={'request': request}
            )

            logger.info(f"Profile updated for user: {request.user.email}")

            return Response({
                'message': 'Profile updated successfully',
                'profile': response_serializer.data
            })
        else:
            # Increment rate limit on validation errors to prevent spam
            increment_rate_limit(request, 'profile_update')

            logger.warning(f"Profile update validation failed for user {request.user.email}: {serializer.errors}")

            return Response({
                'error': 'Profile validation failed',
                'code': 'VALIDATION_ERROR',
                'details': serializer.errors,
                'attempts_remaining': attempts_remaining - 1
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        # Increment rate limit on any error
        increment_rate_limit(request, 'profile_update')

        logger.error(f"Profile update failed for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Profile update failed. Please try again.',
            'code': 'PROFILE_UPDATE_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='upload_profile_picture',
    summary='Upload Profile Picture',
    description="""
    Upload or update the user's profile picture.
    
    **File Requirements:**
    - Supported formats: JPG, JPEG, PNG
    - Maximum file size: 5MB
    - Minimum dimensions: 50x50 pixels
    - Maximum dimensions: 2048x2048 pixels
    
    **Features:**
    - Automatic file validation and processing
    - Secure file storage with unique naming
    - Old profile picture is automatically replaced
    - Image optimization and validation using PIL
    
    Rate limited to 5 uploads per hour per user.
    """,
    tags=['Profile'],
    request={
        'multipart/form-data': {
            'type': 'object',
            'properties': {
                'profile_picture': {
                    'type': 'string',
                    'format': 'binary',
                    'description': 'Profile picture file (JPG/PNG, max 5MB)'
                }
            },
            'required': ['profile_picture']
        }
    },
    responses={
        200: OpenApiExample(
            'Success Response',
            value={
                'message': 'Profile picture uploaded successfully',
                'profile_picture_url': 'https://example.com/media/profile_pictures/user_123_20240115_103000.jpg',
                'profile': {
                    'profile_picture_url': 'https://example.com/media/profile_pictures/user_123_20240115_103000.jpg',
                    'profile_completion_percentage': 95
                }
            }
        ),
        400: OpenApiExample(
            'Validation Error',
            value={
                'error': 'Profile picture upload failed',
                'code': 'UPLOAD_FAILED',
                'details': {
                    'profile_picture': ['Profile picture must be smaller than 5MB.']
                }
            }
        ),
        429: OpenApiExample(
            'Rate Limited',
            value={
                'error': 'Too many picture upload attempts. Please try again later.',
                'code': 'RATE_LIMIT_EXCEEDED'
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def upload_profile_picture(request):
    """
    Upload or update the user's profile picture.

    Expected form data:
    - profile_picture: Image file (JPG/PNG, max 5MB)
    """
    # Check rate limiting
    is_limited, attempts_remaining, reset_time = is_rate_limited(
        request, 'picture_upload', limit=5, window=3600  # 5 uploads per hour
    )

    if is_limited:
        logger.warning(f"Picture upload rate limit exceeded for user: {request.user.email}")
        return Response({
            'error': 'Too many picture upload attempts. Please try again later.',
            'code': 'RATE_LIMIT_EXCEEDED',
            'reset_time': reset_time
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

    picture_file = request.FILES.get('profile_picture')

    if not picture_file:
        increment_rate_limit(request, 'picture_upload')
        return Response({
            'error': 'Profile picture file is required',
            'code': 'FILE_REQUIRED'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        success, profile, errors = ProfileService.update_profile_picture(
            user=request.user,
            picture_file=picture_file,
            request=request
        )

        if success:
            serializer = UserProfileSerializer(profile, context={'request': request})

            logger.info(f"Profile picture uploaded for user: {request.user.email}")

            return Response({
                'message': 'Profile picture uploaded successfully',
                'profile_picture_url': serializer.data.get('profile_picture_url'),
                'profile': serializer.data
            })
        else:
            increment_rate_limit(request, 'picture_upload')

            logger.warning(f"Profile picture upload failed for user {request.user.email}: {errors}")

            return Response({
                'error': 'Profile picture upload failed',
                'code': 'UPLOAD_FAILED',
                'details': errors
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        increment_rate_limit(request, 'picture_upload')

        logger.error(f"Profile picture upload error for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Profile picture upload failed. Please try again.',
            'code': 'UPLOAD_ERROR'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='delete_profile_picture',
    summary='Delete Profile Picture',
    description="""
    Delete the user's profile picture and remove the file from storage.
    
    **Deletion Process:**
    1. Checks if user has a profile picture
    2. Removes the image file from storage
    3. Updates profile record to remove picture reference
    4. Logs the deletion in profile history
    5. Updates profile completion percentage
    
    **Security Features:**
    - User can only delete their own picture
    - Secure file deletion from storage
    - Audit trail of picture deletions
    - Profile completion recalculation
    
    **Use Cases:**
    - User wants to remove their picture
    - Privacy concerns
    - Updating to a new picture (delete then upload)
    - Profile cleanup
    
    **Effects:**
    - Profile picture URL becomes null
    - Profile completion percentage may decrease
    - Change is logged in profile history
    - File is permanently removed from storage
    
    This action cannot be undone - the image file is permanently deleted.
    """,
    tags=['Profile'],
    responses={
        200: OpenApiExample(
            'Picture Deleted',
            value={
                'message': 'Profile picture deleted successfully'
            }
        ),
        400: OpenApiExample(
            'No Picture to Delete',
            value={
                'error': 'Failed to delete profile picture',
                'code': 'DELETE_FAILED',
                'details': {
                    'profile_picture': ['No profile picture to delete']
                }
            }
        )
    }
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_profile_picture(request):
    """
    Delete the user's profile picture.
    """
    try:
        success, profile, errors = ProfileService.delete_profile_picture(
            user=request.user,
            request=request
        )

        if success:
            logger.info(f"Profile picture deleted for user: {request.user.email}")

            return Response({
                'message': 'Profile picture deleted successfully'
            })
        else:
            return Response({
                'error': 'Failed to delete profile picture',
                'code': 'DELETE_FAILED',
                'details': errors
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Profile picture deletion error for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Profile picture deletion failed. Please try again.',
            'code': 'DELETE_ERROR'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='get_profile_completion',
    summary='Get Profile Completion Status',
    description="""
    Get detailed profile completion status and personalized suggestions for improvement.
    
    **Completion Calculation:**
    The completion percentage is calculated based on filled fields with different weights:
    - Basic user info (first_name, last_name): 20 points total
    - Bio: 10 points
    - Date of birth: 10 points
    - Phone number: 10 points
    - Location (city, country): 15 points total
    - Profile picture: 15 points
    - Address details: 20 points total
    - Social links: 12 points total
    - Other fields: remaining points
    
    **Response includes:**
    - Current completion percentage (0-100)
    - Whether profile is considered complete (>= 80%)
    - Personalized suggestions for improvement
    - List of missing important fields
    
    This helps users understand how to improve their profile visibility and completeness.
    """,
    tags=['Profile'],
    responses={
        200: OpenApiExample(
            'Success Response',
            value={
                'message': 'Profile completion status retrieved successfully',
                'completion': {
                    'completion_percentage': 75,
                    'is_complete': False,
                    'suggestions': [
                        'Upload a profile picture',
                        'Add your location (city and country)',
                        'Write a brief bio about yourself'
                    ],
                    'missing_fields': [
                        {'field': 'profile_picture', 'display_name': 'Profile Picture'},
                        {'field': 'city', 'display_name': 'City'},
                        {'field': 'bio', 'display_name': 'Bio/Description'}
                    ]
                }
            }
        )
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile_completion(request):
    """
    Get profile completion status and suggestions for improvement.
    """
    try:
        completion_data = ProfileService.get_profile_completion_status(request.user)

        return Response({
            'message': 'Profile completion status retrieved successfully',
            'completion': completion_data
        })

    except Exception as e:
        logger.error(f"Failed to get profile completion for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to retrieve profile completion status',
            'code': 'COMPLETION_RETRIEVAL_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='update_profile_privacy',
    summary='Update Privacy Settings',
    description="""
    Update user's privacy and visibility settings for profile information.
    
    **Privacy Levels:**
    - **public**: Visible to everyone, including anonymous users
    - **private**: Visible only to the profile owner
    - **friends**: Visible to friends/connections only (future feature)
    
    **Configurable Visibility:**
    - **profile_visibility**: Overall profile visibility
    - **email_visibility**: Email address visibility
    - **phone_visibility**: Phone number visibility
    
    **Security Features:**
    - Granular control over information sharing
    - Audit trail of privacy changes
    - Default secure settings (private)
    - Change history tracking
    
    **Use Cases:**
    - Users wanting to control information sharing
    - Privacy-conscious users
    - Professional vs personal profile separation
    - Compliance with privacy regulations
    
    Changes are logged in profile history for audit purposes.
    """,
    tags=['Profile'],
    request=ProfileVisibilitySerializer,
    examples=[
        OpenApiExample(
            'Make Profile Private',
            value={
                'profile_visibility': 'private',
                'email_visibility': 'private',
                'phone_visibility': 'private'
            }
        ),
        OpenApiExample(
            'Mixed Privacy Settings',
            value={
                'profile_visibility': 'public',
                'email_visibility': 'private',
                'phone_visibility': 'friends'
            }
        )
    ],
    responses={
        200: OpenApiExample(
            'Privacy Settings Updated',
            value={
                'message': 'Privacy settings updated successfully',
                'privacy_settings': {
                    'profile_visibility': 'private',
                    'email_visibility': 'private',
                    'phone_visibility': 'private'
                }
            }
        ),
        400: OpenApiExample(
            'Validation Error',
            value={
                'error': 'Privacy settings validation failed',
                'code': 'VALIDATION_ERROR',
                'details': {
                    'profile_visibility': ['Select a valid choice. invalid is not one of the available choices.']
                }
            }
        )
    }
)
@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_privacy_settings(request):
    """
    Update user's privacy settings.

    Expected payload:
    {
        "profile_visibility": "public|private|friends",
        "email_visibility": "public|private|friends",
        "phone_visibility": "public|private|friends"
    }
    """
    try:
        profile = ProfileService.get_or_create_profile(request.user)

        # Use partial update for PATCH, full update for PUT
        partial = request.method == 'PATCH'

        serializer = ProfileVisibilitySerializer(
            profile,
            data=request.data,
            partial=partial,
            context={'request': request}
        )

        if serializer.is_valid():
            updated_profile = serializer.save()

            logger.info(f"Privacy settings updated for user: {request.user.email}")

            return Response({
                'message': 'Privacy settings updated successfully',
                'privacy_settings': {
                    'profile_visibility': updated_profile.profile_visibility,
                    'email_visibility': updated_profile.email_visibility,
                    'phone_visibility': updated_profile.phone_visibility
                }
            })
        else:
            logger.warning(f"Privacy settings validation failed for user {request.user.email}: {serializer.errors}")

            return Response({
                'error': 'Privacy settings validation failed',
                'code': 'VALIDATION_ERROR',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Privacy settings update failed for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Privacy settings update failed. Please try again.',
            'code': 'PRIVACY_UPDATE_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='update_profile_communication',
    summary='Update Communication Preferences',
    description="""
    Update user's communication and notification preferences.
    
    **Communication Methods:**
    - **email**: Receive communications via email
    - **sms**: Receive communications via SMS/text
    - **push**: Receive push notifications (mobile/web)
    - **none**: No communications (except critical security alerts)
    
    **Notification Types:**
    - **marketing_emails**: Promotional and marketing content
    - **event_notifications**: Event updates and reminders
    - **security_alerts**: Security-related notifications (recommended: always enabled)
    
    **Important Notes:**
    - Security alerts are highly recommended to stay enabled
    - Marketing emails can be disabled for privacy
    - Event notifications help users stay informed
    - Preferred communication method affects all notifications
    
    **Compliance:**
    - Respects user consent for marketing communications
    - Allows granular control over notification types
    - Maintains audit trail of preference changes
    - Supports privacy regulation compliance
    
    Changes are tracked in profile history for transparency.
    """,
    tags=['Profile'],
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'preferred_communication': {
                    'type': 'string',
                    'enum': ['email', 'sms', 'push', 'none'],
                    'description': 'Preferred communication method'
                },
                'marketing_emails': {
                    'type': 'boolean',
                    'description': 'Receive marketing emails'
                },
                'event_notifications': {
                    'type': 'boolean',
                    'description': 'Receive event notifications'
                },
                'security_alerts': {
                    'type': 'boolean',
                    'description': 'Receive security alerts'
                }
            }
        }
    },
    responses={
        200: OpenApiExample(
            'Preferences Updated',
            value={
                'message': 'Communication preferences updated successfully',
                'preferences': {
                    'preferred_communication': 'email',
                    'marketing_emails': False,
                    'event_notifications': True,
                    'security_alerts': True
                }
            }
        ),
        400: OpenApiExample(
            'Validation Error',
            value={
                'error': 'Communication preferences validation failed',
                'code': 'VALIDATION_ERROR',
                'details': {
                    'preferred_communication': ['Select a valid choice. invalid is not one of the available choices.']
                }
            }
        )
    }
)
@api_view(['PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def update_communication_preferences(request):
    """
    Update user's communication preferences.

    Expected payload:
    {
        "preferred_communication": "email|sms|push|none",
        "marketing_emails": true|false,
        "event_notifications": true|false,
        "security_alerts": true|false
    }
    """
    try:
        success, profile, errors = ProfileService.bulk_update_communication_preferences(
            user=request.user,
            preferences=request.data,
            request=request
        )

        if success:
            logger.info(f"Communication preferences updated for user: {request.user.email}")

            return Response({
                'message': 'Communication preferences updated successfully',
                'preferences': {
                    'preferred_communication': profile.preferred_communication,
                    'marketing_emails': profile.marketing_emails,
                    'event_notifications': profile.event_notifications,
                    'security_alerts': profile.security_alerts
                }
            })
        else:
            logger.warning(f"Communication preferences validation failed for user {request.user.email}: {errors}")

            return Response({
                'error': 'Communication preferences validation failed',
                'code': 'VALIDATION_ERROR',
                'details': errors
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Communication preferences update failed for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Communication preferences update failed. Please try again.',
            'code': 'PREFERENCES_UPDATE_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='get_profile_history',
    summary='Get Profile Change History',
    description="""
    Get detailed audit trail of all profile changes for the current user.
    
    **History Information Includes:**
    - Change timestamp and type of action
    - Fields that were modified
    - Old and new values (where appropriate)
    - User who made the change
    - IP address and user agent
    - Reason for the change
    
    **Action Types:**
    - **create**: Profile creation
    - **update**: General profile updates
    - **picture_change**: Profile picture changes
    - **privacy_change**: Privacy settings changes
    
    **Security and Compliance:**
    - Complete audit trail for transparency
    - Change attribution and tracking
    - IP address logging for security
    - Timestamp precision for forensics
    - Data integrity verification
    
    **Use Cases:**
    - Security monitoring and review
    - Compliance and audit requirements
    - User transparency and control
    - Troubleshooting profile issues
    - Change pattern analysis
    
    **Privacy:**
    - Only user's own history is accessible
    - Sensitive data may be masked
    - Configurable retention periods
    - GDPR compliance support
    
    This endpoint provides complete transparency about profile modifications.
    """,
    tags=['Profile'],
    parameters=[
        OpenApiParameter(
            name='limit',
            type=OpenApiTypes.INT,
            location=OpenApiParameter.QUERY,
            description='Number of history entries to return (default: 50, max: 100)',
            required=False
        )
    ],
    responses={
        200: OpenApiExample(
            'Profile History',
            value={
                'message': 'Profile history retrieved successfully',
                'history': [
                    {
                        'id': '123e4567-e89b-12d3-a456-426614174000',
                        'action': 'update',
                        'action_display': 'Profile Updated',
                        'changed_fields': ['bio', 'phone_number'],
                        'old_values': {
                            'bio': 'Old bio text',
                            'phone_number': ''
                        },
                        'new_values': {
                            'bio': 'Updated bio text',
                            'phone_number': '+1234567890'
                        },
                        'changed_by_email': 'user@example.com',
                        'changed_at': '2024-01-15T14:30:00Z',
                        'ip_address': '192.168.1.100',
                        'reason': 'Profile update via API'
                    }
                ],
                'count': 1
            }
        )
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile_history(request):
    """
    Get the user's profile change history.

    Query parameters:
    - limit: Number of history entries to return (default: 50, max: 100)
    """
    try:
        # Get limit from query parameters
        limit = min(int(request.GET.get('limit', 50)), 100)

        history = ProfileService.get_profile_history(request.user, limit=limit)
        serializer = UserProfileHistorySerializer(history, many=True)

        return Response({
            'message': 'Profile history retrieved successfully',
            'history': serializer.data,
            'count': len(serializer.data)
        })

    except Exception as e:
        logger.error(f"Failed to retrieve profile history for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to retrieve profile history',
            'code': 'HISTORY_RETRIEVAL_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='get_profile_statistics',
    summary='Get Profile Statistics',
    description="""
    Get comprehensive statistics and metrics about the user's profile.
    
    **Statistics Include:**
    - Profile creation and last update timestamps
    - Total number of profile modifications
    - Current completion percentage
    - Profile completeness status
    - Profile picture status
    - Current privacy level setting
    
    **Metrics Categories:**
    - **Activity Metrics**: Update frequency and patterns
    - **Completion Metrics**: Profile completeness analysis
    - **Security Metrics**: Privacy settings and status
    - **Usage Metrics**: Profile engagement data
    
    **Use Cases:**
    - User dashboard and analytics
    - Profile completion tracking
    - Activity monitoring
    - User engagement analysis
    - Progress tracking over time
    
    **Data Insights:**
    - Profile evolution over time
    - User engagement patterns
    - Completion progress tracking
    - Privacy preference trends
    - Activity frequency analysis
    
    This endpoint provides valuable insights for users to understand their profile usage and completion status.
    """,
    tags=['Profile'],
    responses={
        200: OpenApiExample(
            'Profile Statistics',
            value={
                'message': 'Profile statistics retrieved successfully',
                'statistics': {
                    'profile_created': '2024-01-01T00:00:00Z',
                    'last_updated': '2024-01-15T14:30:00Z',
                    'total_updates': 15,
                    'completion_percentage': 85,
                    'is_complete': True,
                    'has_profile_picture': True,
                    'privacy_level': 'public'
                }
            }
        )
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile_statistics(request):
    """
    Get profile statistics and metrics for the current user.
    """
    try:
        stats = ProfileService.get_profile_statistics(request.user)

        return Response({
            'message': 'Profile statistics retrieved successfully',
            'statistics': stats
        })

    except Exception as e:
        logger.error(f"Failed to retrieve profile statistics for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to retrieve profile statistics',
            'code': 'STATISTICS_RETRIEVAL_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='get_public_profile',
    summary='Get Public Profile',
    description="""
    Get public profile information for another user based on their privacy settings.
    
    **Privacy Filtering:**
    - Only returns information marked as 'public' by the profile owner
    - Respects individual field visibility settings
    - Filters sensitive information automatically
    - Shows different data based on viewer relationship
    
    **Visible Information (when public):**
    - Display name and basic info
    - Public bio and description
    - Profile picture
    - Public social links (website, LinkedIn, Twitter)
    - Public location information (city, country)
    
    **Hidden Information:**
    - Email address (unless set to public)
    - Phone number (unless set to public)
    - Full address details
    - Date of birth and age
    - Private profile statistics
    - Change history and audit trails
    
    **Privacy Levels:**
    - **public**: Visible to everyone including this endpoint
    - **private**: Hidden from public view
    - **friends**: Future feature for friend connections
    
    **Use Cases:**
    - User directory and discovery
    - Public profile browsing
    - Social features and connections
    - User verification and identification
    
    **Security Features:**
    - Strict privacy setting enforcement
    - No sensitive data exposure
    - User consent-based information sharing
    - Audit trail of profile views (future feature)
    
    This endpoint respects user privacy choices and only shows consented information.
    """,
    tags=['Profile'],
    parameters=[
        OpenApiParameter(
            name='user_id',
            type=OpenApiTypes.UUID,
            location=OpenApiParameter.PATH,
            description='UUID of the user whose public profile to retrieve',
            required=True
        )
    ],
    responses={
        200: OpenApiExample(
            'Public Profile Retrieved',
            value={
                'message': 'Public profile retrieved successfully',
                'profile': {
                    'display_name': 'John Doe',
                    'bio': 'Software developer passionate about technology',
                    'profile_picture_url': 'https://example.com/media/profile_pictures/user_123.jpg',
                    'website_url': 'https://johndoe.dev',
                    'linkedin_url': 'https://linkedin.com/in/johndoe',
                    'city': 'San Francisco',
                    'country': 'United States'
                }
            }
        ),
        404: OpenApiExample(
            'User Not Found',
            value={
                'error': 'User not found',
                'code': 'USER_NOT_FOUND'
            }
        ),
        404: OpenApiExample(
            'Profile Not Found',
            value={
                'error': 'Profile not found',
                'code': 'PROFILE_NOT_FOUND'
            }
        )
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_public_profile(request, user_id):
    """
    Get public profile information for another user.

    Returns only publicly visible information based on privacy settings.
    """
    try:
        from django.contrib.auth import get_user_model
        User = get_user_model()

        # Get the target user
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'error': 'User not found',
                'code': 'USER_NOT_FOUND'
            }, status=status.HTTP_404_NOT_FOUND)

        # Get the target user's profile
        try:
            profile = target_user.profile
        except:
            return Response({
                'error': 'Profile not found',
                'code': 'PROFILE_NOT_FOUND'
            }, status=status.HTTP_404_NOT_FOUND)

        # Get visible profile data
        visible_data = ProfileService.get_visible_profile_data(profile, request.user)

        return Response({
            'message': 'Public profile retrieved successfully',
            'profile': visible_data
        })

    except Exception as e:
        logger.error(f"Failed to retrieve public profile {user_id} for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Failed to retrieve public profile',
            'code': 'PUBLIC_PROFILE_RETRIEVAL_FAILED'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='delete_user_profile',
    summary='Delete Profile Data',
    description="""
    Delete/clear the user's profile data (soft delete).
    
    **What this does:**
    - Clears all personal information (bio, phone, address, etc.)
    - Deletes profile picture file from storage
    - Resets privacy settings to defaults
    - Resets communication preferences to defaults
    - Maintains profile record for data integrity
    - Creates audit trail entry for the deletion
    
    **What is preserved:**
    - User account and login credentials
    - Profile history/audit trail
    - Account creation date
    - Email verification status
    
    **Default settings after deletion:**
    - profile_visibility: 'public'
    - email_visibility: 'private'
    - phone_visibility: 'private'
    - preferred_communication: 'email'
    - marketing_emails: false
    - event_notifications: true
    - security_alerts: true
    
    This is a destructive operation that cannot be undone.
    """,
    tags=['Profile'],
    responses={
        200: OpenApiExample(
            'Success Response',
            value={
                'message': 'Profile data cleared successfully'
            }
        ),
        400: OpenApiExample(
            'Error Response',
            value={
                'error': 'Failed to delete profile',
                'code': 'DELETE_FAILED',
                'details': {'profile': ['Profile does not exist']}
            }
        )
    }
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_profile(request):
    """
    Delete/clear the user's profile data.

    This performs a soft delete by clearing all profile data while keeping the profile record.
    """
    try:
        success, message, errors = ProfileService.delete_profile(
            user=request.user,
            request=request
        )

        if success:
            logger.info(f"Profile deleted for user: {request.user.email}")

            return Response({
                'message': message
            })
        else:
            return Response({
                'error': message,
                'code': 'DELETE_FAILED',
                'details': errors
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Profile deletion error for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Profile deletion failed. Please try again.',
            'code': 'DELETE_ERROR'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema(
    operation_id='reset_profile',
    summary='Reset Profile to Defaults',
    description="""
    Reset the user's profile settings to default values while preserving personal data.
    
    **What Gets Reset:**
    - Privacy settings (profile_visibility, email_visibility, phone_visibility)
    - Communication preferences (preferred_communication, marketing_emails, etc.)
    - Notification settings back to recommended defaults
    
    **What Is Preserved:**
    - Personal information (name, bio, date of birth, etc.)
    - Contact information (phone, address)
    - Profile picture
    - Social links
    - Profile history and audit trail
    
    **Default Settings Applied:**
    - profile_visibility: 'public'
    - email_visibility: 'private'
    - phone_visibility: 'private'
    - preferred_communication: 'email'
    - marketing_emails: false
    - event_notifications: true
    - security_alerts: true (always recommended)
    
    **Use Cases:**
    - User wants to start fresh with settings
    - Privacy reset after sharing concerns
    - Simplifying complex preference configurations
    - Returning to recommended security settings
    
    **Security Features:**
    - Maintains audit trail of the reset
    - Applies secure default settings
    - Preserves important personal data
    - Logs the reset action with timestamp
    
    This is a safe operation that only affects settings, not personal data.
    """,
    tags=['Profile'],
    responses={
        200: OpenApiExample(
            'Profile Reset Success',
            value={
                'message': 'Profile reset to default settings successfully',
                'profile': {
                    'profile_visibility': 'public',
                    'email_visibility': 'private',
                    'phone_visibility': 'private',
                    'preferred_communication': 'email',
                    'marketing_emails': False,
                    'event_notifications': True,
                    'security_alerts': True
                }
            }
        ),
        400: OpenApiExample(
            'Reset Failed',
            value={
                'error': 'Failed to reset profile',
                'code': 'RESET_FAILED',
                'details': {
                    'non_field_errors': ['Profile reset operation failed']
                }
            }
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def reset_profile(request):
    """
    Reset the user's profile to default settings.

    This resets privacy and communication preferences to defaults while keeping personal data.
    """
    try:
        success, profile, errors = ProfileService.reset_profile_to_defaults(
            user=request.user,
            request=request
        )

        if success:
            serializer = UserProfileSerializer(profile, context={'request': request})

            logger.info(f"Profile reset for user: {request.user.email}")

            return Response({
                'message': 'Profile reset to default settings successfully',
                'profile': serializer.data
            })
        else:
            return Response({
                'error': 'Failed to reset profile',
                'code': 'RESET_FAILED',
                'details': errors
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"Profile reset error for user {request.user.email}: {str(e)}")
        return Response({
            'error': 'Profile reset failed. Please try again.',
            'code': 'RESET_ERROR'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)