"""
Profile service for managing user profile operations.
"""
import logging
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from ..models.profile import UserProfile, UserProfileHistory
from ..models.user import User

logger = logging.getLogger(__name__)


class ProfileService:
    """
    Service class for user profile management operations.
    """

    @staticmethod
    def get_or_create_profile(user):
        """
        Get existing profile or create a new one for the user.

        Args:
            user: User instance

        Returns:
            UserProfile instance
        """
        try:
            profile = user.profile
        except UserProfile.DoesNotExist:
            # Create profile if it doesn't exist
            profile = UserProfile.objects.create(user=user)

            # Log profile creation
            UserProfileHistory.log_change(
                profile=profile,
                action='create',
                changed_fields=['user'],
                new_values={'user': user.email},
                changed_by=user,
                reason='Profile auto-created'
            )

            logger.info(f"Profile created for user: {user.email}")

        return profile

    @staticmethod
    def update_profile(user, profile_data, request=None):
        """
        Update user profile with validation and change tracking.

        Args:
            user: User instance
            profile_data: Dictionary of profile fields to update
            request: Django request object for audit tracking

        Returns:
            tuple: (success, profile, errors)
        """
        try:
            with transaction.atomic():
                profile = ProfileService.get_or_create_profile(user)

                # Track changes for audit
                old_values = {}
                new_values = {}
                changed_fields = []

                for field, new_value in profile_data.items():
                    if hasattr(profile, field):
                        old_value = getattr(profile, field)

                        # Handle file fields specially
                        if hasattr(old_value, 'name'):
                            old_value = old_value.name if old_value else None
                        if hasattr(new_value, 'name'):
                            new_value = new_value.name if new_value else None

                        if old_value != new_value:
                            changed_fields.append(field)
                            old_values[field] = str(old_value) if old_value is not None else None
                            new_values[field] = str(new_value) if new_value is not None else None

                            # Update the field
                            setattr(profile, field, profile_data[field])

                # Validate and save
                profile.full_clean()
                profile.save(updated_by=user)

                # Log changes if any
                if changed_fields:
                    # Determine action type
                    action = 'update'
                    if 'profile_picture' in changed_fields:
                        action = 'picture_change'
                    elif any(field in changed_fields for field in ['profile_visibility', 'email_visibility', 'phone_visibility']):
                        action = 'privacy_change'

                    UserProfileHistory.log_change(
                        profile=profile,
                        action=action,
                        changed_fields=changed_fields,
                        old_values=old_values,
                        new_values=new_values,
                        changed_by=user,
                        request=request,
                        reason='Profile update via service'
                    )

                logger.info(f"Profile updated for user: {user.email}, fields: {changed_fields}")
                return True, profile, None

        except ValidationError as e:
            logger.warning(f"Profile validation failed for user {user.email}: {e}")
            return False, None, e.message_dict
        except Exception as e:
            logger.error(f"Profile update failed for user {user.email}: {str(e)}")
            return False, None, {'non_field_errors': [str(e)]}

    @staticmethod
    def update_profile_picture(user, picture_file, request=None):
        """
        Update user profile picture with validation.

        Args:
            user: User instance
            picture_file: Uploaded image file
            request: Django request object for audit tracking

        Returns:
            tuple: (success, profile, errors)
        """
        return ProfileService.update_profile(
            user=user,
            profile_data={'profile_picture': picture_file},
            request=request
        )

    @staticmethod
    def update_privacy_settings(user, privacy_data, request=None):
        """
        Update user privacy settings with validation and tracking.

        Args:
            user: User instance
            privacy_data: Dictionary of privacy settings
            request: Django request object for audit tracking

        Returns:
            tuple: (success, profile, errors)
        """
        # Filter only privacy-related fields
        privacy_fields = ['profile_visibility', 'email_visibility', 'phone_visibility']
        filtered_data = {k: v for k, v in privacy_data.items() if k in privacy_fields}

        return ProfileService.update_profile(
            user=user,
            profile_data=filtered_data,
            request=request
        )

    @staticmethod
    def get_profile_completion_status(user):
        """
        Get profile completion status and suggestions.

        Args:
            user: User instance

        Returns:
            dict: Completion status information
        """
        profile = ProfileService.get_or_create_profile(user)

        return {
            'completion_percentage': profile.profile_completion_percentage,
            'is_complete': profile.is_profile_complete(),
            'suggestions': profile.get_completion_suggestions(),
            'missing_fields': ProfileService._get_missing_fields(profile)
        }

    @staticmethod
    def get_profile_history(user, limit=50):
        """
        Get profile change history for the user.

        Args:
            user: User instance
            limit: Maximum number of history entries to return

        Returns:
            QuerySet: Profile history entries
        """
        try:
            profile = user.profile
            return profile.history.all()[:limit]
        except UserProfile.DoesNotExist:
            return UserProfileHistory.objects.none()

    @staticmethod
    def get_visible_profile_data(profile, viewer_user=None):
        """
        Get profile data visible to the viewer based on privacy settings.

        Args:
            profile: UserProfile instance
            viewer_user: User who is viewing the profile (None for anonymous)

        Returns:
            dict: Visible profile data
        """
        return profile.get_visible_fields(viewer_user)

    @staticmethod
    def delete_profile_picture(user, request=None):
        """
        Delete user's profile picture.

        Args:
            user: User instance
            request: Django request object for audit tracking

        Returns:
            tuple: (success, profile, errors)
        """
        try:
            profile = user.profile

            if profile.profile_picture:
                old_picture = profile.profile_picture.name
                profile.profile_picture.delete(save=False)
                profile.profile_picture = None
                profile.save(updated_by=user)

                # Log the change
                UserProfileHistory.log_change(
                    profile=profile,
                    action='picture_change',
                    changed_fields=['profile_picture'],
                    old_values={'profile_picture': old_picture},
                    new_values={'profile_picture': None},
                    changed_by=user,
                    request=request,
                    reason='Profile picture deleted'
                )

                logger.info(f"Profile picture deleted for user: {user.email}")
                return True, profile, None
            else:
                return False, profile, {'profile_picture': ['No profile picture to delete']}

        except UserProfile.DoesNotExist:
            return False, None, {'profile': ['Profile not found']}
        except Exception as e:
            logger.error(f"Failed to delete profile picture for user {user.email}: {str(e)}")
            return False, None, {'non_field_errors': [str(e)]}

    @staticmethod
    def validate_profile_data(profile_data):
        """
        Validate profile data before updating.

        Args:
            profile_data: Dictionary of profile fields

        Returns:
            tuple: (is_valid, errors)
        """
        try:
            # Create a temporary profile instance for validation
            temp_profile = UserProfile(**profile_data)
            temp_profile.full_clean()
            return True, None
        except ValidationError as e:
            return False, e.message_dict

    @staticmethod
    def _get_missing_fields(profile):
        """
        Get list of missing important fields for profile completion.

        Args:
            profile: UserProfile instance

        Returns:
            list: Missing field information
        """
        missing = []

        # Check important fields
        important_fields = {
            'bio': 'Bio/Description',
            'date_of_birth': 'Date of Birth',
            'phone_number': 'Phone Number',
            'city': 'City',
            'country': 'Country',
            'profile_picture': 'Profile Picture'
        }

        for field, display_name in important_fields.items():
            value = getattr(profile, field)
            if not value or (isinstance(value, str) and not value.strip()):
                missing.append({
                    'field': field,
                    'display_name': display_name
                })

        # Check user fields
        if not profile.user.first_name:
            missing.append({
                'field': 'first_name',
                'display_name': 'First Name'
            })

        if not profile.user.last_name:
            missing.append({
                'field': 'last_name',
                'display_name': 'Last Name'
            })

        return missing

    @staticmethod
    def bulk_update_communication_preferences(user, preferences, request=None):
        """
        Update multiple communication preferences at once.

        Args:
            user: User instance
            preferences: Dictionary of communication preferences
            request: Django request object for audit tracking

        Returns:
            tuple: (success, profile, errors)
        """
        # Filter only communication-related fields
        comm_fields = [
            'preferred_communication', 'marketing_emails',
            'event_notifications', 'security_alerts'
        ]
        filtered_data = {k: v for k, v in preferences.items() if k in comm_fields}

        return ProfileService.update_profile(
            user=user,
            profile_data=filtered_data,
            request=request
        )

    @staticmethod
    def get_profile_statistics(user):
        """
        Get profile statistics and metrics.

        Args:
            user: User instance

        Returns:
            dict: Profile statistics
        """
        try:
            profile = user.profile
            history_count = profile.history.count()
            last_update = profile.updated_at

            return {
                'profile_created': profile.created_at,
                'last_updated': last_update,
                'total_updates': history_count,
                'completion_percentage': profile.profile_completion_percentage,
                'is_complete': profile.is_profile_complete(),
                'has_profile_picture': bool(profile.profile_picture),
                'privacy_level': profile.profile_visibility
            }
        except UserProfile.DoesNotExist:
            return {
                'profile_created': None,
                'last_updated': None,
                'total_updates': 0,
                'completion_percentage': 0,
                'is_complete': False,
                'has_profile_picture': False,
                'privacy_level': 'private'
            }

    @staticmethod
    def delete_profile(user, request=None):
        """
        Delete user's profile completely (soft delete by clearing data).

        Args:
            user: User instance
            request: Django request object for audit tracking

        Returns:
            tuple: (success, message, errors)
        """
        try:
            with transaction.atomic():
                profile = user.profile

                # Store old values for history
                old_values = {
                    'bio': profile.bio,
                    'date_of_birth': str(profile.date_of_birth) if profile.date_of_birth else None,
                    'gender': profile.gender,
                    'phone_number': profile.phone_number,
                    'street_address': profile.street_address,
                    'city': profile.city,
                    'state_province': profile.state_province,
                    'postal_code': profile.postal_code,
                    'country': profile.country,
                    'profile_picture': profile.profile_picture.name if profile.profile_picture else None,
                    'website_url': profile.website_url,
                    'linkedin_url': profile.linkedin_url,
                    'twitter_handle': profile.twitter_handle,
                }

                # Delete profile picture file if exists
                if profile.profile_picture:
                    profile.profile_picture.delete(save=False)

                # Clear all profile data (soft delete)
                profile.bio = ''
                profile.date_of_birth = None
                profile.gender = ''
                profile.phone_number = ''
                profile.street_address = ''
                profile.city = ''
                profile.state_province = ''
                profile.postal_code = ''
                profile.country = ''
                profile.profile_picture = None
                profile.website_url = ''
                profile.linkedin_url = ''
                profile.twitter_handle = ''

                # Reset privacy settings to default
                profile.profile_visibility = 'public'
                profile.email_visibility = 'private'
                profile.phone_visibility = 'private'

                # Reset communication preferences to default
                profile.preferred_communication = 'email'
                profile.marketing_emails = False
                profile.event_notifications = True
                profile.security_alerts = True

                profile.save(updated_by=user)

                # Log the profile deletion
                UserProfileHistory.log_change(
                    profile=profile,
                    action='update',
                    changed_fields=list(old_values.keys()),
                    old_values=old_values,
                    new_values={key: '' for key in old_values.keys()},
                    changed_by=user,
                    request=request,
                    reason='Profile data cleared/deleted by user'
                )

                logger.info(f"Profile data cleared for user: {user.email}")
                return True, 'Profile data cleared successfully', None

        except UserProfile.DoesNotExist:
            return False, 'Profile not found', {'profile': ['Profile does not exist']}
        except Exception as e:
            logger.error(f"Failed to delete profile for user {user.email}: {str(e)}")
            return False, 'Failed to delete profile', {'non_field_errors': [str(e)]}

    @staticmethod
    def reset_profile_to_defaults(user, request=None):
        """
        Reset profile to default settings while keeping basic info.

        Args:
            user: User instance
            request: Django request object for audit tracking

        Returns:
            tuple: (success, profile, errors)
        """
        try:
            with transaction.atomic():
                profile = ProfileService.get_or_create_profile(user)

                # Reset privacy settings to defaults
                profile.profile_visibility = 'public'
                profile.email_visibility = 'private'
                profile.phone_visibility = 'private'

                # Reset communication preferences to defaults
                profile.preferred_communication = 'email'
                profile.marketing_emails = False
                profile.event_notifications = True
                profile.security_alerts = True

                profile.save(updated_by=user)

                # Log the reset
                UserProfileHistory.log_change(
                    profile=profile,
                    action='update',
                    changed_fields=['privacy_settings', 'communication_preferences'],
                    old_values={'action': 'reset_to_defaults'},
                    new_values={'action': 'reset_completed'},
                    changed_by=user,
                    request=request,
                    reason='Profile reset to default settings'
                )

                logger.info(f"Profile reset to defaults for user: {user.email}")
                return True, profile, None

        except Exception as e:
            logger.error(f"Failed to reset profile for user {user.email}: {str(e)}")
            return False, None, {'non_field_errors': [str(e)]}