import logging
from typing import Dict, List, Optional, Any
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from authentication.models import SocialAccount, UserProfile, PrivacySettings

User = get_user_model()
logger = logging.getLogger(__name__)


class SocialProfileSyncService:
    """Service for synchronizing profile information from social providers."""

    def __init__(self):
        self.sync_strategies = {
            'google': self._sync_google_profile
        }

    def sync_profile_from_social(self, social_account: SocialAccount, force_update: bool = False) -> Dict[str, Any]:
        """
        Sync user profile information from social account.

        Args:
            social_account: SocialAccount instance
            force_update: Whether to force update even if user has existing data

        Returns:
            Dict with sync results and updated fields
        """
        if social_account.provider not in self.sync_strategies:
            logger.warning(f"No sync strategy for provider: {social_account.provider}")
            return {'success': False, 'error': 'Unsupported provider'}

        try:
            sync_strategy = self.sync_strategies[social_account.provider]
            return sync_strategy(social_account, force_update)
        except Exception as e:
            logger.error(f"Error syncing profile from {social_account.provider}: {e}")
            return {'success': False, 'error': str(e)}

    def _sync_google_profile(self, social_account: SocialAccount, force_update: bool = False) -> Dict[str, Any]:
        """Sync profile information from Google account."""
        user = social_account.user
        updated_fields = []

        with transaction.atomic():
            # Check user's privacy settings for profile sync
            privacy_settings = self._get_privacy_settings(user)
            if not privacy_settings.allow_social_profile_sync:
                return {
                    'success': False,
                    'error': 'Profile sync disabled by user privacy settings'
                }

            # Sync basic user information
            user_updates = self._sync_user_basic_info(user, social_account, force_update)
            updated_fields.extend(user_updates)

            # Sync user profile information
            profile_updates = self._sync_user_profile_info(user, social_account, force_update)
            updated_fields.extend(profile_updates)

            # Update social account's last sync time
            social_account.updated_at = timezone.now()
            social_account.save(update_fields=['updated_at'])

            logger.info(f"Synced profile for user {user.email} from Google. Updated: {updated_fields}")

            return {
                'success': True,
                'updated_fields': updated_fields,
                'sync_timestamp': timezone.now().isoformat()
            }

    def _sync_user_basic_info(self, user: User, social_account: SocialAccount, force_update: bool) -> List[str]:
        """Sync basic user information (name, email)."""
        updated_fields = []

        # Sync first name
        if (not user.first_name or force_update) and social_account.first_name:
            user.first_name = social_account.first_name
            updated_fields.append('first_name')

        # Sync last name
        if (not user.last_name or force_update) and social_account.last_name:
            user.last_name = social_account.last_name
            updated_fields.append('last_name')

        # Save user if any fields were updated
        if updated_fields:
            user.save(update_fields=updated_fields)

        return [f'user.{field}' for field in updated_fields]

    def _sync_user_profile_info(self, user: User, social_account: SocialAccount, force_update: bool) -> List[str]:
        """Sync user profile information."""
        updated_fields = []

        try:
            profile = user.profile
        except UserProfile.DoesNotExist:
            # Create profile if it doesn't exist
            profile = UserProfile.objects.create(user=user)

        # Sync profile picture URL
        if (not profile.profile_picture or force_update) and social_account.profile_picture_url:
            # In a production system, you might want to download and store the image locally
            # For now, we'll store the URL
            profile.profile_picture_url = social_account.profile_picture_url
            updated_fields.append('profile_picture_url')

        # Sync additional information from extra_data
        extra_data = social_account.extra_data or {}

        # Sync locale/language preference
        if extra_data.get('locale') and (not profile.language_preference or force_update):
            # Map Google locale to our language codes
            locale_mapping = {
                'en': 'en',
                'es': 'es',
                'fr': 'fr',
                'de': 'de',
                # Add more mappings as needed
            }
            google_locale = extra_data['locale'][:2]  # Get language part
            if google_locale in locale_mapping:
                profile.language_preference = locale_mapping[google_locale]
                updated_fields.append('language_preference')

        # Sync timezone if available
        if extra_data.get('timezone') and (not profile.user_timezone or force_update):
            profile.user_timezone = extra_data['timezone']
            updated_fields.append('user_timezone')

        # Update profile completion status
        if updated_fields:
            profile.profile_completion_percentage = profile.calculate_completion_percentage()
            updated_fields.append('profile_completion_percentage')

        # Save profile if any fields were updated
        if updated_fields:
            profile.save(update_fields=updated_fields + ['updated_at'])

        return [f'profile.{field}' for field in updated_fields]

    def _get_privacy_settings(self, user: User) -> PrivacySettings:
        """Get or create privacy settings for user."""
        try:
            return user.privacy_settings
        except PrivacySettings.DoesNotExist:
            # Create default privacy settings
            return PrivacySettings.objects.create(
                user=user,
                allow_social_profile_sync=True  # Default to allowing sync
            )

    def get_sync_preferences(self, user: User) -> Dict[str, Any]:
        """
        Get user's profile sync preferences.

        Args:
            user: User instance

        Returns:
            Dict with sync preferences and available options
        """
        privacy_settings = self._get_privacy_settings(user)

        # Get all social accounts for the user
        social_accounts = SocialAccount.objects.filter(user=user, is_active=True)

        sync_info = {
            'sync_enabled': privacy_settings.allow_social_profile_sync,
            'connected_accounts': [],
            'last_sync_times': {},
            'available_sync_fields': self._get_available_sync_fields()
        }

        for account in social_accounts:
            sync_info['connected_accounts'].append({
                'provider': account.provider,
                'email': account.email,
                'connected_at': account.created_at.isoformat(),
                'last_login': account.last_login_at.isoformat() if account.last_login_at else None
            })
            sync_info['last_sync_times'][account.provider] = account.updated_at.isoformat()

        return sync_info

    def update_sync_preferences(self, user: User, preferences: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update user's profile sync preferences.

        Args:
            user: User instance
            preferences: Dict with preference updates

        Returns:
            Dict with update results
        """
        try:
            privacy_settings = self._get_privacy_settings(user)

            updated_fields = []

            # Update sync enabled status
            if 'sync_enabled' in preferences:
                privacy_settings.allow_social_profile_sync = preferences['sync_enabled']
                updated_fields.append('allow_social_profile_sync')

            # Save changes
            if updated_fields:
                privacy_settings.save(update_fields=updated_fields + ['updated_at'])

            logger.info(f"Updated sync preferences for user {user.email}: {updated_fields}")

            return {
                'success': True,
                'updated_fields': updated_fields
            }

        except Exception as e:
            logger.error(f"Error updating sync preferences: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _get_available_sync_fields(self) -> Dict[str, List[str]]:
        """Get available fields that can be synced from each provider."""
        return {
            'google': [
                'first_name',
                'last_name',
                'profile_picture',
                'language_preference',
                'user_timezone'
            ]
        }

    def manual_sync_from_provider(self, user: User, provider: str) -> Dict[str, Any]:
        """
        Manually trigger profile sync from a specific provider.

        Args:
            user: User instance
            provider: Social provider name

        Returns:
            Dict with sync results
        """
        try:
            social_account = SocialAccount.objects.get(
                user=user,
                provider=provider,
                is_active=True
            )

            # Force update to get latest information
            return self.sync_profile_from_social(social_account, force_update=True)

        except SocialAccount.DoesNotExist:
            return {
                'success': False,
                'error': f'No active {provider} account found for user'
            }

    def bulk_sync_profiles(self, provider: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """
        Bulk sync profiles for multiple users (admin function).

        Args:
            provider: Optional provider filter
            limit: Maximum number of accounts to sync

        Returns:
            Dict with bulk sync results
        """
        query = SocialAccount.objects.filter(is_active=True)
        if provider:
            query = query.filter(provider=provider)

        # Only sync accounts that haven't been synced recently (last 24 hours)
        cutoff_time = timezone.now() - timezone.timedelta(hours=24)
        query = query.filter(updated_at__lt=cutoff_time)

        accounts_to_sync = query[:limit]

        results = {
            'total_processed': 0,
            'successful_syncs': 0,
            'failed_syncs': 0,
            'errors': []
        }

        for account in accounts_to_sync:
            results['total_processed'] += 1

            try:
                sync_result = self.sync_profile_from_social(account)
                if sync_result.get('success'):
                    results['successful_syncs'] += 1
                else:
                    results['failed_syncs'] += 1
                    results['errors'].append({
                        'user': account.user.email,
                        'provider': account.provider,
                        'error': sync_result.get('error', 'Unknown error')
                    })
            except Exception as e:
                results['failed_syncs'] += 1
                results['errors'].append({
                    'user': account.user.email,
                    'provider': account.provider,
                    'error': str(e)
                })

        logger.info(f"Bulk sync completed: {results}")
        return results