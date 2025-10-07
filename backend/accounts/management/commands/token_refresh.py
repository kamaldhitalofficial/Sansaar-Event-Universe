from django.core.management.base import BaseCommand
from django.utils import timezone
from accounts.models import OAuthToken
from accounts.oauth import GoogleOAuthService
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Refresh expired OAuth tokens'
    
    def handle(self, *args, **options):
        oauth_service = GoogleOAuthService()
        
        # Get tokens that are expiring soon or expired
        expiring_tokens = OAuthToken.objects.filter(
            expires_at__lte=timezone.now() + timezone.timedelta(minutes=30),
            refresh_token__isnull=False
        )
        
        refreshed_count = 0
        failed_count = 0
        
        for token in expiring_tokens:
            try:
                new_token_data = oauth_service.refresh_token(token.refresh_token)
                
                if new_token_data:
                    token.access_token = new_token_data['access_token']
                    token.expires_at = timezone.now() + timezone.timedelta(
                        seconds=new_token_data.get('expires_in', 3600)
                    )
                    if new_token_data.get('refresh_token'):
                        token.refresh_token = new_token_data['refresh_token']
                    token.save()
                    
                    refreshed_count += 1
                    self.stdout.write(f"Refreshed token for user: {token.user.email}")
                else:
                    failed_count += 1
                    logger.error(f"Failed to refresh token for user: {token.user.email}")
                    
            except Exception as e:
                failed_count += 1
                logger.error(f"Error refreshing token for user {token.user.email}: {str(e)}")
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Token refresh completed. Refreshed: {refreshed_count}, Failed: {failed_count}"
            )
        )