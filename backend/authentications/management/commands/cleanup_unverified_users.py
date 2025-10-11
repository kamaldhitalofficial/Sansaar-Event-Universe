from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import timedelta
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Django management command to cleanup unverified user accounts.
    
    This command removes user accounts that:
    1. Have is_email_verified=False
    2. Were created more than 12 hours ago
    3. Have not been activated
    
    Usage:
        python manage.py cleanup_unverified_users
        
    For scheduling with cron (run every hour):
        0 * * * * cd /path/to/project && python manage.py cleanup_unverified_users
    """
    
    help = 'Remove unverified user accounts older than 12 hours'
    
    def add_arguments(self, parser):
        """Add command line arguments"""
        parser.add_argument(
            '--hours',
            type=int,
            default=12,
            help='Number of hours after which unverified accounts are deleted (default: 12)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output'
        )
    
    def handle(self, *args, **options):
        """Main command execution"""
        hours = options['hours']
        dry_run = options['dry_run']
        verbose = options['verbose']
        
        # Calculate cutoff time
        cutoff_time = timezone.now() - timedelta(hours=hours)
        
        if verbose:
            self.stdout.write(
                self.style.SUCCESS(f'Looking for unverified users created before: {cutoff_time}')
            )
        
        # Find unverified users older than the cutoff time
        unverified_users = User.objects.filter(
            is_email_verified=False,
            date_joined__lt=cutoff_time
        )
        
        user_count = unverified_users.count()
        
        if user_count == 0:
            if verbose:
                self.stdout.write(
                    self.style.SUCCESS('No unverified users found to cleanup.')
                )
            return
        
        if verbose or dry_run:
            self.stdout.write(
                self.style.WARNING(f'Found {user_count} unverified user(s) to cleanup:')
            )
            
            for user in unverified_users:
                time_since_creation = timezone.now() - user.date_joined
                hours_old = int(time_since_creation.total_seconds() / 3600)
                
                self.stdout.write(
                    f'  - {user.email} (created {hours_old}h ago, joined: {user.date_joined})'
                )
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN: No users were actually deleted.')
            )
            return
        
        # Delete unverified users
        try:
            deleted_users = []
            for user in unverified_users:
                deleted_users.append({
                    'email': user.email,
                    'username': user.username,
                    'date_joined': user.date_joined
                })
            
            # Perform the deletion
            deleted_count, deleted_details = unverified_users.delete()
            
            # Log the cleanup activity
            logger.info(f'Cleaned up {deleted_count} unverified user accounts older than {hours} hours')
            
            if verbose:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully deleted {deleted_count} unverified user account(s).')
                )
                
                for user_info in deleted_users:
                    self.stdout.write(f'  ✓ Deleted: {user_info["email"]}')
            else:
                self.stdout.write(
                    self.style.SUCCESS(f'Cleanup completed: {deleted_count} unverified accounts deleted.')
                )
                
        except Exception as e:
            logger.error(f'Error during user cleanup: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Error occurred during cleanup: {str(e)}')
            )
            raise e