"""
Management command to set up Google OAuth 2.0 application.

This command creates or updates the Google OAuth application
configuration in the database using the credentials from
environment variables.
"""
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from allauth.socialaccount.models import SocialApp
from django.contrib.sites.models import Site


class Command(BaseCommand):
    help = 'Set up Google OAuth 2.0 application configuration'

    def add_arguments(self, parser):
        parser.add_argument(
            '--client-id',
            type=str,
            help='Google OAuth 2.0 Client ID (overrides environment variable)',
        )
        parser.add_argument(
            '--client-secret',
            type=str,
            help='Google OAuth 2.0 Client Secret (overrides environment variable)',
        )
        parser.add_argument(
            '--update',
            action='store_true',
            help='Update existing Google OAuth app if it exists',
        )

    def handle(self, *args, **options):
        # Get credentials from command line or environment
        client_id = options.get('client_id') or getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {}).get('google', {}).get(
            'APP', {}).get('client_id')
        client_secret = options.get('client_secret') or getattr(settings, 'SOCIALACCOUNT_PROVIDERS', {}).get('google',
                                                                                                             {}).get(
            'APP', {}).get('secret')

        if not client_id or not client_secret:
            raise CommandError(
                'Google OAuth credentials not found. Please set GOOGLE_OAUTH2_CLIENT_ID '
                'and GOOGLE_OAUTH2_CLIENT_SECRET environment variables or use '
                '--client-id and --client-secret arguments.'
            )

        # Get or create the default site
        site, created = Site.objects.get_or_create(
            pk=settings.SITE_ID,
            defaults={
                'domain': 'localhost:8000',
                'name': 'Sansaar Event Universe'
            }
        )

        if created:
            self.stdout.write(
                self.style.SUCCESS(f'Created default site: {site.domain}')
            )

        # Check if Google OAuth app already exists
        try:
            google_app = SocialApp.objects.get(provider='google')
            if not options['update']:
                self.stdout.write(
                    self.style.WARNING(
                        'Google OAuth app already exists. Use --update to modify it.'
                    )
                )
                return

            # Update existing app
            google_app.client_id = client_id
            google_app.secret = client_secret
            google_app.save()

            self.stdout.write(
                self.style.SUCCESS('Updated existing Google OAuth app')
            )

        except SocialApp.DoesNotExist:
            # Create new Google OAuth app
            google_app = SocialApp.objects.create(
                provider='google',
                name='Google',
                client_id=client_id,
                secret=client_secret,
            )

            self.stdout.write(
                self.style.SUCCESS('Created new Google OAuth app')
            )

        # Add the app to the current site
        google_app.sites.add(site)

        self.stdout.write(
            self.style.SUCCESS(
                f'Google OAuth app configured successfully for site: {site.domain}'
            )
        )

        # Display configuration info
        self.stdout.write('\nGoogle OAuth Configuration:')
        self.stdout.write(f'  Provider: {google_app.provider}')
        self.stdout.write(f'  Client ID: {google_app.client_id}')
        self.stdout.write(f'  Secret: {"*" * len(google_app.secret)}')
        self.stdout.write(f'  Sites: {", ".join([s.domain for s in google_app.sites.all()])}')

        self.stdout.write('\nNext steps:')
        self.stdout.write('1. Update your Google OAuth 2.0 credentials in the Google Cloud Console')
        self.stdout.write('2. Add authorized redirect URIs:')
        self.stdout.write(f'   - http://{site.domain}/accounts/google/login/callback/')
        self.stdout.write(f'   - http://{site.domain}/api/auth/google/callback/')
        self.stdout.write('3. Test the OAuth flow by visiting /api/auth/google/login/')