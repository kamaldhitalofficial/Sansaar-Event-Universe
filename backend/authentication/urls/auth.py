"""
Social authentication URLs for Google OAuth integration.

This module provides URL patterns for Google OAuth 2.0 authentication,
including login initiation, callback handling, and account linking.

URL Structure:
- /api/auth/google/login/       - Initiate Google OAuth login
- /api/auth/google/callback/    - Handle Google OAuth callback
- /api/auth/google/link/        - Link Google account to existing user
- /api/auth/google/unlink/      - Unlink Google account from user
- /api/auth/google/status/      - Get Google authentication status
"""
from django.urls import path
from authentication.views.google_auth_views import (
    GoogleOAuthCallbackView,
    initiate_google_auth,
    initiate_account_linking,
    google_auth_status,
    unlink_google_account
)

app_name = 'social_auth'

urlpatterns = [
    # Google OAuth login initiation
    path('google/login/', initiate_google_auth, name='google_oauth_login'),

    # Google OAuth callback handler
    path('google/callback/', GoogleOAuthCallbackView.as_view(), name='google_oauth_callback'),

    # Link Google account to existing user
    path('google/link/', initiate_account_linking, name='google_account_link'),

    # Unlink Google account from user
    path('google/unlink/', unlink_google_account, name='google_account_unlink'),

    # Get Google authentication status
    path('google/status/', google_auth_status, name='google_auth_status'),
]