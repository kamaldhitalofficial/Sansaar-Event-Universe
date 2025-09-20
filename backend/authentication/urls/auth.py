"""
Social authentication URLs for Google OAuth integration.

This module provides URL patterns for Google OAuth 2.0 authentication,
including login initiation, callback handling, and account linking.

URL Structure:
- /api/auth/google/login/       - Initiate Google OAuth login
- /api/auth/google/callback/    - Handle Google OAuth callback
- /api/auth/google/connect/     - Connect Google account to existing user
- /api/auth/google/disconnect/  - Disconnect Google account from user
"""
from django.urls import path
from ..views import auth as auth_views

app_name = 'social_auth'

urlpatterns = [
    # Google OAuth login initiation
    path('google/login/', auth_views.GoogleOAuthLoginView.as_view(), name='google_oauth_login'),

    # Google OAuth callback handler
    path('google/callback/', auth_views.GoogleOAuthCallbackView.as_view(), name='google_oauth_callback'),

    # Connect Google account to existing user
    path('google/connect/', auth_views.GoogleAccountConnectView.as_view(), name='google_account_connect'),

    # Disconnect Google account from user
    path('google/disconnect/', auth_views.GoogleAccountDisconnectView.as_view(), name='google_account_disconnect'),
]