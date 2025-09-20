"""
Main authentication URLs with organized endpoint groupings.

This file organizes all authentication-related endpoints into logical groups:
- Registration: User registration and email verification
- Login: User login, logout, and token management
- Sessions: Session tracking and management
- Privacy: Privacy settings and consent management
- Profile: User profile management (included separately in main URLs)

URL Structure:
- /api/auth/register/          - User registration endpoints
- /api/auth/login/             - User login endpoints
- /api/auth/logout/            - User logout
- /api/auth/sessions/          - Session management
- /api/auth/privacy/           - Privacy settings and consent management
- /api/me/                     - Profile management (direct under /api/)
"""
from django.urls import path, include

app_name = 'authentication'

urlpatterns = [
    # Registration endpoints (/api/auth/register/, /api/auth/verify-email/, etc.)
    path('', include('authentication.urls.registration')),

    # Login endpoints (/api/auth/login/, /api/auth/logout/, /api/auth/token/refresh/)
    path('', include('authentication.urls.login')),

    # Session management endpoints (/api/auth/sessions/)
    path('', include('authentication.urls.session')),

    # Privacy management endpoints (/api/auth/privacy/)
    path('privacy/', include('authentication.urls.privacy')),
]