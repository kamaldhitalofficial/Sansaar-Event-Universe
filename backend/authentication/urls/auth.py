"""
Main authentication URLs combining registration, authentication, and session management.
"""
from django.urls import path, include

app_name = 'auth'

urlpatterns = [
    # Registration endpoints
    path('', include('authentication.urls.registration')),

    # Authentication endpoints
    path('', include('authentication.urls.login')),

    # Session management endpoints
    path('', include('authentication.urls.session')),
]