"""
Session management URLs for user session tracking and management.
"""
from django.urls import path
from ..views import (
    get_user_sessions, terminate_session
)

urlpatterns = [
    # Session Management
    path('sessions/', get_user_sessions, name='user_sessions'),
    path('sessions/terminate/', terminate_session, name='terminate_session'),
]