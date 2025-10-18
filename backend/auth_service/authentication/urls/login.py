"""
Login URLs for user login, logout, and token management.
"""
from django.urls import path
from ..views import (
    login_user, logout_user, refresh_token
)

urlpatterns = [
    # User Authentication
    path('login/', login_user, name='login'),
    path('logout/', logout_user, name='logout'),
    path('token/refresh/', refresh_token, name='token_refresh'),
]