"""
Registration URLs for user registration and email verification.
"""
from django.urls import path
from ..views import (
    register_user, registration_status, check_email_availability,
    verify_email, resend_verification_email
)

urlpatterns = [
    # User Registration
    path('register/', register_user, name='register'),
    path('register/status/', registration_status, name='registration_status'),
    path('register/check-email/', check_email_availability, name='check_email_availability'),
    path('register/resend-verification/', resend_verification_email, name='resend_verification'),

    # Email Verification
    path('verify-email/<uuid:token>/', verify_email, name='verify_email'),
]