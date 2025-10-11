from django.urls import path
from . import views

app_name = 'authentications'

urlpatterns = [
    # User Registration
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    
    # Email Verification
    path('verify-email/', views.verify_email, name='verify_email'),
    
    # Resend Email Verification
    path('resend-verification/', views.resend_verification_email, name='resend_verification'),
]