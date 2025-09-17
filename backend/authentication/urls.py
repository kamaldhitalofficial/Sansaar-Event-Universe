from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # User Registration
    path('register/', views.register_user, name='register'),
    path('register/status/', views.registration_status, name='registration_status'),
    path('register/check-email/', views.check_email_availability, name='check_email_availability'),
    path('register/resend-verification/', views.resend_verification_email, name='resend_verification'),

    # User Authentication
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    path('token/refresh/', views.refresh_token, name='token_refresh'),

    # Session Management
    path('sessions/', views.get_user_sessions, name='user_sessions'),
    path('sessions/terminate/', views.terminate_session, name='terminate_session'),
]