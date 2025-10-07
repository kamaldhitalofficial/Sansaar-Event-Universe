from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta
import uuid

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.UUIDField(default=uuid.uuid4, editable=False)
    email_verification_sent_at = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    last_failed_login = models.DateTimeField(null=True, blank=True)

    # OAuth Fields
    google_id = models.CharField(max_length=255, null=True, blank=True, unique=True)
    profile_picture = models.URLField(null=True, blank=True)
    oauth_provider = models.CharField(max_length=50, null=True, blank=True)
    is_oauth_user = models.BooleanField(default=False)
    oauth_connected_at = models.DateTimeField(null=True, blank=True)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def is_locked(self):
        if self.locked_until and self.locked_until > timezone.now():
            return True
        if self.locked_until and self.locked_until <= timezone.now():
            # Reset after lockout expires
            self.failed_login_attempts = 0
            self.locked_until = None
            self.save()
        return False
    
    def increment_failed_login(self):
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        
        if self.failed_login_attempts >= 5:  # MAX_LOGIN_ATTEMPTS
            self.locked_until = timezone.now() + timedelta(minutes=30)
        
        self.save()
    
    def reset_failed_login(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        self.save()

    def connect_google_oauth(self, google_id, profile_picture=None):
        """Connect user account to Google OAuth"""
        self.google_id = google_id
        self.oauth_provider = 'google'
        self.is_oauth_user = True
        self.oauth_connected_at = timezone.now()
        if profile_picture:
            self.profile_picture = profile_picture
        self.save()
    
    def disconnect_oauth(self):
        """Disconnect OAuth account"""
        self.google_id = None
        self.oauth_provider = None
        self.is_oauth_user = False
        self.oauth_connected_at = None
        self.profile_picture = None
        self.save()
    
    class Meta:
        db_table = 'users'


class OAuthToken(models.Model):
    """Store OAuth tokens for users"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='oauth_token')
    access_token = models.TextField()
    refresh_token = models.TextField(null=True, blank=True)
    token_type = models.CharField(max_length=50, default='Bearer')
    expires_at = models.DateTimeField()
    scope = models.CharField(max_length=500, null=True, blank=True)
    provider = models.CharField(max_length=50, default='google')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def is_expired(self):
        return timezone.now() >= self.expires_at
    
    def is_expiring_soon(self, minutes=10):
        """Check if token expires within specified minutes"""
        return timezone.now() + timedelta(minutes=minutes) >= self.expires_at
    
    class Meta:
        db_table = 'oauth_tokens'


class OAuthState(models.Model):
    """Store OAuth state for security"""
    state = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used = models.BooleanField(default=False)
    
    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=10)
    
    class Meta:
        db_table = 'oauth_states'