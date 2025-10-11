from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid


class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    Adds email verification functionality and additional user fields.
    """
    # Make email field required and unique
    email = models.EmailField(unique=True, blank=False, null=False)
    
    # Email verification fields
    is_email_verified = models.BooleanField(default=False, help_text="Indicates if the user has verified their email")
    email_verification_token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    email_verification_sent_at = models.DateTimeField(null=True, blank=True)
    
    # Additional user profile fields (optional for future use)
    date_updated = models.DateTimeField(auto_now=True)
    
    # Override the USERNAME_FIELD to use email for authentication
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']
    
    class Meta:
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return f"{self.email} ({self.first_name} {self.last_name})"
    
    def save(self, *args, **kwargs):
        """
        Override save method to ensure email is lowercase
        """
        if self.email:
            self.email = self.email.lower()
        super().save(*args, **kwargs)
    
    def generate_verification_token(self):
        """
        Generate a new email verification token
        """
        self.email_verification_token = uuid.uuid4()
        self.email_verification_sent_at = timezone.now()
        self.save(update_fields=['email_verification_token', 'email_verification_sent_at'])
        return self.email_verification_token
    
    def verify_email(self):
        """
        Mark email as verified
        """
        self.is_email_verified = True
        self.email_verification_token = uuid.uuid4()  # Invalidate the token
        self.save(update_fields=['is_email_verified', 'email_verification_token'])
