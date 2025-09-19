from django.db import models
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import date
import uuid
import os
from .user import User


def profile_picture_upload_path(instance, filename):
    """Generate upload path for profile pictures."""
    # Get file extension
    ext = filename.split('.')[-1].lower()
    # Generate new filename with user ID and timestamp
    new_filename = f"{instance.user.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
    return f"profile_pictures/{new_filename}"


class UserProfile(models.Model):
    """Extended user profile model with personal information and preferences."""

    # Gender choices
    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
        ('P', 'Prefer not to say'),
    ]

    # Visibility choices for profile fields
    VISIBILITY_CHOICES = [
        ('public', 'Public'),
        ('private', 'Private'),
        ('friends', 'Friends Only'),
    ]

    # Communication preferences
    COMMUNICATION_CHOICES = [
        ('email', 'Email'),
        ('sms', 'SMS'),
        ('push', 'Push Notifications'),
        ('none', 'No Communications'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')

    # Personal Information
    bio = models.TextField(
        max_length=500,
        blank=True,
        help_text='Brief description about yourself (max 500 characters)'
    )
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(
        max_length=1,
        choices=GENDER_CHOICES,
        blank=True,
        help_text='Gender identity'
    )

    # Contact Information
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        validators=[
            RegexValidator(
                regex=r'^\+?1?\d{9,15}$',
                message='Phone number must be entered in the format: "+999999999". Up to 15 digits allowed.'
            )
        ],
        help_text='Phone number in international format'
    )

    # Address Information
    street_address = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100, blank=True)
    state_province = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, blank=True)

    # Profile Picture
    profile_picture = models.ImageField(
        upload_to=profile_picture_upload_path,
        null=True,
        blank=True,
        help_text='Profile picture (max 5MB, JPG/PNG only)'
    )

    # Social Links
    website_url = models.URLField(blank=True, help_text='Personal or professional website')
    linkedin_url = models.URLField(blank=True, help_text='LinkedIn profile URL')
    twitter_handle = models.CharField(
        max_length=50,
        blank=True,
        validators=[
            RegexValidator(
                regex=r'^@?[A-Za-z0-9_]{1,15}$',
                message='Twitter handle must be 1-15 characters, letters, numbers, and underscores only'
            )
        ],
        help_text='Twitter handle (with or without @)'
    )

    # Privacy Settings
    profile_visibility = models.CharField(
        max_length=10,
        choices=VISIBILITY_CHOICES,
        default='public',
        help_text='Who can see your profile information'
    )
    email_visibility = models.CharField(
        max_length=10,
        choices=VISIBILITY_CHOICES,
        default='private',
        help_text='Who can see your email address'
    )
    phone_visibility = models.CharField(
        max_length=10,
        choices=VISIBILITY_CHOICES,
        default='private',
        help_text='Who can see your phone number'
    )

    # Communication Preferences
    preferred_communication = models.CharField(
        max_length=10,
        choices=COMMUNICATION_CHOICES,
        default='email',
        help_text='Preferred method of communication'
    )
    marketing_emails = models.BooleanField(
        default=False,
        help_text='Receive marketing and promotional emails'
    )
    event_notifications = models.BooleanField(
        default=True,
        help_text='Receive notifications about events'
    )
    security_alerts = models.BooleanField(
        default=True,
        help_text='Receive security-related alerts'
    )

    # Profile Completion Tracking
    profile_completion_percentage = models.PositiveIntegerField(
        default=0,
        help_text='Percentage of profile completion (0-100)'
    )

    # Timestamps
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    # Audit Fields
    last_updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='profile_updates',
        help_text='User who last updated this profile'
    )

    class Meta:
        db_table = 'auth_user_profile'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['profile_visibility']),
            models.Index(fields=['created_at']),
            models.Index(fields=['updated_at']),
            models.Index(fields=['profile_completion_percentage']),
        ]

    def __str__(self):
        """Return string representation of the user profile."""
        full_name = self.get_display_name()
        completion = f"{self.profile_completion_percentage}%"
        return f"{full_name} - Profile ({completion} complete)"

    def clean(self):
        """Validate the user profile model."""
        super().clean()

        # Validate date of birth
        if self.date_of_birth:
            if self.date_of_birth > date.today():
                raise ValidationError({'date_of_birth': 'Date of birth cannot be in the future.'})

            # Check if user is at least 13 years old (COPPA compliance)
            age = (date.today() - self.date_of_birth).days / 365.25
            if age < 13:
                raise ValidationError({'date_of_birth': 'Users must be at least 13 years old.'})

        # Validate profile picture size (5MB limit)
        if self.profile_picture:
            if self.profile_picture.size > 5 * 1024 * 1024:  # 5MB
                raise ValidationError({'profile_picture': 'Profile picture must be smaller than 5MB.'})

            # Validate file extension
            allowed_extensions = ['.jpg', '.jpeg', '.png']
            ext = os.path.splitext(self.profile_picture.name)[1].lower()
            if ext not in allowed_extensions:
                raise ValidationError({'profile_picture': 'Only JPG and PNG files are allowed.'})

        # Clean Twitter handle
        if self.twitter_handle and not self.twitter_handle.startswith('@'):
            self.twitter_handle = f"@{self.twitter_handle}"

    def save(self, *args, **kwargs):
        """Override save to update profile completion percentage."""
        # Calculate profile completion before saving
        self.profile_completion_percentage = self.calculate_completion_percentage()

        # Set last_updated_by if provided in kwargs
        if 'updated_by' in kwargs:
            self.last_updated_by = kwargs.pop('updated_by')

        super().save(*args, **kwargs)

    def get_display_name(self):
        """Get the best available display name for the user."""
        if self.user.first_name and self.user.last_name:
            return f"{self.user.first_name} {self.user.last_name}"
        elif self.user.first_name:
            return self.user.first_name
        else:
            return self.user.email.split('@')[0]  # Use email username part

    def get_age(self):
        """Calculate and return user's age."""
        if not self.date_of_birth:
            return None

        today = date.today()
        age = today.year - self.date_of_birth.year

        # Adjust if birthday hasn't occurred this year
        if today.month < self.date_of_birth.month or \
                (today.month == self.date_of_birth.month and today.day < self.date_of_birth.day):
            age -= 1

        return age

    def calculate_completion_percentage(self):
        """Calculate profile completion percentage based on filled fields."""
        # Define fields and their weights for completion calculation
        fields_weights = {
            'bio': 10,
            'date_of_birth': 10,
            'gender': 5,
            'phone_number': 10,
            'street_address': 8,
            'city': 8,
            'state_province': 7,
            'postal_code': 7,
            'country': 8,
            'profile_picture': 15,
            'website_url': 5,
            'linkedin_url': 5,
            'twitter_handle': 2,
        }

        # Always include basic user fields
        total_possible = 100
        current_score = 0

        # Add points for basic user information (always required)
        if self.user.first_name:
            current_score += 10
        if self.user.last_name:
            current_score += 10

        # Add points for profile fields
        for field, weight in fields_weights.items():
            field_value = getattr(self, field)
            if field_value:
                if isinstance(field_value, str) and field_value.strip():
                    current_score += weight
                elif field_value:  # For non-string fields like ImageField
                    current_score += weight

        # Ensure percentage doesn't exceed 100
        return min(current_score, 100)

    def get_completion_suggestions(self):
        """Get suggestions for improving profile completion."""
        suggestions = []

        # Check basic user information
        if not self.user.first_name:
            suggestions.append("Add your first name")
        if not self.user.last_name:
            suggestions.append("Add your last name")

        # Check profile fields
        if not self.bio:
            suggestions.append("Write a brief bio about yourself")
        if not self.date_of_birth:
            suggestions.append("Add your date of birth")
        if not self.profile_picture:
            suggestions.append("Upload a profile picture")
        if not self.phone_number:
            suggestions.append("Add your phone number")
        if not self.city or not self.country:
            suggestions.append("Add your location (city and country)")

        return suggestions

    def is_profile_complete(self, threshold=80):
        """Check if profile is considered complete based on threshold."""
        return self.profile_completion_percentage >= threshold

    def get_visible_fields(self, viewer_user=None):
        """
        Get fields that are visible to the given viewer based on privacy settings.

        Args:
            viewer_user: User who is viewing the profile (None for anonymous)

        Returns:
            dict: Dictionary of visible fields and their values
        """
        visible_fields = {}

        # Always visible fields
        visible_fields.update({
            'display_name': self.get_display_name(),
            'profile_picture': self.profile_picture.url if self.profile_picture else None,
        })

        # Check profile visibility
        if self.profile_visibility == 'public' or \
                (viewer_user and viewer_user == self.user):
            # Add public profile fields
            visible_fields.update({
                'bio': self.bio,
                'website_url': self.website_url,
                'linkedin_url': self.linkedin_url,
                'twitter_handle': self.twitter_handle,
                'city': self.city,
                'country': self.country,
            })

        # Check email visibility
        if self.email_visibility == 'public' or \
                (viewer_user and viewer_user == self.user):
            visible_fields['email'] = self.user.email

        # Check phone visibility
        if self.phone_visibility == 'public' or \
                (viewer_user and viewer_user == self.user):
            visible_fields['phone_number'] = self.phone_number

        # Owner always sees everything
        if viewer_user and viewer_user == self.user:
            visible_fields.update({
                'date_of_birth': self.date_of_birth,
                'gender': self.get_gender_display(),
                'street_address': self.street_address,
                'state_province': self.state_province,
                'postal_code': self.postal_code,
                'age': self.get_age(),
                'profile_completion': self.profile_completion_percentage,
            })

        return visible_fields

    @classmethod
    def create_profile(cls, user, **profile_data):
        """
        Create a user profile with the given data.

        Args:
            user: User instance
            **profile_data: Profile field data

        Returns:
            UserProfile instance
        """
        profile = cls.objects.create(user=user, **profile_data)
        return profile

    def update_profile(self, updated_by=None, **profile_data):
        """
        Update profile with the given data and track who made the update.

        Args:
            updated_by: User who is making the update
            **profile_data: Profile field data to update
        """
        for field, value in profile_data.items():
            if hasattr(self, field):
                setattr(self, field, value)

        if updated_by:
            self.last_updated_by = updated_by

        self.save()


class UserProfileHistory(models.Model):
    """Model to track changes to user profiles for audit purposes."""

    ACTION_CHOICES = [
        ('create', 'Profile Created'),
        ('update', 'Profile Updated'),
        ('picture_change', 'Profile Picture Changed'),
        ('privacy_change', 'Privacy Settings Changed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='history')

    # Change tracking
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    changed_fields = models.JSONField(default=dict, help_text='Fields that were changed')
    old_values = models.JSONField(default=dict, help_text='Previous values of changed fields')
    new_values = models.JSONField(default=dict, help_text='New values of changed fields')

    # Audit information
    changed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    changed_at = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    # Additional context
    reason = models.CharField(max_length=255, blank=True, help_text='Reason for the change')

    class Meta:
        db_table = 'auth_user_profile_history'
        verbose_name = 'User Profile History'
        verbose_name_plural = 'User Profile Histories'
        ordering = ['-changed_at']
        indexes = [
            models.Index(fields=['profile', '-changed_at']),
            models.Index(fields=['changed_by']),
            models.Index(fields=['action']),
            models.Index(fields=['changed_at']),
        ]

    def __str__(self):
        return f"{self.profile.user.email} - {self.get_action_display()} - {self.changed_at.strftime('%Y-%m-%d %H:%M:%S')}"

    @classmethod
    def log_change(cls, profile, action, changed_fields=None, old_values=None,
                   new_values=None, changed_by=None, request=None, reason=''):
        """
        Log a profile change for audit purposes.

        Args:
            profile: UserProfile instance
            action: Type of action performed
            changed_fields: List of field names that changed
            old_values: Dictionary of old field values
            new_values: Dictionary of new field values
            changed_by: User who made the change
            request: Django request object for tracking
            reason: Reason for the change
        """
        from ..utils.device_detection import get_client_ip

        ip_address = get_client_ip(request) if request else None
        user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''

        history_entry = cls.objects.create(
            profile=profile,
            action=action,
            changed_fields=changed_fields or [],
            old_values=old_values or {},
            new_values=new_values or {},
            changed_by=changed_by,
            ip_address=ip_address,
            user_agent=user_agent,
            reason=reason
        )

        return history_entry