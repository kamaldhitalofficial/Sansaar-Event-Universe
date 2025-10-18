"""
Profile serializers for user profile management.
"""
import os
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile, TemporaryUploadedFile
from rest_framework import serializers
from PIL import Image
from ..models.profile import UserProfile, UserProfileHistory


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile with comprehensive validation.
    """
    # Read-only computed fields
    display_name = serializers.CharField(read_only=True)
    age = serializers.IntegerField(read_only=True)
    profile_completion_percentage = serializers.IntegerField(read_only=True)
    completion_suggestions = serializers.ListField(read_only=True)

    # User fields (read-only for profile context)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)

    # Profile picture URL
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            # User info
            'email', 'first_name', 'last_name', 'display_name',

            # Personal information
            'bio', 'date_of_birth', 'gender', 'age',

            # Contact information
            'phone_number',

            # Address information
            'street_address', 'city', 'state_province', 'postal_code', 'country',

            # Profile picture
            'profile_picture', 'profile_picture_url',

            # Social links
            'website_url', 'linkedin_url', 'twitter_handle',

            # Privacy settings
            'profile_visibility', 'email_visibility', 'phone_visibility',

            # Communication preferences
            'preferred_communication', 'marketing_emails', 'event_notifications', 'security_alerts',

            # Profile completion
            'profile_completion_percentage', 'completion_suggestions',

            # Timestamps
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_profile_picture_url(self, obj):
        """Get the full URL for the profile picture."""
        if obj.profile_picture:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_picture.url)
            return obj.profile_picture.url
        return None

    def validate_profile_picture(self, value):
        """
        Validate profile picture upload.
        """
        if not value:
            return value

        # Check file size (5MB limit)
        if value.size > 5 * 1024 * 1024:
            raise serializers.ValidationError(
                "Profile picture must be smaller than 5MB."
            )

        # Check file type
        allowed_extensions = ['.jpg', '.jpeg', '.png']
        file_extension = os.path.splitext(value.name)[1].lower()

        if file_extension not in allowed_extensions:
            raise serializers.ValidationError(
                "Only JPG and PNG files are allowed for profile pictures."
            )

        # Validate image using PIL
        try:
            # Open and verify the image
            image = Image.open(value)
            image.verify()

            # Reset file pointer after verification
            if hasattr(value, 'seek'):
                value.seek(0)

            # Check image dimensions (optional - reasonable limits)
            if image.width > 2048 or image.height > 2048:
                raise serializers.ValidationError(
                    "Profile picture dimensions must not exceed 2048x2048 pixels."
                )

            if image.width < 50 or image.height < 50:
                raise serializers.ValidationError(
                    "Profile picture must be at least 50x50 pixels."
                )

        except Exception as e:
            raise serializers.ValidationError(
                "Invalid image file. Please upload a valid JPG or PNG image."
            )

        return value

    def validate_phone_number(self, value):
        """
        Validate phone number format.
        """
        if value:
            # Remove spaces and common separators for validation
            cleaned_number = ''.join(c for c in value if c.isdigit() or c == '+')

            # Basic validation - should start with + and have 10-15 digits
            if not cleaned_number.startswith('+'):
                raise serializers.ValidationError(
                    "Phone number must include country code (e.g., +1234567890)."
                )

            digits_only = cleaned_number[1:]  # Remove the +
            if len(digits_only) < 10 or len(digits_only) > 15:
                raise serializers.ValidationError(
                    "Phone number must have 10-15 digits after country code."
                )

        return value

    def validate_twitter_handle(self, value):
        """
        Validate Twitter handle format.
        """
        if value:
            # Remove @ if present
            handle = value.lstrip('@')

            # Validate format
            if not handle.replace('_', '').replace('-', '').isalnum():
                raise serializers.ValidationError(
                    "Twitter handle can only contain letters, numbers, underscores, and hyphens."
                )

            if len(handle) > 15:
                raise serializers.ValidationError(
                    "Twitter handle must be 15 characters or less."
                )

            # Add @ prefix if not present
            return f"@{handle}"

        return value

    def to_representation(self, instance):
        """
        Customize the serialized representation.
        """
        data = super().to_representation(instance)

        # Add computed fields
        data['display_name'] = instance.get_display_name()
        data['age'] = instance.get_age()
        data['completion_suggestions'] = instance.get_completion_suggestions()

        # Filter visible fields based on privacy settings
        request = self.context.get('request')
        viewer_user = request.user if request and request.user.is_authenticated else None

        # If viewer is not the profile owner, filter based on privacy settings
        if viewer_user != instance.user:
            visible_fields = instance.get_visible_fields(viewer_user)

            # Remove private fields from response
            private_fields = [
                'phone_number', 'street_address', 'state_province',
                'postal_code', 'date_of_birth', 'gender'
            ]

            for field in private_fields:
                if field not in visible_fields:
                    data.pop(field, None)

        return data


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user profile with change tracking.
    """

    class Meta:
        model = UserProfile
        fields = [
            'bio', 'date_of_birth', 'gender', 'phone_number',
            'street_address', 'city', 'state_province', 'postal_code', 'country',
            'profile_picture', 'website_url', 'linkedin_url', 'twitter_handle',
            'profile_visibility', 'email_visibility', 'phone_visibility',
            'preferred_communication', 'marketing_emails', 'event_notifications', 'security_alerts'
        ]

    def validate_profile_picture(self, value):
        """
        Validate profile picture upload.
        """
        if not value:
            return value

        # Use the same validation as UserProfileSerializer
        serializer = UserProfileSerializer()
        return serializer.validate_profile_picture(value)

    def validate_phone_number(self, value):
        """
        Validate phone number format.
        """
        if value:
            serializer = UserProfileSerializer()
            return serializer.validate_phone_number(value)
        return value

    def validate_twitter_handle(self, value):
        """
        Validate Twitter handle format.
        """
        if value:
            serializer = UserProfileSerializer()
            return serializer.validate_twitter_handle(value)
        return value

    def update(self, instance, validated_data):
        """
        Update profile with change tracking.
        """
        # Track changes for audit
        old_values = {}
        new_values = {}
        changed_fields = []

        for field, new_value in validated_data.items():
            old_value = getattr(instance, field)

            # Handle file fields specially
            if hasattr(old_value, 'name'):
                old_value = old_value.name if old_value else None
            if hasattr(new_value, 'name'):
                new_value = new_value.name if new_value else None

            if old_value != new_value:
                changed_fields.append(field)
                old_values[field] = str(old_value) if old_value is not None else None
                new_values[field] = str(new_value) if new_value is not None else None

        # Update the instance
        updated_instance = super().update(instance, validated_data)

        # Log the change if there were any changes
        if changed_fields:
            request = self.context.get('request')
            changed_by = request.user if request and request.user.is_authenticated else None

            # Determine action type
            action = 'update'
            if 'profile_picture' in changed_fields:
                action = 'picture_change'
            elif any(field in changed_fields for field in
                     ['profile_visibility', 'email_visibility', 'phone_visibility']):
                action = 'privacy_change'

            UserProfileHistory.log_change(
                profile=updated_instance,
                action=action,
                changed_fields=changed_fields,
                old_values=old_values,
                new_values=new_values,
                changed_by=changed_by,
                request=request,
                reason='Profile update via API'
            )

        return updated_instance


class UserProfileHistorySerializer(serializers.ModelSerializer):
    """
    Serializer for user profile change history.
    """
    changed_by_email = serializers.CharField(source='changed_by.email', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)

    class Meta:
        model = UserProfileHistory
        fields = [
            'id', 'action', 'action_display', 'changed_fields',
            'old_values', 'new_values', 'changed_by_email',
            'changed_at', 'ip_address', 'reason'
        ]
        read_only_fields = ['id', 'changed_at']


class ProfileCompletionSerializer(serializers.Serializer):
    """
    Serializer for profile completion status and suggestions.
    """
    completion_percentage = serializers.IntegerField(read_only=True)
    is_complete = serializers.BooleanField(read_only=True)
    suggestions = serializers.ListField(read_only=True)
    missing_fields = serializers.ListField(read_only=True)

    def to_representation(self, instance):
        """
        Generate completion data for a profile.
        """
        return {
            'completion_percentage': instance.profile_completion_percentage,
            'is_complete': instance.is_profile_complete(),
            'suggestions': instance.get_completion_suggestions(),
            'missing_fields': self._get_missing_fields(instance)
        }

    def _get_missing_fields(self, profile):
        """
        Get list of missing important fields.
        """
        missing = []

        # Check important fields
        important_fields = {
            'bio': 'Bio/Description',
            'date_of_birth': 'Date of Birth',
            'phone_number': 'Phone Number',
            'city': 'City',
            'country': 'Country',
            'profile_picture': 'Profile Picture'
        }

        for field, display_name in important_fields.items():
            value = getattr(profile, field)
            if not value or (isinstance(value, str) and not value.strip()):
                missing.append({
                    'field': field,
                    'display_name': display_name
                })

        # Check user fields
        if not profile.user.first_name:
            missing.append({
                'field': 'first_name',
                'display_name': 'First Name'
            })

        if not profile.user.last_name:
            missing.append({
                'field': 'last_name',
                'display_name': 'Last Name'
            })

        return missing


class ProfileVisibilitySerializer(serializers.ModelSerializer):
    """
    Serializer for managing profile visibility settings.
    """

    class Meta:
        model = UserProfile
        fields = ['profile_visibility', 'email_visibility', 'phone_visibility']

    def update(self, instance, validated_data):
        """
        Update visibility settings with change tracking.
        """
        # Track changes
        old_values = {}
        new_values = {}
        changed_fields = []

        for field, new_value in validated_data.items():
            old_value = getattr(instance, field)
            if old_value != new_value:
                changed_fields.append(field)
                old_values[field] = old_value
                new_values[field] = new_value

        # Update the instance
        updated_instance = super().update(instance, validated_data)

        # Log the change if there were any changes
        if changed_fields:
            request = self.context.get('request')
            changed_by = request.user if request and request.user.is_authenticated else None

            UserProfileHistory.log_change(
                profile=updated_instance,
                action='privacy_change',
                changed_fields=changed_fields,
                old_values=old_values,
                new_values=new_values,
                changed_by=changed_by,
                request=request,
                reason='Privacy settings update via API'
            )

        return updated_instance