"""
Unit tests for profile management functionality.
Tests profile management features and profile validation/update functionality.
"""
import os
import tempfile
from datetime import date, timedelta
from django.test import TestCase, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from PIL import Image
from io import BytesIO

from ..models.profile import UserProfile, UserProfileHistory
from ..services.profile_service import ProfileService
from ..serializers.profile import (
    UserProfileSerializer,
    UserProfileUpdateSerializer,
    ProfileCompletionSerializer,
    ProfileVisibilitySerializer
)

User = get_user_model()


class UserProfileModelTests(TestCase):
    """Test cases for UserProfile model functionality."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

    def test_profile_creation(self):
        """Test creating a user profile."""
        profile = UserProfile.objects.create(
            user=self.user,
            bio='Test bio',
            phone_number='+1234567890'
        )

        self.assertEqual(profile.user, self.user)
        self.assertEqual(profile.bio, 'Test bio')
        self.assertEqual(profile.phone_number, '+1234567890')
        self.assertEqual(profile.profile_visibility, 'public')  # Default
        self.assertEqual(profile.email_visibility, 'private')  # Default
        self.assertIsNotNone(profile.id)  # UUID should be generated

    def test_profile_string_representation(self):
        """Test profile string representation."""
        profile = UserProfile.objects.create(
            user=self.user,
            bio='Test bio'
        )

        expected = f"John Doe - Profile ({profile.profile_completion_percentage}% complete)"
        self.assertEqual(str(profile), expected)

    def test_get_display_name(self):
        """Test get_display_name method."""
        profile = UserProfile.objects.create(user=self.user)

        # With first and last name
        self.assertEqual(profile.get_display_name(), 'John Doe')

        # With only first name
        self.user.last_name = ''
        self.user.save()
        self.assertEqual(profile.get_display_name(), 'John')

        # With no names
        self.user.first_name = ''
        self.user.save()
        self.assertEqual(profile.get_display_name(), 'test')  # Email username part

    def test_get_age_calculation(self):
        """Test age calculation."""
        # Test with valid birth date
        birth_date = date.today() - timedelta(days=365 * 25 + 6)  # ~25 years ago
        profile = UserProfile.objects.create(
            user=self.user,
            date_of_birth=birth_date
        )

        age = profile.get_age()
        self.assertIsInstance(age, int)
        self.assertGreaterEqual(age, 24)
        self.assertLessEqual(age, 26)

        # Test with no birth date
        profile.date_of_birth = None
        profile.save()
        self.assertIsNone(profile.get_age())

    def test_profile_completion_calculation(self):
        """Test profile completion percentage calculation."""
        profile = UserProfile.objects.create(user=self.user)

        # Basic profile should have some completion from user names
        initial_completion = profile.calculate_completion_percentage()
        self.assertGreater(initial_completion, 0)

        # Add more fields and check completion increases
        profile.bio = 'Test bio'
        profile.phone_number = '+1234567890'
        profile.city = 'New York'
        profile.country = 'USA'

        new_completion = profile.calculate_completion_percentage()
        self.assertGreater(new_completion, initial_completion)

        # Completion should not exceed 100
        self.assertLessEqual(new_completion, 100)

    def test_completion_suggestions(self):
        """Test profile completion suggestions."""
        profile = UserProfile.objects.create(user=self.user)

        suggestions = profile.get_completion_suggestions()
        self.assertIsInstance(suggestions, list)

        # Should suggest missing fields
        self.assertIn('Write a brief bio about yourself', suggestions)
        self.assertIn('Add your date of birth', suggestions)

        # Add bio and check it's no longer suggested
        profile.bio = 'Test bio'
        profile.save()

        new_suggestions = profile.get_completion_suggestions()
        self.assertNotIn('Write a brief bio about yourself', new_suggestions)

    def test_is_profile_complete(self):
        """Test profile completion status check."""
        profile = UserProfile.objects.create(user=self.user)

        # Initially should not be complete
        self.assertFalse(profile.is_profile_complete())

        # Fill in most fields
        profile.bio = 'Test bio'
        profile.date_of_birth = date(1990, 1, 1)
        profile.phone_number = '+1234567890'
        profile.city = 'New York'
        profile.country = 'USA'
        profile.save()

        # Should be complete now (depending on threshold)
        completion = profile.calculate_completion_percentage()
        if completion >= 80:
            self.assertTrue(profile.is_profile_complete())

    def test_profile_validation_date_of_birth(self):
        """Test date of birth validation."""
        profile = UserProfile(user=self.user)

        # Future date should be invalid
        profile.date_of_birth = date.today() + timedelta(days=1)
        with self.assertRaises(ValidationError):
            profile.clean()

        # Too young (under 13) should be invalid
        profile.date_of_birth = date.today() - timedelta(days=365 * 10)  # 10 years old
        with self.assertRaises(ValidationError):
            profile.clean()

        # Valid age should pass
        profile.date_of_birth = date.today() - timedelta(days=365 * 20)  # 20 years old
        try:
            profile.clean()
        except ValidationError:
            self.fail("Valid date of birth should not raise ValidationError")

    def test_twitter_handle_cleaning(self):
        """Test Twitter handle cleaning."""
        profile = UserProfile(
            user=self.user,
            twitter_handle='johndoe'  # Without @
        )

        profile.clean()
        self.assertEqual(profile.twitter_handle, '@johndoe')

        # Already has @ should remain unchanged
        profile.twitter_handle = '@janedoe'
        profile.clean()
        self.assertEqual(profile.twitter_handle, '@janedoe')

    def test_get_visible_fields(self):
        """Test visible fields based on privacy settings."""
        profile = UserProfile.objects.create(
            user=self.user,
            bio='Test bio',
            phone_number='+1234567890',
            profile_visibility='public',
            email_visibility='private',
            phone_visibility='private'
        )

        # Anonymous viewer
        visible_fields = profile.get_visible_fields(None)
        self.assertIn('display_name', visible_fields)
        self.assertIn('bio', visible_fields)  # Public profile
        self.assertNotIn('phone_number', visible_fields)  # Private phone

        # Profile owner
        owner_fields = profile.get_visible_fields(self.user)
        self.assertIn('phone_number', owner_fields)  # Owner sees everything
        self.assertIn('email', owner_fields)

    def test_create_profile_class_method(self):
        """Test create_profile class method."""
        profile_data = {
            'bio': 'Test bio',
            'phone_number': '+1234567890',
            'city': 'New York'
        }

        profile = UserProfile.create_profile(self.user, **profile_data)

        self.assertEqual(profile.user, self.user)
        self.assertEqual(profile.bio, 'Test bio')
        self.assertEqual(profile.phone_number, '+1234567890')
        self.assertEqual(profile.city, 'New York')

    def test_update_profile_method(self):
        """Test update_profile method."""
        profile = UserProfile.objects.create(user=self.user)

        update_data = {
            'bio': 'Updated bio',
            'city': 'San Francisco'
        }

        profile.update_profile(updated_by=self.user, **update_data)

        profile.refresh_from_db()
        self.assertEqual(profile.bio, 'Updated bio')
        self.assertEqual(profile.city, 'San Francisco')
        self.assertEqual(profile.last_updated_by, self.user)


class UserProfileHistoryTests(TestCase):
    """Test cases for UserProfileHistory model."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.profile = UserProfile.objects.create(user=self.user)

    def test_log_change(self):
        """Test logging profile changes."""
        history_entry = UserProfileHistory.log_change(
            profile=self.profile,
            action='update',
            changed_fields=['bio', 'city'],
            old_values={'bio': '', 'city': ''},
            new_values={'bio': 'New bio', 'city': 'New York'},
            changed_by=self.user,
            reason='Test update'
        )

        self.assertEqual(history_entry.profile, self.profile)
        self.assertEqual(history_entry.action, 'update')
        self.assertEqual(history_entry.changed_fields, ['bio', 'city'])
        self.assertEqual(history_entry.changed_by, self.user)
        self.assertEqual(history_entry.reason, 'Test update')

    def test_history_string_representation(self):
        """Test history entry string representation."""
        history_entry = UserProfileHistory.objects.create(
            profile=self.profile,
            action='update',
            changed_by=self.user
        )

        expected = f"{self.user.email} - Profile Updated - {history_entry.changed_at.strftime('%Y-%m-%d %H:%M:%S')}"
        self.assertEqual(str(history_entry), expected)


class ProfileServiceTests(TestCase):
    """Test cases for ProfileService functionality."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

    def test_get_or_create_profile(self):
        """Test getting or creating a profile."""
        # Should create profile if it doesn't exist
        profile = ProfileService.get_or_create_profile(self.user)
        self.assertIsInstance(profile, UserProfile)
        self.assertEqual(profile.user, self.user)

        # Should return existing profile
        same_profile = ProfileService.get_or_create_profile(self.user)
        self.assertEqual(profile.id, same_profile.id)

    def test_update_profile_service(self):
        """Test profile update through service."""
        profile_data = {
            'bio': 'Updated bio',
            'phone_number': '+1234567890',
            'city': 'New York'
        }

        success, profile, errors = ProfileService.update_profile(
            user=self.user,
            profile_data=profile_data
        )

        self.assertTrue(success)
        self.assertIsNone(errors)
        self.assertEqual(profile.bio, 'Updated bio')
        self.assertEqual(profile.phone_number, '+1234567890')
        self.assertEqual(profile.city, 'New York')

    def test_update_profile_validation_error(self):
        """Test profile update with validation errors."""
        profile_data = {
            'date_of_birth': date.today() + timedelta(days=1)  # Future date
        }

        success, profile, errors = ProfileService.update_profile(
            user=self.user,
            profile_data=profile_data
        )

        self.assertFalse(success)
        self.assertIsNotNone(errors)
        self.assertIn('date_of_birth', errors)

    def test_update_privacy_settings(self):
        """Test updating privacy settings."""
        privacy_data = {
            'profile_visibility': 'private',
            'email_visibility': 'friends',
            'phone_visibility': 'private'
        }

        success, profile, errors = ProfileService.update_privacy_settings(
            user=self.user,
            privacy_data=privacy_data
        )

        self.assertTrue(success)
        self.assertIsNone(errors)
        self.assertEqual(profile.profile_visibility, 'private')
        self.assertEqual(profile.email_visibility, 'friends')
        self.assertEqual(profile.phone_visibility, 'private')

    def test_get_profile_completion_status(self):
        """Test getting profile completion status."""
        completion_data = ProfileService.get_profile_completion_status(self.user)

        self.assertIn('completion_percentage', completion_data)
        self.assertIn('is_complete', completion_data)
        self.assertIn('suggestions', completion_data)
        self.assertIn('missing_fields', completion_data)

        self.assertIsInstance(completion_data['completion_percentage'], int)
        self.assertIsInstance(completion_data['is_complete'], bool)
        self.assertIsInstance(completion_data['suggestions'], list)
        self.assertIsInstance(completion_data['missing_fields'], list)

    def test_get_profile_history(self):
        """Test getting profile history."""
        # Create some history
        profile = ProfileService.get_or_create_profile(self.user)
        ProfileService.update_profile(
            user=self.user,
            profile_data={'bio': 'Test bio'}
        )

        history = ProfileService.get_profile_history(self.user)
        self.assertGreater(history.count(), 0)

    def test_delete_profile_picture(self):
        """Test deleting profile picture."""
        # First create a profile with a picture
        profile = ProfileService.get_or_create_profile(self.user)

        # Test deleting when no picture exists
        success, profile, errors = ProfileService.delete_profile_picture(self.user)
        self.assertFalse(success)
        self.assertIn('profile_picture', errors)

    def test_validate_profile_data(self):
        """Test profile data validation."""
        # Valid data - need to create a temporary user for the profile
        temp_user = User.objects.create_user(
            email='temp@example.com',
            password='temppass123'
        )

        valid_data = {
            'user': temp_user,
            'bio': 'Test bio',
            'phone_number': '+1234567890'
        }

        is_valid, errors = ProfileService.validate_profile_data(valid_data)
        self.assertTrue(is_valid)
        self.assertIsNone(errors)

        # Invalid data - future date of birth
        invalid_data = {
            'user': temp_user,
            'date_of_birth': date.today() + timedelta(days=1)
        }

        is_valid, errors = ProfileService.validate_profile_data(invalid_data)
        self.assertFalse(is_valid)
        self.assertIsNotNone(errors)

    def test_bulk_update_communication_preferences(self):
        """Test bulk updating communication preferences."""
        preferences = {
            'preferred_communication': 'sms',
            'marketing_emails': True,
            'event_notifications': False,
            'security_alerts': True
        }

        success, profile, errors = ProfileService.bulk_update_communication_preferences(
            user=self.user,
            preferences=preferences
        )

        self.assertTrue(success)
        self.assertIsNone(errors)
        self.assertEqual(profile.preferred_communication, 'sms')
        self.assertTrue(profile.marketing_emails)
        self.assertFalse(profile.event_notifications)
        self.assertTrue(profile.security_alerts)

    def test_get_profile_statistics(self):
        """Test getting profile statistics."""
        stats = ProfileService.get_profile_statistics(self.user)

        expected_keys = [
            'profile_created', 'last_updated', 'total_updates',
            'completion_percentage', 'is_complete', 'has_profile_picture',
            'privacy_level'
        ]

        for key in expected_keys:
            self.assertIn(key, stats)

    def test_reset_profile_to_defaults(self):
        """Test resetting profile to defaults."""
        # First update some settings
        profile = ProfileService.get_or_create_profile(self.user)
        profile.profile_visibility = 'private'
        profile.marketing_emails = True
        profile.save()

        # Reset to defaults
        success, profile, errors = ProfileService.reset_profile_to_defaults(self.user)

        self.assertTrue(success)
        self.assertIsNone(errors)
        self.assertEqual(profile.profile_visibility, 'public')
        self.assertFalse(profile.marketing_emails)


class ProfileSerializerTests(TestCase):
    """Test cases for profile serializers."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )
        self.profile = UserProfile.objects.create(
            user=self.user,
            bio='Test bio',
            phone_number='+1234567890'
        )

    def test_user_profile_serializer(self):
        """Test UserProfileSerializer."""
        # Create a mock request with the profile owner as user
        from django.test import RequestFactory
        from django.contrib.auth.models import AnonymousUser

        factory = RequestFactory()
        request = factory.get('/')
        request.user = self.user  # Profile owner

        serializer = UserProfileSerializer(self.profile, context={'request': request})
        data = serializer.data

        # Check basic fields
        self.assertEqual(data['email'], 'test@example.com')
        self.assertEqual(data['first_name'], 'John')
        self.assertEqual(data['last_name'], 'Doe')
        self.assertEqual(data['bio'], 'Test bio')
        self.assertEqual(data['phone_number'], '+1234567890')  # Should be visible to owner

        # Check computed fields
        self.assertIn('display_name', data)
        self.assertIn('profile_completion_percentage', data)

    def test_user_profile_serializer_privacy_filtering(self):
        """Test UserProfileSerializer privacy filtering for non-owners."""
        from django.test import RequestFactory
        from django.contrib.auth.models import AnonymousUser

        # Set phone visibility to private
        self.profile.phone_visibility = 'private'
        self.profile.save()

        # Create another user (not the profile owner)
        other_user = User.objects.create_user(
            email='other@example.com',
            password='otherpass123'
        )

        factory = RequestFactory()
        request = factory.get('/')
        request.user = other_user  # Different user

        serializer = UserProfileSerializer(self.profile, context={'request': request})
        data = serializer.data

        # Phone number should be filtered out for non-owner
        self.assertNotIn('phone_number', data)

        # But bio should still be visible (public profile)
        self.assertEqual(data['bio'], 'Test bio')

    def test_profile_update_serializer_validation(self):
        """Test UserProfileUpdateSerializer validation."""
        # Valid data
        valid_data = {
            'bio': 'Updated bio',
            'phone_number': '+9876543210'
        }

        serializer = UserProfileUpdateSerializer(
            self.profile,
            data=valid_data,
            partial=True
        )

        self.assertTrue(serializer.is_valid())

        # Invalid phone number
        invalid_data = {
            'phone_number': 'invalid-phone'
        }

        serializer = UserProfileUpdateSerializer(
            self.profile,
            data=invalid_data,
            partial=True
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn('phone_number', serializer.errors)

    def test_twitter_handle_validation(self):
        """Test Twitter handle validation in serializer."""
        # Valid handle without @
        data = {'twitter_handle': 'johndoe'}
        serializer = UserProfileUpdateSerializer(
            self.profile,
            data=data,
            partial=True
        )

        self.assertTrue(serializer.is_valid())
        validated_data = serializer.validated_data
        self.assertEqual(validated_data['twitter_handle'], '@johndoe')

        # Invalid handle with special characters
        data = {'twitter_handle': 'john@doe!'}
        serializer = UserProfileUpdateSerializer(
            self.profile,
            data=data,
            partial=True
        )

        self.assertFalse(serializer.is_valid())

    def test_profile_completion_serializer(self):
        """Test ProfileCompletionSerializer."""
        serializer = ProfileCompletionSerializer()
        data = serializer.to_representation(self.profile)

        self.assertIn('completion_percentage', data)
        self.assertIn('is_complete', data)
        self.assertIn('suggestions', data)
        self.assertIn('missing_fields', data)

        self.assertIsInstance(data['completion_percentage'], int)
        self.assertIsInstance(data['is_complete'], bool)
        self.assertIsInstance(data['suggestions'], list)
        self.assertIsInstance(data['missing_fields'], list)

    def test_profile_visibility_serializer(self):
        """Test ProfileVisibilitySerializer."""
        data = {
            'profile_visibility': 'private',
            'email_visibility': 'friends',
            'phone_visibility': 'private'
        }

        serializer = ProfileVisibilitySerializer(
            self.profile,
            data=data,
            partial=True
        )

        self.assertTrue(serializer.is_valid())

        # Invalid visibility choice
        invalid_data = {
            'profile_visibility': 'invalid_choice'
        }

        serializer = ProfileVisibilitySerializer(
            self.profile,
            data=invalid_data,
            partial=True
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn('profile_visibility', serializer.errors)


@override_settings(MEDIA_ROOT=tempfile.gettempdir())
class ProfilePictureTests(TestCase):
    """Test cases for profile picture functionality."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def create_test_image(self, format='JPEG', size=(100, 100)):
        """Create a test image file."""
        image = Image.new('RGB', size, color='red')
        image_file = BytesIO()
        image.save(image_file, format=format)
        image_file.seek(0)

        filename = f'test_image.{format.lower()}'
        if format == 'JPEG':
            filename = 'test_image.jpg'

        return SimpleUploadedFile(
            filename,
            image_file.getvalue(),
            content_type=f'image/{format.lower()}'
        )

    def test_profile_picture_validation_valid_image(self):
        """Test profile picture validation with valid image."""
        image_file = self.create_test_image()

        serializer = UserProfileUpdateSerializer()
        validated_file = serializer.validate_profile_picture(image_file)

        self.assertEqual(validated_file, image_file)

    def test_profile_picture_validation_invalid_format(self):
        """Test profile picture validation with invalid format."""
        # Create a text file instead of image
        text_file = SimpleUploadedFile(
            'test.txt',
            b'This is not an image',
            content_type='text/plain'
        )

        serializer = UserProfileUpdateSerializer()

        with self.assertRaises(Exception):  # Should raise validation error
            serializer.validate_profile_picture(text_file)

    def test_profile_picture_validation_large_file(self):
        """Test profile picture validation with large file."""
        # Create a large image (simulate > 5MB)
        large_image = self.create_test_image(size=(3000, 3000))

        # Mock the size to be over 5MB
        large_image.size = 6 * 1024 * 1024  # 6MB

        serializer = UserProfileUpdateSerializer()

        with self.assertRaises(Exception):  # Should raise validation error
            serializer.validate_profile_picture(large_image)

    def test_profile_picture_validation_small_dimensions(self):
        """Test profile picture validation with small dimensions."""
        small_image = self.create_test_image(size=(30, 30))  # Below 50x50 minimum

        serializer = UserProfileUpdateSerializer()

        with self.assertRaises(Exception):  # Should raise validation error
            serializer.validate_profile_picture(small_image)

    def test_profile_picture_upload_path(self):
        """Test profile picture upload path generation."""
        from ..models.profile import profile_picture_upload_path

        profile = UserProfile.objects.create(user=self.user)
        filename = 'test_image.jpg'

        path = profile_picture_upload_path(profile, filename)

        self.assertTrue(path.startswith('profile_pictures/'))
        self.assertTrue(path.endswith('.jpg'))
        self.assertIn(str(self.user.id), path)


class ProfileIntegrationTests(TestCase):
    """Integration tests for profile management."""

    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

    def test_complete_profile_workflow(self):
        """Test complete profile management workflow."""
        # 1. Create profile
        profile = ProfileService.get_or_create_profile(self.user)
        self.assertIsInstance(profile, UserProfile)

        # 2. Update basic information
        basic_data = {
            'bio': 'Software developer',
            'date_of_birth': date(1990, 1, 1),
            'phone_number': '+1234567890'
        }

        success, updated_profile, errors = ProfileService.update_profile(
            user=self.user,
            profile_data=basic_data
        )

        self.assertTrue(success)
        self.assertEqual(updated_profile.bio, 'Software developer')

        # 3. Update privacy settings
        privacy_data = {
            'profile_visibility': 'private',
            'email_visibility': 'friends'
        }

        success, profile, errors = ProfileService.update_privacy_settings(
            user=self.user,
            privacy_data=privacy_data
        )

        self.assertTrue(success)
        self.assertEqual(profile.profile_visibility, 'private')

        # 4. Check completion status
        completion = ProfileService.get_profile_completion_status(self.user)
        self.assertGreater(completion['completion_percentage'], 0)

        # 5. Verify history tracking
        history = ProfileService.get_profile_history(self.user)
        self.assertGreater(history.count(), 0)

    def test_profile_visibility_enforcement(self):
        """Test profile visibility enforcement."""
        # Create profile with mixed visibility settings
        profile = UserProfile.objects.create(
            user=self.user,
            bio='Public bio',
            phone_number='+1234567890',
            profile_visibility='public',
            email_visibility='private',
            phone_visibility='private'
        )

        # Test anonymous viewer
        visible_fields = ProfileService.get_visible_profile_data(profile, None)
        self.assertIn('bio', visible_fields)  # Public
        self.assertNotIn('phone_number', visible_fields)  # Private

        # Test profile owner
        owner_fields = ProfileService.get_visible_profile_data(profile, self.user)
        self.assertIn('phone_number', owner_fields)  # Owner sees all
        self.assertIn('email', owner_fields)

    def test_profile_change_tracking(self):
        """Test profile change tracking and audit trail."""
        profile = ProfileService.get_or_create_profile(self.user)

        # Make several updates
        updates = [
            {'bio': 'First bio'},
            {'bio': 'Updated bio', 'city': 'New York'},
            {'profile_visibility': 'private'}
        ]

        for update_data in updates:
            ProfileService.update_profile(
                user=self.user,
                profile_data=update_data
            )

        # Check history
        history = ProfileService.get_profile_history(self.user)
        self.assertGreaterEqual(history.count(), len(updates))

        # Verify history entries have correct data
        for entry in history:
            self.assertEqual(entry.profile, profile)
            self.assertEqual(entry.changed_by, self.user)
            self.assertIsInstance(entry.changed_fields, list)

    def test_error_handling_and_validation(self):
        """Test error handling and validation across the system."""
        # Test invalid data through service
        invalid_data = {
            'date_of_birth': date.today() + timedelta(days=1),  # Future date
            'phone_number': 'invalid-phone',
            'twitter_handle': 'invalid@handle!'
        }

        success, profile, errors = ProfileService.update_profile(
            user=self.user,
            profile_data=invalid_data
        )

        self.assertFalse(success)
        self.assertIsNotNone(errors)

        # Test validation through serializer
        serializer = UserProfileUpdateSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())
        self.assertTrue(len(serializer.errors) > 0)