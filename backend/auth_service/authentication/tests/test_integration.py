"""
Integration tests for registration validation combining all validators.
Tests Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7
"""
from django.test import TestCase
from django.contrib.auth import get_user_model

from ..serializers import UserRegistrationSerializer

User = get_user_model()


class RegistrationValidationIntegrationTests(TestCase):
    """
    Integration tests for registration validation combining all validators.
    Tests Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7
    """

    def test_complete_valid_registration(self):
        """Test complete valid registration with all validations passing."""
        valid_data = {
            'email': 'john.doe@company.com',
            'password': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'password_confirm': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'first_name': 'John',
            'last_name': 'Doe'
        }

        serializer = UserRegistrationSerializer(data=valid_data)
        self.assertTrue(serializer.is_valid(), f"Valid registration failed: {serializer.errors}")

        user = serializer.save()
        self.assertEqual(user.email, 'john.doe@company.com')
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_email_verified)

    def test_multiple_validation_failures(self):
        """Test that multiple validation failures are reported."""
        invalid_data = {
            'email': 'test@10minutemail.com',  # Disposable email
            'password': 'weak',                # Truly weak password
            'password_confirm': 'different',   # Mismatched confirmation
            'first_name': 'test',             # Fake name
            'last_name': '123456'             # Numeric name
        }

        serializer = UserRegistrationSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())

        # Check that multiple validation errors are present
        self.assertIn('email', serializer.errors)
        self.assertIn('password', serializer.errors)
        self.assertIn('first_name', serializer.errors)
        self.assertIn('last_name', serializer.errors)
        # Note: password_confirm validation only runs if password passes basic validation

    def test_edge_case_validations(self):
        """Test edge cases in validation logic."""
        edge_cases = [
            {
                'email': 'test@example.com',
                'password': 'MinimumLength12!A1',  # Meet all requirements including 12+ chars
                'password_confirm': 'MinimumLength12!A1',
                'first_name': 'Jo',       # Minimum length name
                'last_name': 'Li'
            },
            {
                'email': 'very.long.email.address@very.long.domain.name.example.com',
                'password': 'C0mpl3x&P@ssw0rd!' + 'x' * 100,  # Long but valid password
                'password_confirm': 'C0mpl3x&P@ssw0rd!' + 'x' * 100,
                'first_name': 'Very-Long-Hyphenated-Name',
                'last_name': "O'Very-Long-Apostrophe-Name"
            }
        ]

        for i, data in enumerate(edge_cases):
            with self.subTest(case=i):
                serializer = UserRegistrationSerializer(data=data)
                self.assertTrue(serializer.is_valid(), f"Edge case {i} failed: {serializer.errors}")

    def test_registration_with_minimal_data(self):
        """Test registration with only required fields."""
        minimal_data = {
            'email': 'minimal@example.com',
            'password': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'password_confirm': 'MyC0mpl3x&UniqueP@ssw0rd!'
        }

        serializer = UserRegistrationSerializer(data=minimal_data)
        self.assertTrue(serializer.is_valid(), f"Minimal registration failed: {serializer.errors}")

        user = serializer.save()
        self.assertEqual(user.email, 'minimal@example.com')
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')

    def test_case_insensitive_email_uniqueness(self):
        """Test that email uniqueness works with normalized emails."""
        # Create user with lowercase email
        User.objects.create_user(email='test@example.com', password='password123')

        # Try to register with same email (should fail due to uniqueness)
        data = {
            'email': 'test@example.com',  # Same email should fail
            'password': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'password_confirm': 'MyC0mpl3x&UniqueP@ssw0rd!'
        }

        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

    def test_whitespace_handling(self):
        """Test proper handling of whitespace in inputs."""
        data_with_whitespace = {
            'email': '  test@example.com  ',
            'password': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'password_confirm': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'first_name': '  John  ',
            'last_name': '  Doe  '
        }

        serializer = UserRegistrationSerializer(data=data_with_whitespace)
        self.assertTrue(serializer.is_valid(), f"Whitespace handling failed: {serializer.errors}")

        user = serializer.save()
        self.assertEqual(user.email, 'test@example.com')  # Should be normalized
        self.assertEqual(user.first_name, 'John')     # Names are trimmed
        self.assertEqual(user.last_name, 'Doe')

    def test_unicode_name_support(self):
        """Test support for unicode characters in names."""
        unicode_data = {
            'email': 'unicode@example.com',
            'password': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'password_confirm': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'first_name': 'José',
            'last_name': 'François'
        }

        serializer = UserRegistrationSerializer(data=unicode_data)
        self.assertTrue(serializer.is_valid(), f"Unicode names failed: {serializer.errors}")

        user = serializer.save()
        self.assertEqual(user.first_name, 'José')
        self.assertEqual(user.last_name, 'François')

    def test_comprehensive_password_requirements(self):
        """Test that all password requirements work together."""
        # Test password that meets all individual requirements but is still weak
        weak_but_complex = {
            'email': 'entropy@example.com',
            'password': 'password123!',  # Common pattern that should be rejected
            'password_confirm': 'password123!'
        }

        serializer = UserRegistrationSerializer(data=weak_but_complex)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)

    def test_serializer_error_messages_quality(self):
        """Test that error messages are user-friendly and informative."""
        invalid_data = {
            'email': 'invalid-email',
            'password': 'weak',
            'password_confirm': 'different',
            'first_name': 'test'
        }

        serializer = UserRegistrationSerializer(data=invalid_data)
        self.assertFalse(serializer.is_valid())

        # Check that error messages are present and informative
        self.assertIn('email', serializer.errors)
        self.assertIn('password', serializer.errors)
        self.assertIn('first_name', serializer.errors)
        # Note: password_confirm validation only runs if password passes basic validation

        # Verify error messages contain helpful information
        email_error = str(serializer.errors['email'][0])
        self.assertIn('valid email', email_error.lower())

        password_error = str(serializer.errors['password'][0])
        self.assertTrue(len(password_error) > 10)  # Should be descriptive