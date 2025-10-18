"""
Unit tests for UserRegistrationSerializer validation logic.
Tests Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from unittest.mock import patch

from ..serializers import UserRegistrationSerializer

User = get_user_model()


class UserRegistrationSerializerTests(TestCase):
    """
    Comprehensive unit tests for UserRegistrationSerializer validation logic.
    Tests Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
    """

    def setUp(self):
        """Set up test data."""
        self.valid_data = {
            'email': 'test@example.com',
            'password': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'password_confirm': 'MyC0mpl3x&UniqueP@ssw0rd!',
            'first_name': 'John',
            'last_name': 'Doe'
        }

    def test_valid_registration_data(self):
        """Test serializer with valid registration data."""
        serializer = UserRegistrationSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())

        user = serializer.save()
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')
        self.assertFalse(user.is_active)  # Should be inactive until email verification
        self.assertFalse(user.is_email_verified)

    def test_email_format_validation(self):
        """Test email format validation - Requirement 1.1"""
        invalid_emails = [
            'invalid-email',
            'test@',
            '@example.com',
            'test..test@example.com',
            'test@example',
            'test@.com',
            'test@example.',
            'test space@example.com',
            'test@exam ple.com',
            '',
            'test@example..com'
        ]

        for invalid_email in invalid_emails:
            with self.subTest(email=invalid_email):
                data = self.valid_data.copy()
                data['email'] = invalid_email
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('email', serializer.errors)

    def test_disposable_email_validation(self):
        """Test disposable email provider blocking - Requirement 1.3"""
        disposable_emails = [
            'test@10minutemail.com',
            'user@guerrillamail.com',
            'temp@mailinator.com',
            'fake@tempmail.org',
            'spam@yopmail.com',
            'test@maildrop.cc',
            'user@sharklasers.com',
            'temp@trashmail.com'
        ]

        for disposable_email in disposable_emails:
            with self.subTest(email=disposable_email):
                data = self.valid_data.copy()
                data['email'] = disposable_email
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('email', serializer.errors)
                self.assertIn('disposable', str(serializer.errors['email'][0]).lower())

    def test_suspicious_domain_validation(self):
        """Test suspicious domain detection - Requirement 1.3"""
        suspicious_emails = [
            'test@123456.com',  # Too many numbers
            'user@ab.tk',       # Suspicious TLD
            'temp@x.ml',        # Very short domain with suspicious TLD
            'fake@999.ga',      # Numbers + suspicious TLD
        ]

        for suspicious_email in suspicious_emails:
            with self.subTest(email=suspicious_email):
                data = self.valid_data.copy()
                data['email'] = suspicious_email
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('email', serializer.errors)

    def test_duplicate_email_validation(self):
        """Test unique email validation - Requirement 1.1"""
        # Create existing user
        User.objects.create_user(email='existing@example.com', password='password123')

        data = self.valid_data.copy()
        data['email'] = 'existing@example.com'
        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)
        self.assertIn('already exists', str(serializer.errors['email'][0]))

    def test_password_strength_validation(self):
        """Test comprehensive password strength validation - Requirement 1.2"""
        weak_passwords = [
            'short',                    # Too short
            'nouppercase123!',         # No uppercase
            'NOLOWERCASE123!',         # No lowercase
            'NoNumbers!',              # No numbers
            'NoSpecialChars123',       # No special characters
            'password123',             # Common pattern
            'qwerty123!',              # Keyboard pattern
            '123456789!',              # Sequential numbers
            'Password123',             # Missing special character
            'a' * 129,                 # Too long
        ]

        for weak_password in weak_passwords:
            with self.subTest(password=weak_password):
                data = self.valid_data.copy()
                data['password'] = weak_password
                data['password_confirm'] = weak_password
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('password', serializer.errors)

    def test_password_entropy_validation(self):
        """Test password entropy calculation - Requirement 1.2"""
        low_entropy_passwords = [
            'password123!',            # Common pattern
            'Aaaa1!',                  # Too short and repeated
            'Abab1!',                  # Very low variety pattern
        ]

        for low_entropy_password in low_entropy_passwords:
            with self.subTest(password=low_entropy_password):
                data = self.valid_data.copy()
                data['password'] = low_entropy_password
                data['password_confirm'] = low_entropy_password
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('password', serializer.errors)

    def test_password_confirmation_validation(self):
        """Test password confirmation matching - Requirement 1.2"""
        data = self.valid_data.copy()
        data['password_confirm'] = 'Diff3r3nt&P@ssw0rd!'

        serializer = UserRegistrationSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password_confirm', serializer.errors)
        self.assertIn('do not match', str(serializer.errors['password_confirm'][0]))

    def test_name_validation_fake_patterns(self):
        """Test name validation for fake patterns - Requirement 1.7"""
        fake_names = [
            'test',
            'fake',
            'dummy',
            'admin',
            'null',
            'undefined',
            'asdf',
            'qwerty',
            '123',
            'abc',
            'xxx'
        ]

        for fake_name in fake_names:
            with self.subTest(name=fake_name):
                # Test first name
                data = self.valid_data.copy()
                data['first_name'] = fake_name
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('first_name', serializer.errors)

                # Test last name
                data = self.valid_data.copy()
                data['last_name'] = fake_name
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('last_name', serializer.errors)

    def test_name_validation_excessive_numbers(self):
        """Test name validation for excessive numbers - Requirement 1.7"""
        numeric_names = [
            '123456',
            'John123456',
            '999Test999',
            'Name12345'
        ]

        for numeric_name in numeric_names:
            with self.subTest(name=numeric_name):
                data = self.valid_data.copy()
                data['first_name'] = numeric_name
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('first_name', serializer.errors)

    def test_name_validation_repeated_characters(self):
        """Test name validation for repeated character patterns - Requirement 1.7"""
        repeated_names = [
            'aaaa',
            'bbbb',
            '1111',
            'xxxx'
        ]

        for repeated_name in repeated_names:
            with self.subTest(name=repeated_name):
                data = self.valid_data.copy()
                data['first_name'] = repeated_name
                serializer = UserRegistrationSerializer(data=data)
                self.assertFalse(serializer.is_valid())
                self.assertIn('first_name', serializer.errors)

    def test_optional_name_fields(self):
        """Test that name fields are optional."""
        data = self.valid_data.copy()
        del data['first_name']
        del data['last_name']

        serializer = UserRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())

        user = serializer.save()
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')

    def test_empty_name_fields_allowed(self):
        """Test that empty name fields are allowed."""
        data = self.valid_data.copy()
        data['first_name'] = ''
        data['last_name'] = ''

        serializer = UserRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())

    def test_email_normalization(self):
        """Test email normalization (lowercase, strip) - Requirement 1.1"""
        data = self.valid_data.copy()
        data['email'] = '  TEST@EXAMPLE.COM  '

        serializer = UserRegistrationSerializer(data=data)
        self.assertTrue(serializer.is_valid())

        user = serializer.save()
        self.assertEqual(user.email, 'test@example.com')

    def test_strong_password_acceptance(self):
        """Test that strong passwords are accepted - Requirement 1.2"""
        strong_passwords = [
            'MyC0mpl3x&UniqueP@ssw0rd!',
            'Str0ng!P@ssw0rd#2024',
            'C0mpl3x&S3cur3!P@ss',
            'Un1qu3$P@ssw0rd!2024',
            'S3cur3&R@nd0m!P@ss'
        ]

        for strong_password in strong_passwords:
            with self.subTest(password=strong_password):
                data = self.valid_data.copy()
                data['password'] = strong_password
                data['password_confirm'] = strong_password
                serializer = UserRegistrationSerializer(data=data)
                self.assertTrue(serializer.is_valid(), f"Strong password rejected: {serializer.errors}")

    def test_valid_name_acceptance(self):
        """Test that valid names are accepted - Requirement 1.7"""
        valid_names = [
            'John',
            'Mary-Jane',
            "O'Connor",
            'Jean-Pierre',
            'Anna Maria',
            'José',
            'François'
        ]

        for valid_name in valid_names:
            with self.subTest(name=valid_name):
                data = self.valid_data.copy()
                data['first_name'] = valid_name
                data['last_name'] = valid_name
                serializer = UserRegistrationSerializer(data=data)
                self.assertTrue(serializer.is_valid(), f"Valid name rejected: {serializer.errors}")

    @patch('authentication.serializers.logger')
    def test_user_creation_logging(self, mock_logger):
        """Test that user creation is properly logged."""
        serializer = UserRegistrationSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())

        user = serializer.save()

        # Verify logging was called
        mock_logger.info.assert_called_once_with(f"New user registered: {user.email}")

    def test_password_confirmation_removal(self):
        """Test that password_confirm is removed from validated data."""
        serializer = UserRegistrationSerializer(data=self.valid_data)
        self.assertTrue(serializer.is_valid())

        # password_confirm should not be in validated_data
        self.assertNotIn('password_confirm', serializer.validated_data)
        self.assertIn('password', serializer.validated_data)