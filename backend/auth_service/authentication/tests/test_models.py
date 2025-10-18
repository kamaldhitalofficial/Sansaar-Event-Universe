"""
Unit tests for authentication models.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model

User = get_user_model()


class UserModelTests(TestCase):
    """
    Test cases for User model functionality.
    """

    def test_create_user(self):
        """Test creating a regular user."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        self.assertEqual(user.email, 'test@example.com')
        self.assertFalse(user.is_active)  # Default inactive
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.check_password('testpass123'))

    def test_create_superuser(self):
        """Test creating a superuser."""
        user = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123'
        )

        self.assertEqual(user.email, 'admin@example.com')
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    def test_user_string_representation(self):
        """Test user string representation."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

        expected = 'John Doe (test@example.com)'
        self.assertEqual(str(user), expected)

    def test_user_string_representation_without_names(self):
        """Test user string representation without first/last names."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        self.assertEqual(str(user), 'test@example.com')

    def test_get_full_name(self):
        """Test get_full_name method."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

        self.assertEqual(user.get_full_name(), 'John Doe')

        # Test without names
        user_no_names = User.objects.create_user(
            email='test2@example.com',
            password='testpass123'
        )
        self.assertEqual(user_no_names.get_full_name(), 'test2@example.com')

    def test_get_short_name(self):
        """Test get_short_name method."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe'
        )

        self.assertEqual(user.get_short_name(), 'John')

        # Test without first name
        user_no_first = User.objects.create_user(
            email='test2@example.com',
            password='testpass123'
        )
        self.assertEqual(user_no_first.get_short_name(), 'test2@example.com')

    def test_account_locking(self):
        """Test account locking functionality."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        # Initially not locked
        self.assertFalse(user.is_account_locked())

        # Increment failed attempts
        for i in range(5):
            user.increment_failed_login()

        # Should be locked after 5 attempts
        self.assertTrue(user.is_account_locked())

        # Unlock account
        user.unlock_account()
        self.assertFalse(user.is_account_locked())
        self.assertEqual(user.failed_login_attempts, 0)

    def test_failed_login_increment(self):
        """Test failed login attempt incrementing."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        # Initial state
        self.assertEqual(user.failed_login_attempts, 0)

        # Increment attempts
        user.increment_failed_login()
        self.assertEqual(user.failed_login_attempts, 1)

        user.increment_failed_login()
        self.assertEqual(user.failed_login_attempts, 2)

    def test_reset_failed_login_attempts(self):
        """Test resetting failed login attempts."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        # Set some failed attempts
        user.failed_login_attempts = 3
        user.save()

        # Reset attempts
        user.reset_failed_login_attempts()
        self.assertEqual(user.failed_login_attempts, 0)

    def test_lock_account_duration(self):
        """Test account locking with specific duration."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        # Lock account for 60 minutes
        user.lock_account(duration_minutes=60)

        self.assertTrue(user.is_account_locked())
        self.assertIsNotNone(user.account_locked_until)

    def test_email_normalization(self):
        """Test email normalization in clean method."""
        user = User(
            email='  TEST@EXAMPLE.COM  ',
            password='testpass123'
        )

        user.clean()
        # The clean method normalizes the email (removes whitespace and normalizes domain)
        self.assertEqual(user.email, 'TEST@example.com')

    def test_user_manager_create_user_validation(self):
        """Test UserManager create_user validation."""
        with self.assertRaises(ValueError):
            User.objects.create_user(email='', password='testpass123')

        with self.assertRaises(ValueError):
            User.objects.create_user(email=None, password='testpass123')

    def test_user_manager_create_superuser_validation(self):
        """Test UserManager create_superuser validation."""
        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                email='admin@example.com',
                password='adminpass123',
                is_staff=False
            )

        with self.assertRaises(ValueError):
            User.objects.create_superuser(
                email='admin@example.com',
                password='adminpass123',
                is_superuser=False
            )