"""
Unit tests for authentication validators.
Tests Requirements: 1.1, 1.2, 1.3, 1.7
"""
from django.test import TestCase
from django.core.exceptions import ValidationError

from ..utils.validators import DisposableEmailValidator, PasswordStrengthValidator, NameValidator


class DisposableEmailValidatorTests(TestCase):
    """
    Unit tests for DisposableEmailValidator - Requirement 1.3
    """

    def setUp(self):
        self.validator = DisposableEmailValidator()

    def test_valid_email_domains(self):
        """Test that valid email domains pass validation."""
        valid_emails = [
            'test@gmail.com',
            'user@yahoo.com',
            'contact@company.com',
            'info@university.edu',
            'admin@government.gov'
        ]

        for email in valid_emails:
            with self.subTest(email=email):
                try:
                    self.validator(email)
                except ValidationError:
                    self.fail(f"Valid email {email} was rejected")

    def test_disposable_email_domains(self):
        """Test that disposable email domains are rejected."""
        disposable_emails = [
            'test@10minutemail.com',
            'user@guerrillamail.com',
            'temp@mailinator.com',
            'fake@tempmail.org',
            'spam@yopmail.com'
        ]

        for email in disposable_emails:
            with self.subTest(email=email):
                with self.assertRaises(ValidationError):
                    self.validator(email)

    def test_suspicious_domain_patterns(self):
        """Test that suspicious domain patterns are rejected."""
        suspicious_emails = [
            'test@123456.com',  # Too many numbers
            'user@ab.tk',       # Suspicious TLD
            'temp@x.ml',        # Very short domain
            'fake@999.ga'       # Numbers + suspicious TLD
        ]

        for email in suspicious_emails:
            with self.subTest(email=email):
                with self.assertRaises(ValidationError):
                    self.validator(email)

    def test_invalid_email_format_ignored(self):
        """Test that invalid email formats are ignored by this validator."""
        invalid_emails = [
            'invalid-email',
            'test@',
            '@example.com'
        ]

        for email in invalid_emails:
            with self.subTest(email=email):
                try:
                    self.validator(email)
                except ValidationError:
                    self.fail(f"Validator should ignore invalid format: {email}")


class PasswordStrengthValidatorTests(TestCase):
    """
    Unit tests for PasswordStrengthValidator - Requirement 1.2
    """

    def setUp(self):
        self.validator = PasswordStrengthValidator(min_entropy=50)

    def test_strong_passwords_accepted(self):
        """Test that strong passwords are accepted."""
        strong_passwords = [
            'MyC0mpl3x&UniqueP@ssw0rd!',
            'Str0ng!P@ssw0rd#2024',
            'C0mpl3x&S3cur3!P@ss',
            'Un1qu3$P@ssw0rd!2024'
        ]

        for password in strong_passwords:
            with self.subTest(password=password):
                try:
                    self.validator(password)
                except ValidationError:
                    self.fail(f"Strong password was rejected: {password}")

    def test_weak_passwords_rejected(self):
        """Test that weak passwords are rejected."""
        weak_passwords = [
            'short',                    # Too short
            'nouppercase123!',         # No uppercase
            'NOLOWERCASE123!',         # No lowercase
            'NoNumbers!',              # No numbers
            'NoSpecialChars123',       # No special characters
            'password123',             # Common pattern
            'qwerty123!',              # Keyboard pattern
            'a' * 129,                 # Too long
        ]

        for password in weak_passwords:
            with self.subTest(password=password):
                with self.assertRaises(ValidationError):
                    self.validator(password)

    def test_common_pattern_detection(self):
        """Test detection of common password patterns."""
        common_patterns = [
            'password',
            '123456',
            'qwerty',
            'abc123',
            'admin',
            'letmein'
        ]

        for pattern in common_patterns:
            with self.subTest(pattern=pattern):
                with self.assertRaises(ValidationError):
                    self.validator(pattern)

    def test_keyboard_pattern_detection(self):
        """Test detection of keyboard patterns."""
        keyboard_patterns = [
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm',
            '1234567890',
            '0987654321'
        ]

        for pattern in keyboard_patterns:
            with self.subTest(pattern=pattern):
                with self.assertRaises(ValidationError):
                    self.validator(pattern)

    def test_entropy_calculation(self):
        """Test password entropy calculation."""
        # Low entropy password
        low_entropy = 'Aaaaaaaa1!'
        with self.assertRaises(ValidationError):
            self.validator(low_entropy)

        # High entropy password
        high_entropy = 'MyC0mpl3x&UniqueP@ssw0rd!'
        try:
            self.validator(high_entropy)
        except ValidationError:
            self.fail("High entropy password was rejected")


class NameValidatorTests(TestCase):
    """
    Unit tests for NameValidator - Requirement 1.7
    """

    def setUp(self):
        self.validator = NameValidator()

    def test_valid_names_accepted(self):
        """Test that valid names are accepted."""
        valid_names = [
            'John',
            'Mary-Jane',
            "O'Connor",
            'Jean-Pierre',
            'Anna Maria',
            'José',
            'François'
        ]

        for name in valid_names:
            with self.subTest(name=name):
                try:
                    self.validator(name)
                except ValidationError:
                    self.fail(f"Valid name was rejected: {name}")

    def test_fake_patterns_rejected(self):
        """Test that fake name patterns are rejected."""
        fake_names = [
            'test',
            'fake',
            'dummy',
            'admin',
            'null',
            'undefined',
            'asdf',
            'qwerty'
        ]

        for name in fake_names:
            with self.subTest(name=name):
                with self.assertRaises(ValidationError):
                    self.validator(name)

    def test_excessive_numbers_rejected(self):
        """Test that names with excessive numbers are rejected."""
        numeric_names = [
            '123456',
            'John123456',
            '999Test999'
        ]

        for name in numeric_names:
            with self.subTest(name=name):
                with self.assertRaises(ValidationError):
                    self.validator(name)

    def test_repeated_characters_rejected(self):
        """Test that names with repeated characters are rejected."""
        repeated_names = [
            'aaaa',
            'bbbb',
            '1111',
            'xxxx'
        ]

        for name in repeated_names:
            with self.subTest(name=name):
                with self.assertRaises(ValidationError):
                    self.validator(name)

    def test_empty_names_allowed(self):
        """Test that empty names are allowed."""
        try:
            self.validator('')
            self.validator(None)
        except ValidationError:
            self.fail("Empty names should be allowed")

    def test_name_length_validation(self):
        """Test name length validation."""
        # Too short
        with self.assertRaises(ValidationError):
            self.validator('A')

        # Too long
        long_name = 'A' * 51
        with self.assertRaises(ValidationError):
            self.validator(long_name)

    def test_invalid_characters_rejected(self):
        """Test that names with invalid characters are rejected."""
        invalid_names = [
            'John123',
            'Mary@Smith',
            'Test#Name',
            'Name$Test',
            'User%Name'
        ]

        for name in invalid_names:
            with self.subTest(name=name):
                with self.assertRaises(ValidationError):
                    self.validator(name)