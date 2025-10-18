"""
Validation utilities for authentication.

This module contains various validation functions and classes for user input,
passwords, emails, names, and security-related validations.
"""

import re
import math
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password as django_validate_password


class DisposableEmailValidator:
    """
    Validator to check for disposable/temporary email addresses.
    Requirement 1.3: Email validation and disposable email detection.
    """

    # Common disposable email domains
    DISPOSABLE_DOMAINS = {
        '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
        'tempmail.org', 'yopmail.com', 'temp-mail.org', 'throwaway.email',
        'getnada.com', 'maildrop.cc', 'sharklasers.com', 'guerrillamailblock.com',
        'pokemail.net', 'spam4.me', 'bccto.me', 'chacuo.net', 'dispostable.com',
        'fakeinbox.com', 'spambox.us', 'tempr.email', 'trashmail.com',
        'wegwerfmail.de', 'zehnminuten.de', 'zetmail.com', '33mail.com',
        'mailnesia.com', 'mailcatch.com', 'mytrashmail.com', 'thankyou2010.com',
        'trash2009.com', 'mt2009.com', 'trashymail.com', 'mytrashmailer.com'
    }

    # Suspicious TLDs commonly used for disposable emails
    SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}

    def __call__(self, value):
        """
        Validate that the email is not from a disposable email provider.

        Args:
            value (str): Email address to validate

        Raises:
            ValidationError: If email is from disposable provider
        """
        if not value:
            return

        try:
            # Extract domain from email
            domain = value.lower().split('@')[1]
        except (IndexError, AttributeError):
            # Invalid email format - let other validators handle this
            return

        # Check against known disposable domains
        if domain in self.DISPOSABLE_DOMAINS:
            raise ValidationError(
                'Disposable email addresses are not allowed. Please use a permanent email address.'
            )

        # Check for suspicious domain patterns
        if any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
            raise ValidationError(
                'Email domain appears to be temporary. Please use a permanent email address.'
            )

        # Check for domains with excessive numbers (often disposable)
        if re.search(r'\d{4,}', domain):
            raise ValidationError(
                'Email domain appears to be temporary. Please use a permanent email address.'
            )

        # Check for very short domains (often suspicious)
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2 and len(domain_parts[0]) <= 2:
            raise ValidationError(
                'Email domain appears to be temporary. Please use a permanent email address.'
            )


class PasswordStrengthValidator:
    """
    Advanced password strength validator with entropy calculation.
    Requirement 1.2: Strong password validation with entropy analysis.
    """

    def __init__(self, min_entropy=50, min_length=8, max_length=128):
        self.min_entropy = min_entropy
        self.min_length = min_length
        self.max_length = max_length

        # Common password patterns to reject
        self.common_patterns = {
            'password', '123456', 'qwerty', 'abc123', 'admin', 'letmein',
            'welcome', 'monkey', 'dragon', 'master', 'shadow', 'superman',
            'michael', 'football', 'baseball', 'liverpool', 'jordan'
        }

        # Keyboard patterns
        self.keyboard_patterns = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', '0987654321',
            'qwerty', 'asdfgh', 'zxcvbn', '123456', '654321'
        ]

    def calculate_entropy(self, password):
        """
        Calculate password entropy based on character set and length.

        Args:
            password (str): Password to analyze

        Returns:
            float: Entropy value in bits
        """
        if not password:
            return 0

        # Determine character set size
        charset_size = 0

        if re.search(r'[a-z]', password):
            charset_size += 26  # lowercase letters
        if re.search(r'[A-Z]', password):
            charset_size += 26  # uppercase letters
        if re.search(r'\d', password):
            charset_size += 10  # digits
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32  # common special characters
        if re.search(r'[^\w\s!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32  # other special characters

        # Calculate entropy: log2(charset_size^length)
        if charset_size > 0:
            entropy = len(password) * math.log2(charset_size)
        else:
            entropy = 0

        # Reduce entropy for common patterns
        password_lower = password.lower()

        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            entropy *= 0.7

        # Check for sequential characters
        sequential_patterns = ['abcdefghijklmnopqrstuvwxyz', '0123456789']
        for pattern in sequential_patterns:
            for i in range(len(pattern) - 2):
                if pattern[i:i+3] in password_lower or pattern[i:i+3][::-1] in password_lower:
                    entropy *= 0.8
                    break

        # Check for keyboard patterns
        for pattern in self.keyboard_patterns:
            if pattern in password_lower:
                entropy *= 0.6
                break

        # Check for common patterns
        for pattern in self.common_patterns:
            if pattern in password_lower:
                entropy *= 0.5
                break

        return entropy

    def __call__(self, password):
        """
        Validate password strength.

        Args:
            password (str): Password to validate

        Raises:
            ValidationError: If password doesn't meet strength requirements
        """
        if not password:
            raise ValidationError('Password is required.')

        errors = []

        # Length validation
        if len(password) < self.min_length:
            errors.append(f'Password must be at least {self.min_length} characters long.')

        if len(password) > self.max_length:
            errors.append(f'Password cannot exceed {self.max_length} characters.')

        # Character set requirements
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter.')

        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter.')

        if not re.search(r'\d', password):
            errors.append('Password must contain at least one digit.')

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append('Password must contain at least one special character.')

        # Common pattern detection
        password_lower = password.lower()

        for pattern in self.common_patterns:
            if pattern in password_lower:
                errors.append(f'Password cannot contain common patterns like "{pattern}".')
                break

        # Keyboard pattern detection
        for pattern in self.keyboard_patterns:
            if pattern in password_lower:
                errors.append('Password cannot contain keyboard patterns (e.g., qwerty, 123456).')
                break

        # Repeated character detection
        if re.search(r'(.)\1{3,}', password):
            errors.append('Password cannot contain more than 3 consecutive identical characters.')

        # Entropy validation
        entropy = self.calculate_entropy(password)
        if entropy < self.min_entropy:
            errors.append(f'Password is too predictable. Please use a more complex password.')

        if errors:
            raise ValidationError(errors)


class NameValidator:
    """
    Validator for first and last names to detect fake or suspicious entries.
    Requirement 1.7: Name validation and fake pattern detection.
    """

    def __init__(self, min_length=2, max_length=50):
        self.min_length = min_length
        self.max_length = max_length

        # Common fake name patterns
        self.fake_patterns = {
            'test', 'fake', 'dummy', 'admin', 'null', 'undefined', 'asdf',
            'qwerty', 'temp', 'temporary', 'example', 'sample', 'demo',
            'user', 'name', 'firstname', 'lastname', 'fname', 'lname'
        }

    def __call__(self, value):
        """
        Validate name for fake patterns and suspicious content.

        Args:
            value (str): Name to validate

        Raises:
            ValidationError: If name appears fake or suspicious
        """
        # Allow empty names (optional fields)
        if not value:
            return

        value = value.strip()

        # Length validation
        if len(value) < self.min_length:
            raise ValidationError(f'Name must be at least {self.min_length} characters long.')

        if len(value) > self.max_length:
            raise ValidationError(f'Name cannot exceed {self.max_length} characters.')

        # Character validation - allow letters, spaces, hyphens, apostrophes
        if not re.match(r"^[a-zA-ZÀ-ÿ\s\-']+$", value):
            raise ValidationError('Name can only contain letters, spaces, hyphens, and apostrophes.')

        # Check for fake patterns
        value_lower = value.lower()
        for pattern in self.fake_patterns:
            if pattern in value_lower:
                raise ValidationError('Please enter a valid name.')

        # Check for excessive numbers (shouldn't happen with regex above, but extra safety)
        if re.search(r'\d{3,}', value):
            raise ValidationError('Name cannot contain multiple consecutive numbers.')

        # Check for repeated characters (likely fake)
        if re.search(r'(.)\1{3,}', value):
            raise ValidationError('Name cannot contain more than 3 consecutive identical characters.')

        # Check for single character names (except for middle initials)
        if len(value) == 1:
            raise ValidationError('Name must be at least 2 characters long.')


# Additional MFA-related validation functions

def validate_password_strength(password):
    """
    Validate password strength with custom rules.

    Requirements:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    - Not a common password (uses Django's built-in validation)

    Args:
        password (str): Password to validate

    Raises:
        ValidationError: If password doesn't meet requirements
    """
    # Use Django's built-in password validation first
    try:
        django_validate_password(password)
    except ValidationError as e:
        raise ValidationError(e.messages)

    # Additional custom validations
    errors = []

    # Check minimum length
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")

    # Check for uppercase letter
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")

    # Check for lowercase letter
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")

    # Check for digit
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit.")

    # Check for special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>).")

    # Check for common patterns
    if re.search(r'(.)\1{2,}', password):
        errors.append("Password cannot contain more than 2 consecutive identical characters.")

    # Check for sequential characters
    sequential_patterns = [
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        'qwertyuiopasdfghjklzxcvbnm'
    ]

    password_lower = password.lower()
    for pattern in sequential_patterns:
        for i in range(len(pattern) - 2):
            if pattern[i:i+3] in password_lower or pattern[i:i+3][::-1] in password_lower:
                errors.append("Password cannot contain sequential characters (e.g., abc, 123, qwe).")
                break
        if errors:
            break

    if errors:
        raise ValidationError(errors)

    return True


def validate_email_format(email):
    """
    Validate email format with additional checks.

    Args:
        email (str): Email to validate

    Raises:
        ValidationError: If email format is invalid
    """
    try:
        validate_email(email)
    except ValidationError:
        raise ValidationError("Enter a valid email address.")

    # Additional checks
    if len(email) > 254:
        raise ValidationError("Email address is too long.")

    local_part, domain = email.rsplit('@', 1)

    if len(local_part) > 64:
        raise ValidationError("Email local part is too long.")

    # Check for suspicious patterns
    suspicious_patterns = [
        r'\.{2,}',  # Multiple consecutive dots
        r'^\.|\.$',  # Starting or ending with dot
        r'[<>]',  # Angle brackets
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, email):
            raise ValidationError("Email contains invalid characters or patterns.")

    return True


def validate_device_name(device_name):
    """
    Validate MFA device name.

    Args:
        device_name (str): Device name to validate

    Raises:
        ValidationError: If device name is invalid
    """
    if not device_name or not device_name.strip():
        raise ValidationError("Device name cannot be empty.")

    device_name = device_name.strip()

    if len(device_name) < 2:
        raise ValidationError("Device name must be at least 2 characters long.")

    if len(device_name) > 100:
        raise ValidationError("Device name cannot exceed 100 characters.")

    # Check for valid characters (alphanumeric, spaces, hyphens, underscores)
    if not re.match(r'^[a-zA-Z0-9\s\-_]+$', device_name):
        raise ValidationError("Device name can only contain letters, numbers, spaces, hyphens, and underscores.")

    # Check for suspicious patterns
    if re.search(r'[<>"\']', device_name):
        raise ValidationError("Device name contains invalid characters.")

    return True


def validate_totp_code(code):
    """
    Validate TOTP code format.

    Args:
        code (str): TOTP code to validate

    Raises:
        ValidationError: If code format is invalid
    """
    if not code:
        raise ValidationError("TOTP code is required.")

    code = code.strip()

    if len(code) != 6:
        raise ValidationError("TOTP code must be exactly 6 digits.")

    if not code.isdigit():
        raise ValidationError("TOTP code must contain only digits.")

    return True


def validate_backup_code(code):
    """
    Validate backup code format.

    Args:
        code (str): Backup code to validate

    Raises:
        ValidationError: If code format is invalid
    """
    if not code:
        raise ValidationError("Backup code is required.")

    code = code.strip().upper()

    if len(code) != 8:
        raise ValidationError("Backup code must be exactly 8 characters.")

    if not code.isalnum():
        raise ValidationError("Backup code must contain only letters and numbers.")

    return True


def validate_user_agent(user_agent):
    """
    Validate and sanitize user agent string.

    Args:
        user_agent (str): User agent string to validate

    Returns:
        str: Sanitized user agent string
    """
    if not user_agent:
        return "Unknown"

    # Limit length
    user_agent = user_agent[:500]

    # Remove potentially dangerous characters
    user_agent = re.sub(r'[<>"\']', '', user_agent)

    return user_agent


def validate_ip_address(ip_address):
    """
    Validate IP address format.

    Args:
        ip_address (str): IP address to validate

    Raises:
        ValidationError: If IP address is invalid
    """
    import ipaddress

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise ValidationError("Invalid IP address format.")

    return True