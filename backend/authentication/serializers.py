"""
Serializers for authentication app.
"""
import re
import requests
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.utils import timezone
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

# List of known disposable email domains
DISPOSABLE_EMAIL_DOMAINS = {
    '10minutemail.com', 'guerrillamail.com', 'mailinator.com', 'tempmail.org',
    'temp-mail.org', 'throwaway.email', 'yopmail.com', 'maildrop.cc',
    'sharklasers.com', 'guerrillamailblock.com', 'pokemail.net', 'spam4.me',
    'bccto.me', 'chacuo.net', 'dispostable.com', 'spambox.us', 'trbvm.com',
    'wegwerfmail.de', 'zehnminutenmail.de', 'zetmail.com', '33mail.com',
    'getnada.com', 'mailnesia.com', 'trashmail.com', 'fakeinbox.com'
}


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration with comprehensive validation.
    """
    email = serializers.EmailField(
        validators=[
            EmailValidator(message="Enter a valid email address."),
            UniqueValidator(
                queryset=User.objects.all(),
                message="A user with this email already exists."
            )
        ]
    )
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        max_length=128,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    first_name = serializers.CharField(
        max_length=150,
        required=False,
        allow_blank=True
    )
    last_name = serializers.CharField(
        max_length=150,
        required=False,
        allow_blank=True
    )

    class Meta:
        model = User
        fields = ('email', 'password', 'password_confirm', 'first_name', 'last_name')

    def validate_email(self, value):
        """
        Validate email format and check for disposable email providers.
        """
        # Normalize email
        email = value.lower().strip()

        # Extract domain
        domain = email.split('@')[1] if '@' in email else ''

        # Check for disposable email domains
        if domain in DISPOSABLE_EMAIL_DOMAINS:
            raise serializers.ValidationError(
                "Registration with disposable email addresses is not allowed."
            )

        # Additional domain validation - check for suspicious patterns
        if self._is_suspicious_domain(domain):
            raise serializers.ValidationError(
                "This email domain appears to be temporary or suspicious."
            )

        return email

    def validate_first_name(self, value):
        """
        Validate first name for profanity and fake patterns.
        """
        if value:
            value = value.strip()
            if self._contains_profanity_or_fake_patterns(value):
                raise serializers.ValidationError(
                    "Please enter a valid first name."
                )
        return value

    def validate_last_name(self, value):
        """
        Validate last name for profanity and fake patterns.
        """
        if value:
            value = value.strip()
            if self._contains_profanity_or_fake_patterns(value):
                raise serializers.ValidationError(
                    "Please enter a valid last name."
                )
        return value

    def validate_password(self, value):
        """
        Validate password strength with comprehensive requirements.
        """
        # Check minimum length
        if len(value) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )

        # Check maximum length
        if len(value) > 128:
            raise serializers.ValidationError(
                "Password must be no more than 128 characters long."
            )

        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )

        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )

        # Check for at least one digit
        if not re.search(r'\d', value):
            raise serializers.ValidationError(
                "Password must contain at least one number."
            )

        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError(
                "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."
            )

        # Check for common patterns
        if self._contains_common_patterns(value):
            raise serializers.ValidationError(
                "Password contains common patterns that are not secure."
            )

        # Calculate password entropy (basic check)
        entropy = self._calculate_password_entropy(value)
        if entropy < 50:  # Minimum entropy threshold
            raise serializers.ValidationError(
                "Password is not complex enough. Please use a more varied combination of characters."
            )

        # Use Django's built-in password validators
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)

        return value

    def validate(self, attrs):
        """
        Validate that passwords match and perform cross-field validation.
        """
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')

        if password != password_confirm:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match.'
            })

        # Remove password_confirm from attrs as it's not needed for user creation
        attrs.pop('password_confirm', None)

        return attrs

    def create(self, validated_data):
        """
        Create a new user with validated data.
        """
        # Extract password before creating user
        password = validated_data.pop('password')

        # Create user (inactive by default, requires email verification)
        user = User.objects.create_user(
            password=password,
            is_active=False,  # User must verify email first
            **validated_data
        )

        logger.info(f"New user registered: {user.email}")
        return user

    def _is_suspicious_domain(self, domain):
        """
        Check if domain appears suspicious (basic heuristics).
        """
        # Check for domains with excessive numbers
        if len(re.findall(r'\d', domain)) > len(domain) * 0.5:
            return True

        # Check for very short domains (less than 4 characters before TLD)
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2 and len(domain_parts[0]) < 4:
            return True

        # Check for suspicious TLDs commonly used by disposable services
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq'}
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True

        return False

    def _contains_profanity_or_fake_patterns(self, name):
        """
        Check for profanity and fake name patterns.
        """
        name_lower = name.lower()

        # Basic profanity check (simplified list)
        profanity_words = {
            'test', 'fake', 'dummy', 'admin', 'null', 'undefined',
            'asdf', 'qwerty', '123', 'abc', 'xxx'
        }

        if name_lower in profanity_words:
            return True

        # Check for repeated characters (like "aaaa" or "1111")
        if len(set(name_lower)) <= 2 and len(name) > 3:
            return True

        # Check for excessive numbers
        if len(re.findall(r'\d', name)) > len(name) * 0.5:
            return True

        return False

    def _contains_common_patterns(self, password):
        """
        Check for common password patterns.
        """
        password_lower = password.lower()

        # Only check for exact matches of very common weak passwords
        exact_weak_passwords = {
            '123456', 'password', 'qwerty', 'abc123',
            'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'superman',
            '12345678', 'password123', 'admin123'
        }

        if password_lower in exact_weak_passwords:
            return True

        # Check for long keyboard patterns (6+ characters)
        keyboard_patterns = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', '0987654321', 'qwerty',
            'asdfgh', 'zxcvbn'
        ]

        for pattern in keyboard_patterns:
            if len(pattern) >= 6 and (pattern in password_lower or pattern[::-1] in password_lower):
                return True

        return False

    def _calculate_password_entropy(self, password):
        """
        Calculate basic password entropy.
        """
        import math

        # Character set sizes
        lowercase = any(c.islower() for c in password)
        uppercase = any(c.isupper() for c in password)
        digits = any(c.isdigit() for c in password)
        special = any(c in '!@#$%^&*(),.?":{}|<>' for c in password)

        charset_size = 0
        if lowercase:
            charset_size += 26
        if uppercase:
            charset_size += 26
        if digits:
            charset_size += 10
        if special:
            charset_size += 20  # Approximate number of common special chars

        if charset_size == 0:
            return 0

        # Entropy = log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)
        return entropy


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login with comprehensive validation.
    """
    email = serializers.EmailField(
        validators=[EmailValidator(message="Enter a valid email address.")]
    )
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    remember_me = serializers.BooleanField(default=False, required=False)

    def validate(self, attrs):
        """
        Validate login credentials and check account status.
        """
        email = attrs.get('email', '').lower().strip()
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError({
                'non_field_errors': ['Email and password are required.']
            })

        # Get user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'non_field_errors': ['Invalid email or password.']
            })

        # Check if account is locked
        if user.is_account_locked():
            lock_time_remaining = user.account_locked_until - timezone.now()
            minutes_remaining = int(lock_time_remaining.total_seconds() / 60)
            raise serializers.ValidationError({
                'non_field_errors': [
                    f'Account is locked due to multiple failed login attempts. '
                    f'Please try again in {minutes_remaining} minutes.'
                ]
            })

        # Check if account is active
        if not user.is_active:
            raise serializers.ValidationError({
                'non_field_errors': ['Account is not active. Please verify your email address.']
            })

        # Authenticate user
        if not user.check_password(password):
            # Increment failed login attempts
            user.increment_failed_login()

            # Log failed attempt
            logger.warning(f"Failed login attempt for user: {email}")

            raise serializers.ValidationError({
                'non_field_errors': ['Invalid email or password.']
            })

        # Reset failed login attempts on successful authentication
        user.reset_failed_login_attempts()

        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        attrs['user'] = user
        return attrs


class TokenRefreshSerializer(serializers.Serializer):
    """
    Serializer for refreshing access tokens.
    """
    refresh_token = serializers.CharField(write_only=True)

    def validate_refresh_token(self, value):
        """
        Validate the refresh token using SimpleJWT.
        """
        from rest_framework_simplejwt.tokens import RefreshToken
        from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

        try:
            RefreshToken(value)
        except (InvalidToken, TokenError) as e:
            raise serializers.ValidationError(f'Invalid refresh token: {str(e)}')

        return value


class LogoutSerializer(serializers.Serializer):
    """
    Serializer for user logout.
    """
    logout_all_devices = serializers.BooleanField(default=False, required=False)