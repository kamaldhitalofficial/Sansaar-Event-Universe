from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import re

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration with comprehensive validation.
    Handles first name, last name, username, email, password, and confirm password validation.
    """
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        max_length=128,
        style={'input_type': 'password'},
        help_text="Password must be at least 8 characters long and contain a mix of letters, numbers, and symbols."
    )
    confirm_password = serializers.CharField(
        write_only=True,
        min_length=8,
        max_length=128,
        style={'input_type': 'password'},
        help_text="Re-enter the password for confirmation."
    )
    email = serializers.EmailField(
        required=True,
        help_text="A valid email address is required for account verification."
    )
    first_name = serializers.CharField(
        required=True,
        min_length=2,
        max_length=30,
        help_text="First name is required and must be between 2-30 characters."
    )
    last_name = serializers.CharField(
        required=True,
        min_length=2,
        max_length=30,
        help_text="Last name is required and must be between 2-30 characters."
    )
    username = serializers.CharField(
        required=True,
        min_length=3,
        max_length=150,
        help_text="Username must be 3-150 characters and contain only letters, numbers, and @/./+/-/_ characters."
    )

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'username', 'email', 'password', 'confirm_password')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True},
        }

    def validate_email(self, value):
        """
        Validate email uniqueness and format
        """
        if not value:
            raise serializers.ValidationError("Email is required.")
        
        # Convert to lowercase for consistency
        value = value.lower()
        
        # Check if email already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        
        # Additional email format validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, value):
            raise serializers.ValidationError("Enter a valid email address.")
        
        return value

    def validate_username(self, value):
        """
        Validate username uniqueness and format
        """
        if not value:
            raise serializers.ValidationError("Username is required.")
        
        # Check if username already exists
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        
        # Username format validation (letters, numbers, and @/./+/-/_ only)
        username_regex = r'^[\w.@+-]+$'
        if not re.match(username_regex, value):
            raise serializers.ValidationError(
                "Username can only contain letters, numbers, and @/./+/-/_ characters."
            )
        
        return value

    def validate_first_name(self, value):
        """
        Validate first name format
        """
        if not value or not value.strip():
            raise serializers.ValidationError("First name is required.")
        
        # Remove extra whitespace and capitalize
        value = value.strip().title()
        
        # Check for valid characters (letters, spaces, hyphens, apostrophes)
        name_regex = r"^[a-zA-Z\s\-']+$"
        if not re.match(name_regex, value):
            raise serializers.ValidationError(
                "First name can only contain letters, spaces, hyphens, and apostrophes."
            )
        
        return value

    def validate_last_name(self, value):
        """
        Validate last name format
        """
        if not value or not value.strip():
            raise serializers.ValidationError("Last name is required.")
        
        # Remove extra whitespace and capitalize
        value = value.strip().title()
        
        # Check for valid characters (letters, spaces, hyphens, apostrophes)
        name_regex = r"^[a-zA-Z\s\-']+$"
        if not re.match(name_regex, value):
            raise serializers.ValidationError(
                "Last name can only contain letters, spaces, hyphens, and apostrophes."
            )
        
        return value

    def validate_password(self, value):
        """
        Validate password strength using Django's built-in validators and custom rules
        """
        if not value:
            raise serializers.ValidationError("Password is required.")
        
        # Use Django's built-in password validation
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(list(e.messages))
        
        # Additional custom password strength validation
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        
        # Check for at least one letter
        if not re.search(r'[a-zA-Z]', value):
            raise serializers.ValidationError("Password must contain at least one letter.")
        
        # Check for at least one number
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number.")
        
        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError(
                "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."
            )
        
        return value

    def validate(self, attrs):
        """
        Validate that password and confirm_password match
        """
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        
        if password != confirm_password:
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match.'
            })
        
        return attrs

    def create(self, validated_data):
        """
        Create a new user with the validated data
        """
        # Remove confirm_password from validated_data since it's not needed for user creation
        validated_data.pop('confirm_password', None)
        
        # Create user with encrypted password
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=True,  # User is active but email not verified
            is_email_verified=False  # Email verification required
        )
        
        # Generate email verification token
        user.generate_verification_token()
        
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile information (read-only)
    """
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'full_name', 
                 'is_email_verified', 'date_joined', 'date_updated')
        read_only_fields = ('id', 'username', 'email', 'is_email_verified', 
                           'date_joined', 'date_updated')
    
    def get_full_name(self, obj):
        """
        Return the user's full name
        """
        return f"{obj.first_name} {obj.last_name}".strip()


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for email verification endpoint
    """
    token = serializers.UUIDField(
        required=True,
        help_text="Email verification token received via email"
    )
    
    def validate_token(self, value):
        """
        Validate that the token exists and belongs to a user
        """
        try:
            user = User.objects.get(email_verification_token=value, is_email_verified=False)
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired verification token.")


class ResendVerificationSerializer(serializers.Serializer):
    """
    Serializer for resending email verification
    """
    email = serializers.EmailField(
        required=True,
        help_text="Email address to resend verification email to"
    )
    
    def validate_email(self, value):
        """
        Validate that the email exists and belongs to an unverified user
        """
        if not value:
            raise serializers.ValidationError("Email is required.")
        
        # Convert to lowercase for consistency
        value = value.lower()
        
        try:
            user = User.objects.get(email=value)
            if user.is_email_verified:
                raise serializers.ValidationError("This email is already verified.")
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError("No account found with this email address.")


class ResendVerificationEmailSerializer(serializers.Serializer):
    """
    Serializer for resending email verification
    """
    email = serializers.EmailField(
        required=True,
        help_text="Email address to resend verification to"
    )
    
    def validate_email(self, value):
        """
        Validate email format and convert to lowercase
        """
        if not value:
            raise serializers.ValidationError("Email is required.")
        
        # Convert to lowercase for consistency
        value = value.lower()
        
        # Additional email format validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, value):
            raise serializers.ValidationError("Enter a valid email address.")
        
        return value