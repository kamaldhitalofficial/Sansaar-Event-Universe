import re
import requests
from django.core.exceptions import ValidationError
from django.core.cache import cache

class PasswordValidator:
    """
    Validates password strength:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    
    @staticmethod
    def validate(password):
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        
        if not re.search(r'[a-z]', password):
            raise ValidationError("Password must contain at least one lowercase letter.")
        
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one digit.")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("Password must contain at least one special character.")
        
        # Check against common passwords
        common_passwords = [
            'password', '12345678', 'qwerty', 'abc123', 
            'password123', 'admin123', 'letmein'
        ]
        if password.lower() in common_passwords:
            raise ValidationError("This password is too common.")
        
        return True


class DisposableEmailValidator:
    """
    Validates against disposable email addresses using multiple methods
    """
    
    DISPOSABLE_DOMAINS_CACHE_KEY = 'disposable_email_domains'
    CACHE_TIMEOUT = 86400  # 24 hours
    
    # Common disposable email domains (fallback list)
    KNOWN_DISPOSABLE = {
        'tempmail.com', 'guerrillamail.com', '10minutemail.com',
        'mailinator.com', 'throwaway.email', 'temp-mail.org',
        'fakeinbox.com', 'trashmail.com', 'yopmail.com',
        'maildrop.cc', 'sharklasers.com', 'guerrillamail.info',
    }
    
    @classmethod
    def get_disposable_domains(cls):
        """Fetch and cache disposable email domains"""
        cached = cache.get(cls.DISPOSABLE_DOMAINS_CACHE_KEY)
        if cached:
            return cached
        
        domains = cls.KNOWN_DISPOSABLE.copy()
        
        try:
            # Fetch from public API
            response = requests.get(
                'https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt',
                timeout=5
            )
            if response.status_code == 200:
                online_domains = set(response.text.strip().split('\n'))
                domains.update(online_domains)
        except:
            pass  # Fall back to known list
        
        cache.set(cls.DISPOSABLE_DOMAINS_CACHE_KEY, domains, cls.CACHE_TIMEOUT)
        return domains
    
    @classmethod
    def validate(cls, email):
        domain = email.split('@')[-1].lower()
        disposable_domains = cls.get_disposable_domains()
        
        if domain in disposable_domains:
            raise ValidationError(
                "Disposable email addresses are not allowed. Please use a permanent email address."
            )
        
        return True