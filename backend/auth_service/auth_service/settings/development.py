"""
Django settings for sansaar project (Development environment).
"""

from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    },
}

# Session Configuration - Less secure for development
SESSION_COOKIE_SECURE = False

# Security Settings - Relaxed for development
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 0  # Disabled for development
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# CORS - More permissive for development
CORS_ALLOW_ALL_ORIGINS = True  # Only for development!

# Email - Console another_backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Logging Configuration - More verbose for development
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'auth_service' / 'logs' / 'django_dev.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'django.server': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
        'authentications': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

# Django REST Framework - More permissive for development
REST_FRAMEWORK.update({
    'DEFAULT_THROTTLE_RATES': {
        'anon': '1000/hour',  # More permissive for development
        'user': '10000/hour',
    }
})

# Development-specific authentication settings
MAX_LOGIN_ATTEMPTS = 10  # More lenient for development
ACCOUNT_LOCKOUT_DURATION = 5  # Shorter lockout for development