"""
Django settings for sansaar project (Development environment).
"""

from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST'),
        'PORT': config('DB_PORT'),
        'OPTIONS': {
            'sslmode': 'prefer',
        },
        'CONN_MAX_AGE': 600,
        'ATOMIC_REQUESTS': True,
    }
}

# CORS settings for development
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",   # React development server (default)
    "http://localhost:5173",   # Vite development server
    "http://localhost:8080",   # Flutter web development
    "http://localhost:5000",   # Flutter desktop
    "http://127.0.0.1:8000",   # Django development server
]

# Allow all origins in development (alternative to specific origins)
# CORS_ALLOW_ALL_ORIGINS = True

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# Development-specific file serving
# In development, Django can serve static and media files
import os

# Ensure directories exist in development
os.makedirs(MEDIA_ROOT, exist_ok=True)
os.makedirs(STATIC_ROOT, exist_ok=True)

# Create static directory for development if it doesn't exist
STATIC_DIR = BASE_DIR / 'static'
os.makedirs(STATIC_DIR, exist_ok=True)

STATICFILES_DIRS = [
    STATIC_DIR,
]