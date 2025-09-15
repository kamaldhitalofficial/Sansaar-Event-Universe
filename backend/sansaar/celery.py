"""
Celery configuration for sansaar project.

This module configures Celery for handling asynchronous tasks like
email sending, background processing, and scheduled tasks.
"""

import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sansaar.settings.development')

app = Celery('sansaar')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Celery Beat Schedule for periodic tasks
app.conf.beat_schedule = {
    'cleanup-expired-tokens': {
        'task': 'authentications.tasks.cleanup_expired_tokens',
        'schedule': 3600.0,  # Run every hour
    },
    'cleanup-failed-login-attempts': {
        'task': 'authentications.tasks.cleanup_failed_login_attempts',
        'schedule': 1800.0,  # Run every 30 minutes
    },
}

app.conf.timezone = 'UTC'

@app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery configuration."""
    print(f'Request: {self.request!r}')
