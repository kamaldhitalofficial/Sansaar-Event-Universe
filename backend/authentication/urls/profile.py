"""
Profile management URLs - directly under /api/
"""
from django.urls import path
from ..views import (
    get_profile, update_profile, upload_profile_picture,
    delete_profile_picture, get_profile_completion,
    update_privacy_settings, update_communication_preferences,
    get_profile_history, get_profile_statistics, get_public_profile,
    delete_profile, reset_profile
)

app_name = 'profile'

urlpatterns = [
    # Profile Management (under /api/)
    path('profile/', get_profile, name='get_profile'),
    path('profile/update/', update_profile, name='update_profile'),
    path('profile/delete/', delete_profile, name='delete_profile'),
    path('profile/reset/', reset_profile, name='reset_profile'),
    path('profile/picture/', upload_profile_picture, name='upload_profile_picture'),
    path('profile/picture/delete/', delete_profile_picture, name='delete_profile_picture'),
    path('profile/completion/', get_profile_completion, name='get_profile_completion'),
    path('profile/privacy/', update_privacy_settings, name='update_privacy_settings'),
    path('profile/communication/', update_communication_preferences, name='update_communication_preferences'),
    path('profile/history/', get_profile_history, name='get_profile_history'),
    path('profile/statistics/', get_profile_statistics, name='get_profile_statistics'),
    path('users/<uuid:user_id>/', get_public_profile, name='get_public_profile'),
]