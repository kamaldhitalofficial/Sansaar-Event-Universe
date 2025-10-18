"""
URL patterns for privacy management endpoints.
"""
from django.urls import path
from ..views.privacy import (
    get_privacy_settings,
    update_privacy_settings,
    manage_consent,
    apply_privacy_template,
    export_user_data,
    request_account_deletion,
    get_privacy_history,
    get_privacy_compliance_report,
    complete_privacy_review
)

urlpatterns = [
    # Privacy Settings Management
    path('settings/', get_privacy_settings, name='get_privacy_settings'),
    path('settings/update/', update_privacy_settings, name='update_privacy_settings'),

    # Consent Management
    path('consent/', manage_consent, name='manage_consent'),

    # Privacy Templates
    path('template/', apply_privacy_template, name='apply_privacy_template'),

    # Data Export and Deletion (GDPR Rights)
    path('export/', export_user_data, name='export_user_data'),
    path('delete-account/', request_account_deletion, name='request_account_deletion'),

    # Privacy History and Compliance
    path('history/', get_privacy_history, name='get_privacy_history'),
    path('compliance-report/', get_privacy_compliance_report, name='get_privacy_compliance_report'),
    path('complete-review/', complete_privacy_review, name='complete_privacy_review'),
]