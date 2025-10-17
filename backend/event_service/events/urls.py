from django.urls import path
from . import views

app_name = 'events'

urlpatterns = [
    # Main CRUD endpoints
    path('', views.EventListCreateView.as_view(), name='event-list-create'),
    path('<slug:slug>/', views.EventDetailView.as_view(), name='event-detail'),

    # Status management
    path('<slug:slug>/status/', views.update_event_status, name='event-status-update'),
    path('<slug:slug>/toggle-featured/', views.toggle_featured, name='event-toggle-featured'),

    # Filtering endpoints
    path('status/<str:status_type>/', views.event_list_by_status, name='event-list-by-status'),
    path('category/<str:category>/', views.event_list_by_category, name='event-list-by-category'),

    # Special endpoints
    path('upcoming/', views.upcoming_events, name='upcoming-events'),
    path('featured/', views.featured_events, name='featured-events'),
    path('stats/', views.event_stats, name='event-stats'),
]