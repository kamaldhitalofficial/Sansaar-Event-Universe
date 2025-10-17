"""
URL configuration for event_service project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Sansaar Event Universe API",
        default_version='v1',
        description="""
        # Sansaar Event Universe API Documentation
        
        A comprehensive event management system API that allows you to create, manage, and discover events.
        
        ## Features
        - **Event Management**: Create, update, delete, and retrieve events
        - **Advanced Filtering**: Filter events by status, category, location, date range, and more
        - **Event Status Management**: Handle draft, published, cancelled, postponed, and completed events
        - **Registration System**: Manage event registrations with capacity limits and fees
        - **Media Support**: Handle event images and galleries
        - **Organizer Management**: Support for primary organizers and co-organizers
        - **SEO Optimization**: Built-in SEO fields and slug-based URLs
        
        ## Event Categories
        - Conference, Workshop, Seminar, Webinar
        - Meetup, Networking, Training, Social
        - Sports, Cultural, Business, Educational
        - Entertainment, and more
        
        ## Event Privacy Levels
        - **Public**: Visible to everyone
        - **Private**: Restricted access
        - **Invite Only**: By invitation only
        
        ## API Endpoints Overview
        - `/api/events/` - Main event listing and creation
        - `/api/events/{slug}/` - Individual event operations
        - `/api/events/upcoming/` - Get upcoming events
        - `/api/events/featured/` - Get featured events
        - `/api/events/stats/` - Get event statistics
        """,
        # TODO: Need Update later on
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="kamaldhitalofficial@gmail.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/events/', include('events.urls')),

    # Swagger Documentation URLs
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui-root'),
]
