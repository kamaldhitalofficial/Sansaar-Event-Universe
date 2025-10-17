from rest_framework import generics, status, filters
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.shortcuts import get_object_or_404
from django.db.models import Q
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Event
from .serializers import (
    EventSerializer, EventCreateSerializer, EventUpdateSerializer, EventListSerializer
)
# Swagger documentation examples and parameters
def get_event_list_parameters():
    """Returns the list of query parameters for event listing."""
    return [
        openapi.Parameter(
            'status', openapi.IN_QUERY, description="Filter by event status",
            type=openapi.TYPE_STRING, enum=['draft', 'published', 'cancelled', 'postponed', 'completed']
        ),
        openapi.Parameter(
            'category', openapi.IN_QUERY, description="Filter by event category",
            type=openapi.TYPE_STRING, enum=['conference', 'workshop', 'seminar', 'webinar', 'meetup', 'networking',
                                            'training', 'social', 'sports', 'cultural', 'business', 'educational', 'entertainment', 'other']
        ),
        openapi.Parameter(
            'privacy', openapi.IN_QUERY, description="Filter by privacy level",
            type=openapi.TYPE_STRING, enum=['public', 'private', 'invite_only']
        ),
        openapi.Parameter(
            'start_date', openapi.IN_QUERY, description="Filter events starting from this date (YYYY-MM-DD format)",
            type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE
        ),
        openapi.Parameter(
            'end_date', openapi.IN_QUERY, description="Filter events ending before this date (YYYY-MM-DD format)",
            type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE
        ),
        openapi.Parameter(
            'city', openapi.IN_QUERY, description="Filter by city name (case-insensitive partial match)",
            type=openapi.TYPE_STRING
        ),
        openapi.Parameter(
            'country', openapi.IN_QUERY, description="Filter by country name (case-insensitive partial match)",
            type=openapi.TYPE_STRING
        ),
        openapi.Parameter(
            'is_online', openapi.IN_QUERY, description="Filter online events", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            'is_featured', openapi.IN_QUERY, description="Filter featured events", type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            'registration_required', openapi.IN_QUERY, description="Filter events requiring registration",
            type=openapi.TYPE_BOOLEAN
        ),
        openapi.Parameter(
            'time', openapi.IN_QUERY, description="Filter by time period",
            type=openapi.TYPE_STRING, enum=['upcoming', 'past', 'ongoing']
        ),
        openapi.Parameter(
            'search', openapi.IN_QUERY, description="Search in title, description, location, city, and tags",
            type=openapi.TYPE_STRING
        ),
        openapi.Parameter(
            'ordering', openapi.IN_QUERY, description="Sort results (prefix with - for descending order)",
            type=openapi.TYPE_STRING, enum=['start_date', '-start_date', 'created_at', '-created_at', 'title', '-title', 'view_count', '-view_count']
        ),
    ]

EVENT_LIST_RESPONSE_EXAMPLE = {
    "count": 1, "next": None, "previous": None,
    "results": [{
        "id": 1, "title": "Django Conference 2024", "slug": "django-conference-2024",
        "short_description": "Learn Django from experts in this comprehensive conference.",
        "start_date": "2024-12-15T09:00:00Z", "end_date": "2024-12-15T17:00:00Z",
        "location_name": "Tech Convention Center", "city": "San Francisco", "category": "conference",
        "status": "published", "privacy": "public", "max_attendees": 500, "registration_required": True,
        "registration_fee": "299.00", "currency": "USD", "featured_image": "https://example.com/images/django-conf-2024.jpg",
        "organizer_username": "admin", "is_featured": True, "is_past": False, "registration_open": True
    }]
}

EVENT_RESPONSE_EXAMPLE = {
    "id": 1, "title": "Django Conference 2024", "slug": "django-conference-2024",
    "description": "A comprehensive conference about Django web framework covering latest features, best practices, and real-world applications.",
    "short_description": "Learn Django from experts in this comprehensive conference.",
    "start_date": "2024-12-15T09:00:00Z", "end_date": "2024-12-15T17:00:00Z",
    "timezone": "UTC", "all_day": False, "location_name": "Tech Convention Center",
    "address": "123 Tech Street, Silicon Valley", "city": "San Francisco", "state": "California",
    "country": "USA", "postal_code": "94105", "category": "conference", "tags": "django, python, web development, conference",
    "status": "published", "privacy": "public", "max_attendees": 500, "registration_required": True,
    "registration_fee": "299.00", "currency": "USD", "featured_image": "https://example.com/images/django-conf-2024.jpg",
    "contact_email": "info@djangoconf.com", "website": "https://djangoconf.com",
    "organizer": 1, "organizer_name": "Admin User", "organizer_username": "admin",
    "created_at": "2024-10-19T10:30:00Z", "updated_at": "2024-10-19T10:30:00Z",
    "is_featured": True, "view_count": 0, "duration_hours": 8.0, "is_past": False, "registration_open": True
}


class EventListCreateView(generics.ListCreateAPIView):
    """
    List all events or create a new event.

    ## List Events (GET)
    Retrieve a paginated list of events with advanced filtering options.

    ### Query Parameters:
    - `status`: Filter by event status (draft, published, cancelled, postponed, completed)
    - `category`: Filter by event category (conference, workshop, seminar, etc.)
    - `privacy`: Filter by privacy level (public, private, invite_only)
    - `start_date`: Filter events starting from this date (YYYY-MM-DD format)
    - `end_date`: Filter events ending before this date (YYYY-MM-DD format)
    - `city`: Filter by city name (case-insensitive partial match)
    - `country`: Filter by country name (case-insensitive partial match)
    - `is_online`: Filter online events (true/false)
    - `is_featured`: Filter featured events (true/false)
    - `registration_required`: Filter events requiring registration (true/false)
    - `time`: Filter by time period (upcoming, past, ongoing)
    - `search`: Search in title, description, location, city, and tags
    - `ordering`: Sort by start_date, created_at, title, or view_count (prefix with - for descending)

    ## Create Event (POST)
    Create a new event with comprehensive details.
    """
    queryset = Event.objects.select_related('organizer').prefetch_related('co_organizers')
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'description', 'location_name', 'city', 'tags']
    ordering_fields = ['start_date', 'created_at', 'title', 'view_count']
    ordering = ['-start_date']

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return EventCreateSerializer
        # Use lightweight serializer for lists
        return EventListSerializer if self.request.method == 'GET' else EventSerializer

    @swagger_auto_schema(
        operation_description="Retrieve a paginated list of events with advanced filtering options",
        operation_summary="List Events",
        manual_parameters=get_event_list_parameters(),
        responses={
            200: openapi.Response(
                description="List of events",
                examples={"application/json": EVENT_LIST_RESPONSE_EXAMPLE}
            )
        },
        tags=['Events']
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Create a new event with comprehensive details",
        operation_summary="Create Event",
        request_body=EventCreateSerializer,
        responses={
            201: openapi.Response(
                description="Event created successfully",
                examples={"application/json": EVENT_RESPONSE_EXAMPLE}
            ),
            400: openapi.Response(description="Validation errors")
        },
        tags=['Events']
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def get_queryset(self):
        queryset = self.queryset

        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        # Filter by category
        category_filter = self.request.query_params.get('category')
        if category_filter:
            queryset = queryset.filter(category=category_filter)

        # Filter by privacy
        privacy_filter = self.request.query_params.get('privacy')
        if privacy_filter:
            queryset = queryset.filter(privacy=privacy_filter)

        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date:
            queryset = queryset.filter(start_date__gte=start_date)
        if end_date:
            queryset = queryset.filter(start_date__lte=end_date)

        # Filter by location
        city = self.request.query_params.get('city')
        if city:
            queryset = queryset.filter(city__icontains=city)

        country = self.request.query_params.get('country')
        if country:
            queryset = queryset.filter(country__icontains=country)

        # Filter by online/offline
        is_online = self.request.query_params.get('is_online')
        if is_online is not None:
            queryset = queryset.filter(is_online=is_online.lower() == 'true')

        # Filter by featured events
        is_featured = self.request.query_params.get('is_featured')
        if is_featured is not None:
            queryset = queryset.filter(is_featured=is_featured.lower() == 'true')

        # Filter by registration required
        registration_required = self.request.query_params.get('registration_required')
        if registration_required is not None:
            queryset = queryset.filter(registration_required=registration_required.lower() == 'true')

        # Filter by upcoming/past events
        time_filter = self.request.query_params.get('time')
        if time_filter == 'upcoming':
            queryset = queryset.filter(start_date__gte=timezone.now())
        elif time_filter == 'past':
            queryset = queryset.filter(start_date__lt=timezone.now())
        elif time_filter == 'ongoing':
            now = timezone.now()
            queryset = queryset.filter(
                start_date__lte=now,
                end_date__gte=now
            ).exclude(end_date__isnull=True)

        return queryset


class EventDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a specific event by its slug.

    ## Retrieve Event (GET)
    Get detailed information about a specific event. This automatically increments the view count.

    ## Update Event (PUT/PATCH)
    Update event details. Use PUT for complete updates or PATCH for partial updates.

    ## Delete Event (DELETE)
    Permanently delete an event. This action cannot be undone.
    """
    queryset = Event.objects.select_related('organizer').prefetch_related('co_organizers')
    lookup_field = 'slug'

    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return EventUpdateSerializer
        return EventSerializer

    @swagger_auto_schema(
        operation_description="Get detailed information about a specific event. Automatically increments view count.",
        operation_summary="Get Event Details",
        responses={
            200: EventSerializer,
            404: openapi.Response(description="Event not found")
        },
        tags=['Events']
    )
    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Update all fields of an event",
        operation_summary="Update Event (Full)",
        request_body=EventUpdateSerializer,
        responses={
            200: EventSerializer,
            400: openapi.Response(description="Validation errors"),
            404: openapi.Response(description="Event not found")
        },
        tags=['Events']
    )
    def put(self, request, *args, **kwargs):
        return super().put(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Partially update an event",
        operation_summary="Update Event (Partial)",
        request_body=EventUpdateSerializer,
        responses={
            200: EventSerializer,
            400: openapi.Response(description="Validation errors"),
            404: openapi.Response(description="Event not found")
        },
        tags=['Events']
    )
    def patch(self, request, *args, **kwargs):
        return super().patch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Permanently delete an event. This action cannot be undone.",
        operation_summary="Delete Event",
        responses={
            204: openapi.Response(description="Event deleted successfully"),
            404: openapi.Response(description="Event not found")
        },
        tags=['Events']
    )
    def delete(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """Increment view count when retrieving event details"""
        instance = self.get_object()
        instance.view_count += 1
        instance.save(update_fields=['view_count'])
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


@swagger_auto_schema(
    method='patch',
    operation_description="Update the status of a specific event",
    operation_summary="Update Event Status",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['status'],
        properties={
            'status': openapi.Schema(
                type=openapi.TYPE_STRING,
                enum=['draft', 'published', 'cancelled', 'postponed', 'completed'],
                description='New status for the event'
            )
        },
        example={'status': 'published'}
    ),
    responses={
        200: EventSerializer,
        400: openapi.Response(
            description="Bad Request",
            examples={
                "application/json": {
                    "error": "Invalid status. Must be one of: draft, published, cancelled, postponed, completed."
                }
            }
        ),
        404: openapi.Response(description="Event not found")
    },
    tags=['Event Management']
)
@api_view(['PATCH'])
def update_event_status(request, slug):
    """
    Update event status (draft, published, cancelled, postponed, completed)
    """
    event = get_object_or_404(Event, slug=slug)

    new_status = request.data.get('status')
    valid_statuses = ['draft', 'published', 'cancelled', 'postponed', 'completed']

    if new_status not in valid_statuses:
        return Response(
            {'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    event.status = new_status
    event.save(update_fields=['status', 'updated_at'])

    serializer = EventSerializer(event)
    return Response(serializer.data)


@swagger_auto_schema(
    method='get',
    operation_description="Retrieve a list of events filtered by their status",
    operation_summary="List Events by Status",
    manual_parameters=[
        openapi.Parameter(
            'status_type',
            openapi.IN_PATH,
            description="Event status to filter by",
            type=openapi.TYPE_STRING,
            enum=['draft', 'published', 'cancelled', 'postponed', 'completed']
        )
    ],
    responses={
        200: EventListSerializer(many=True),
        400: openapi.Response(
            description="Invalid status type",
            examples={
                "application/json": {
                    "error": "Invalid status. Must be one of: draft, published, cancelled, postponed, completed."
                }
            }
        )
    },
    tags=['Event Filtering']
)
@api_view(['GET'])
def event_list_by_status(request, status_type):
    """
    List events by status (draft, published, cancelled, postponed, completed)
    """
    valid_statuses = ['draft', 'published', 'cancelled', 'postponed', 'completed']

    if status_type not in valid_statuses:
        return Response(
            {'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    events = Event.objects.filter(status=status_type).select_related('organizer')
    serializer = EventListSerializer(events, many=True)
    return Response(serializer.data)


@swagger_auto_schema(
    method='get',
    operation_description="Retrieve a list of events filtered by their category",
    operation_summary="List Events by Category",
    manual_parameters=[
        openapi.Parameter(
            'category',
            openapi.IN_PATH,
            description="Event category to filter by",
            type=openapi.TYPE_STRING,
            enum=['conference', 'workshop', 'seminar', 'webinar', 'meetup', 'networking',
                  'training', 'social', 'sports', 'cultural', 'business', 'educational',
                  'entertainment', 'other']
        )
    ],
    responses={
        200: EventListSerializer(many=True),
        400: openapi.Response(description="Invalid category")
    },
    tags=['Event Filtering']
)
@api_view(['GET'])
def event_list_by_category(request, category):
    """
    List events by category (conference, workshop, seminar, etc.)
    """
    valid_categories = [choice[0] for choice in Event.CATEGORY_CHOICES]

    if category not in valid_categories:
        return Response(
            {'error': f'Invalid category. Must be one of: {", ".join(valid_categories)}.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    events = Event.objects.filter(category=category).select_related('organizer')
    serializer = EventListSerializer(events, many=True)
    return Response(serializer.data)


@swagger_auto_schema(
    method='get',
    operation_description="Get the next 10 upcoming published events",
    operation_summary="Get Upcoming Events",
    responses={
        200: EventListSerializer(many=True)
    },
    tags=['Event Discovery']
)
@api_view(['GET'])
def upcoming_events(request):
    """
    List the next 10 upcoming published events
    """
    events = Event.objects.filter(
        start_date__gte=timezone.now(),
        status='published'
    ).select_related('organizer')[:10]

    serializer = EventListSerializer(events, many=True)
    return Response(serializer.data)


@swagger_auto_schema(
    method='get',
    operation_description="Get all featured published events",
    operation_summary="Get Featured Events",
    responses={
        200: EventListSerializer(many=True)
    },
    tags=['Event Discovery']
)
@api_view(['GET'])
def featured_events(request):
    """
    List all featured published events
    """
    events = Event.objects.filter(
        is_featured=True,
        status='published'
    ).select_related('organizer')

    serializer = EventListSerializer(events, many=True)
    return Response(serializer.data)


@swagger_auto_schema(
    method='post',
    operation_description="Toggle the featured status of an event (featured/unfeatured)",
    operation_summary="Toggle Featured Status",
    responses={
        200: openapi.Response(
            description="Success",
            examples={
                "application/json": {
                    "message": "Event featured successfully.",
                    "is_featured": True
                }
            }
        ),
        404: openapi.Response(description="Event not found")
    },
    tags=['Event Management']
)
@api_view(['POST'])
def toggle_featured(request, slug):
    """
    Toggle featured status of an event (featured/unfeatured)
    """
    event = get_object_or_404(Event, slug=slug)
    event.is_featured = not event.is_featured
    event.save(update_fields=['is_featured', 'updated_at'])

    return Response({
        'message': f'Event {"featured" if event.is_featured else "unfeatured"} successfully.',
        'is_featured': event.is_featured
    })


@swagger_auto_schema(
    method='get',
    operation_description="Get comprehensive statistics about events in the system",
    operation_summary="Get Event Statistics",
    responses={
        200: openapi.Response(
            description="Event statistics",
            examples={
                "application/json": {
                    "total_events": 150,
                    "published_events": 120,
                    "upcoming_events": 45,
                    "draft_events": 25,
                    "featured_events": 15,
                    "online_events": 60
                }
            }
        )
    },
    tags=['Analytics']
)
@api_view(['GET'])
def event_stats(request):
    """
    Get comprehensive event statistics including counts by status and type
    """
    total_events = Event.objects.count()
    published_events = Event.objects.filter(status='published').count()
    upcoming_events = Event.objects.filter(
        start_date__gte=timezone.now(),
        status='published'
    ).count()

    stats = {
        'total_events': total_events,
        'published_events': published_events,
        'upcoming_events': upcoming_events,
        'draft_events': Event.objects.filter(status='draft').count(),
        'featured_events': Event.objects.filter(is_featured=True).count(),
        'online_events': Event.objects.filter(is_online=True, status='published').count(),
    }

    return Response(stats)
