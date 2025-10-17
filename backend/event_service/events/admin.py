from django.contrib import admin
from .models import Event


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'start_date', 'location_name', 'category', 'status',
        'privacy', 'is_featured', 'organizer', 'view_count'
    ]
    list_filter = [
        'status', 'category', 'privacy', 'is_featured', 'is_online',
        'registration_required', 'all_day', 'start_date', 'created_at'
    ]
    search_fields = [
        'title', 'description', 'location_name', 'city', 'tags',
        'organizer__username', 'organizer__first_name', 'organizer__last_name'
    ]
    ordering = ['-start_date']
    readonly_fields = ['slug', 'created_at', 'updated_at', 'view_count']

    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'slug', 'description', 'short_description', 'category', 'tags')
        }),
        ('Date & Time', {
            'fields': ('start_date', 'end_date', 'timezone', 'all_day')
        }),
        ('Location', {
            'fields': (
                'location_name', 'address', 'city', 'state', 'country', 'postal_code',
                'latitude', 'longitude', 'venue_details', 'is_online', 'online_link'
            )
        }),
        ('Event Settings', {
            'fields': ('status', 'privacy', 'is_featured')
        }),
        ('Registration', {
            'fields': (
                'registration_required', 'registration_deadline', 'max_attendees',
                'registration_fee', 'currency'
            )
        }),
        ('Media', {
            'fields': ('featured_image', 'banner_image', 'gallery_images')
        }),
        ('Contact & Social', {
            'fields': ('contact_email', 'contact_phone', 'website', 'social_links')
        }),
        ('Organizer', {
            'fields': ('organizer', 'organizer_name', 'organizer_description', 'co_organizers')
        }),
        ('Additional Information', {
            'fields': (
                'agenda', 'speakers', 'sponsors', 'requirements', 'what_to_bring',
                'parking_info', 'accessibility_info'
            ),
            'classes': ('collapse',)
        }),
        ('SEO & Marketing', {
            'fields': ('meta_title', 'meta_description', 'keywords'),
            'classes': ('collapse',)
        }),
        ('System', {
            'fields': ('created_at', 'updated_at', 'view_count'),
            'classes': ('collapse',)
        }),
    )

    filter_horizontal = ['co_organizers']

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('organizer').prefetch_related('co_organizers')
