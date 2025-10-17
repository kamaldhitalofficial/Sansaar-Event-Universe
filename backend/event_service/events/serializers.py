from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Event


class EventSerializer(serializers.ModelSerializer):
    # Computed fields
    duration_hours = serializers.ReadOnlyField()
    is_past = serializers.ReadOnlyField()
    is_ongoing = serializers.ReadOnlyField()
    registration_open = serializers.ReadOnlyField()

    # Backward compatibility
    date = serializers.ReadOnlyField()
    location = serializers.ReadOnlyField()

    # Organizer details
    organizer_username = serializers.CharField(source='organizer.username', read_only=True)
    co_organizer_usernames = serializers.SerializerMethodField()

    class Meta:
        model = Event
        fields = [
            # Basic Information
            'id', 'title', 'slug', 'description', 'short_description',

            # Date and Time
            'start_date', 'end_date', 'timezone', 'all_day',

            # Location
            'location_name', 'address', 'city', 'state', 'country', 'postal_code',
            'latitude', 'longitude', 'venue_details', 'is_online', 'online_link',

            # Event Details
            'category', 'tags', 'status', 'privacy',

            # Capacity and Registration
            'max_attendees', 'registration_required', 'registration_deadline',
            'registration_fee', 'currency',

            # Media
            'featured_image', 'banner_image', 'gallery_images',

            # Contact and Social
            'contact_email', 'contact_phone', 'website', 'social_links',

            # Organizer Information
            'organizer', 'organizer_name', 'organizer_description', 'co_organizers',
            'organizer_username', 'co_organizer_usernames',

            # Additional Information
            'agenda', 'speakers', 'sponsors', 'requirements', 'what_to_bring',
            'parking_info', 'accessibility_info',

            # SEO and Marketing
            'meta_title', 'meta_description', 'keywords',

            # System Fields
            'created_at', 'updated_at', 'is_featured', 'view_count',

            # Computed Fields
            'duration_hours', 'is_past', 'is_ongoing', 'registration_open',

            # Backward Compatibility
            'date', 'location',
        ]
        read_only_fields = [
            'id', 'slug', 'created_at', 'updated_at', 'view_count',
            'organizer_username', 'co_organizer_usernames',
            'duration_hours', 'is_past', 'is_ongoing', 'registration_open',
            'date', 'location',
        ]

    def get_co_organizer_usernames(self, obj):
        """Get usernames of co-organizers"""
        return [user.username for user in obj.co_organizers.all()]

    def validate_start_date(self, value):
        """Validate that event start date is not in the past"""
        from django.utils import timezone
        if value < timezone.now():
            raise serializers.ValidationError("Event start date cannot be in the past.")
        return value

    def validate_title(self, value):
        """Validate title is not empty"""
        if not value or not value.strip():
            raise serializers.ValidationError("Event title is required.")
        return value.strip()

    def validate_description(self, value):
        """Validate description is not empty"""
        if not value or not value.strip():
            raise serializers.ValidationError("Event description is required.")
        return value.strip()

    def validate_location_name(self, value):
        """Validate location name is not empty"""
        if not value or not value.strip():
            raise serializers.ValidationError("Event location name is required.")
        return value.strip()

    def validate(self, data):
        """Cross-field validation"""
        errors = {}

        # End date validation
        if 'end_date' in data and 'start_date' in data:
            if data['end_date'] and data['start_date'] and data['end_date'] <= data['start_date']:
                errors['end_date'] = 'Event end date must be after start date.'

        # Registration deadline validation
        if 'registration_deadline' in data and 'start_date' in data:
            if (data.get('registration_deadline') and data.get('start_date') and
                    data['registration_deadline'] > data['start_date']):
                errors['registration_deadline'] = 'Registration deadline must be before event start date.'

        # Online event validation
        if data.get('is_online') and not data.get('online_link'):
            errors['online_link'] = 'Online link is required for online events.'

        # Registration validation
        if (data.get('registration_required') and data.get('max_attendees') and
                data['max_attendees'] <= 0):
            errors['max_attendees'] = 'Maximum attendees must be greater than 0 for events requiring registration.'

        if errors:
            raise serializers.ValidationError(errors)

        return data


class EventCreateSerializer(EventSerializer):
    """Serializer for creating events"""

    def create(self, validated_data):
        # Set organizer to current user if not provided
        if 'organizer' not in validated_data:
            validated_data['organizer'] = self.context['request'].user

        # Handle co_organizers separately
        co_organizers = validated_data.pop('co_organizers', [])

        event = Event.objects.create(**validated_data)

        if co_organizers:
            event.co_organizers.set(co_organizers)

        return event


class EventUpdateSerializer(EventSerializer):
    """Serializer for updating events"""

    def update(self, instance, validated_data):
        # Handle co_organizers separately
        co_organizers = validated_data.pop('co_organizers', None)

        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()

        # Update co_organizers if provided
        if co_organizers is not None:
            instance.co_organizers.set(co_organizers)

        return instance


class EventListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for event lists"""
    organizer_username = serializers.CharField(source='organizer.username', read_only=True)
    is_past = serializers.ReadOnlyField()
    registration_open = serializers.ReadOnlyField()

    class Meta:
        model = Event
        fields = [
            'id', 'title', 'slug', 'short_description', 'start_date', 'end_date',
            'location_name', 'city', 'category', 'status', 'privacy',
            'max_attendees', 'registration_required', 'registration_fee', 'currency',
            'featured_image', 'organizer_username', 'is_featured', 'is_past', 'registration_open'
        ]