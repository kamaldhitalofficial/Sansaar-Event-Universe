from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.contrib.auth.models import User


class Event(models.Model):
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('published', 'Published'),
        ('cancelled', 'Cancelled'),
        ('postponed', 'Postponed'),
        ('completed', 'Completed'),
    ]

    CATEGORY_CHOICES = [
        ('conference', 'Conference'),
        ('workshop', 'Workshop'),
        ('seminar', 'Seminar'),
        ('webinar', 'Webinar'),
        ('meetup', 'Meetup'),
        ('networking', 'Networking'),
        ('training', 'Training'),
        ('social', 'Social'),
        ('sports', 'Sports'),
        ('cultural', 'Cultural'),
        ('business', 'Business'),
        ('educational', 'Educational'),
        ('entertainment', 'Entertainment'),
        ('other', 'Other'),
    ]

    PRIVACY_CHOICES = [
        ('public', 'Public'),
        ('private', 'Private'),
        ('invite_only', 'Invite Only'),
    ]

    # Basic Information
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=250, unique=True, blank=True)
    description = models.TextField()
    short_description = models.CharField(max_length=500, blank=True)

    # Date and Time
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    timezone = models.CharField(max_length=50, default='UTC')
    all_day = models.BooleanField(default=False)

    # Location
    location_name = models.CharField(max_length=300)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    venue_details = models.TextField(blank=True)
    is_online = models.BooleanField(default=False)
    online_link = models.URLField(blank=True)

    # Event Details
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default='other')
    tags = models.CharField(max_length=500, blank=True, help_text="Comma-separated tags")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    privacy = models.CharField(max_length=20, choices=PRIVACY_CHOICES, default='public')

    # Capacity and Registration
    max_attendees = models.PositiveIntegerField(null=True, blank=True)
    registration_required = models.BooleanField(default=False)
    registration_deadline = models.DateTimeField(null=True, blank=True)
    registration_fee = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=3, default='USD')

    # Media
    featured_image = models.URLField(blank=True)
    banner_image = models.URLField(blank=True)
    gallery_images = models.JSONField(default=list, blank=True)

    # Contact and Social
    contact_email = models.EmailField(blank=True)
    contact_phone = models.CharField(max_length=20, blank=True)
    website = models.URLField(blank=True)
    social_links = models.JSONField(default=dict, blank=True)

    # Organizer Information
    organizer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='organized_events')
    organizer_name = models.CharField(max_length=200, blank=True)
    organizer_description = models.TextField(blank=True)
    co_organizers = models.ManyToManyField(User, blank=True, related_name='co_organized_events')

    # Additional Information
    agenda = models.JSONField(default=list, blank=True)
    speakers = models.JSONField(default=list, blank=True)
    sponsors = models.JSONField(default=list, blank=True)
    requirements = models.TextField(blank=True)
    what_to_bring = models.TextField(blank=True)
    parking_info = models.TextField(blank=True)
    accessibility_info = models.TextField(blank=True)

    # SEO and Marketing
    meta_title = models.CharField(max_length=200, blank=True)
    meta_description = models.CharField(max_length=500, blank=True)
    keywords = models.CharField(max_length=500, blank=True)

    # System Fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_featured = models.BooleanField(default=False)
    view_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['-start_date']
        indexes = [
            models.Index(fields=['start_date']),
            models.Index(fields=['status']),
            models.Index(fields=['category']),
            models.Index(fields=['privacy']),
            models.Index(fields=['is_featured']),
        ]

    def __str__(self):
        return self.title

    @property
    def date(self):
        """Backward compatibility property"""
        return self.start_date

    @property
    def location(self):
        """Backward compatibility property"""
        return self.location_name

    @property
    def duration_hours(self):
        """Calculate event duration in hours"""
        if self.end_date:
            delta = self.end_date - self.start_date
            return delta.total_seconds() / 3600
        return None

    @property
    def is_past(self):
        """Check if event is in the past"""
        return self.start_date < timezone.now()

    @property
    def is_ongoing(self):
        """Check if event is currently ongoing"""
        now = timezone.now()
        if self.end_date:
            return self.start_date <= now <= self.end_date
        return False

    @property
    def registration_open(self):
        """Check if registration is still open"""
        if not self.registration_required:
            return False
        if self.registration_deadline:
            return timezone.now() < self.registration_deadline
        return timezone.now() < self.start_date

    def clean(self):
        """Validate event data"""
        errors = {}

        # Basic validation
        if not self.title or not self.title.strip():
            errors['title'] = 'Event title is required.'

        if not self.description or not self.description.strip():
            errors['description'] = 'Event description is required.'

        if not self.location_name or not self.location_name.strip():
            errors['location_name'] = 'Event location is required.'

        # Date validation
        if self.start_date and self.start_date < timezone.now():
            errors['start_date'] = 'Event start date cannot be in the past.'

        if self.end_date and self.start_date and self.end_date <= self.start_date:
            errors['end_date'] = 'Event end date must be after start date.'

        if self.registration_deadline and self.start_date and self.registration_deadline > self.start_date:
            errors['registration_deadline'] = 'Registration deadline must be before event start date.'

        # Online event validation
        if self.is_online and not self.online_link:
            errors['online_link'] = 'Online link is required for online events.'

        # Registration validation
        if self.registration_required and self.max_attendees and self.max_attendees <= 0:
            errors['max_attendees'] = 'Maximum attendees must be greater than 0 for events requiring registration.'

        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        # Generate slug if not provided
        if not self.slug:
            from django.utils.text import slugify
            base_slug = slugify(self.title)
            slug = base_slug
            counter = 1
            while Event.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug

        # Set organizer name if not provided
        if not self.organizer_name and self.organizer:
            self.organizer_name = f"{self.organizer.first_name} {self.organizer.last_name}".strip() or self.organizer.username

        self.full_clean()
        super().save(*args, **kwargs)
