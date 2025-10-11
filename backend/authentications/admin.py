from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model

User = get_user_model()


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """
    Custom User admin interface with email verification fields
    """
    # Fields to display in the admin list view
    list_display = ('email', 'username', 'first_name', 'last_name', 'is_email_verified', 
                   'is_active', 'is_staff', 'date_joined')
    
    # Fields that can be searched
    search_fields = ('email', 'username', 'first_name', 'last_name')
    
    # Filters for the admin interface
    list_filter = ('is_email_verified', 'is_active', 'is_staff', 'is_superuser', 'date_joined')
    
    # Default ordering
    ordering = ('-date_joined',)
    
    # Fields to display in the user detail/edit form
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Email Verification', {
            'fields': ('is_email_verified', 'email_verification_token', 'email_verification_sent_at'),
            'description': 'Email verification status and token information'
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined', 'date_updated')}),
    )
    
    # Fields for adding a new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'first_name', 'last_name', 'password1', 'password2'),
        }),
    )
    
    # Read-only fields
    readonly_fields = ('email_verification_token', 'email_verification_sent_at', 
                      'date_joined', 'date_updated', 'last_login')
    
    # Actions for bulk operations
    actions = ['verify_emails', 'unverify_emails']
    
    def verify_emails(self, request, queryset):
        """
        Admin action to verify selected users' emails
        """
        updated = queryset.update(is_email_verified=True)
        self.message_user(request, f'{updated} users had their emails verified.')
    verify_emails.short_description = "Mark selected users' emails as verified"
    
    def unverify_emails(self, request, queryset):
        """
        Admin action to unverify selected users' emails
        """
        updated = queryset.update(is_email_verified=False)
        self.message_user(request, f'{updated} users had their emails unverified.')
    unverify_emails.short_description = "Mark selected users' emails as unverified"
