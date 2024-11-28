from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _

from .models import (
    University,
    Campus,
    Account,
    ReportCategory,
    Report,
    Challenge
)


@admin.register(University)
class UniversityAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)


@admin.register(Campus)
class CampusAdmin(admin.ModelAdmin):
    list_display = ('name', 'university', 'address')
    list_filter = ('university',)
    search_fields = ('name', 'university__name', 'address')


@admin.register(Account)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'university',
                    'integrity_points', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'university')
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal Info'), {'fields': (
            'first_name', 'last_name', 'email', 'university', 'integrity_points')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'university'),
        }),
    )
    search_fields = ('username', 'first_name', 'last_name',
                     'email', 'university__name')


@admin.register(ReportCategory)
class ReportCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name', 'description')


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = (
        'title',
        'university',
        'campus',
        'category',
        'status',
        'posted_by',
        'created_at'
    )
    list_filter = ('status', 'category', 'university', 'campus')
    search_fields = ('title', 'description', 'university', 'campus__name')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(Challenge)
class ChallengeAdmin(admin.ModelAdmin):
    list_display = (
        'title',
        'difficulty',
        'points_reward',
        'category',
        'created_at'
    )
    list_filter = ('difficulty', 'category')
    search_fields = ('title', 'description')
    readonly_fields = ('created_at',)
