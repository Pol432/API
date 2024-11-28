from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    UserRegister,
    UserLogin,
    UserLogout,
    UserProfileViewSet,
    PasswordResetView,
    ReportViewSet,
    ReportCategoryViewSet
)

# Create routers for ViewSets
profile_router = DefaultRouter()
profile_router.register(r'profile', UserProfileViewSet, basename='profile')

report_router = DefaultRouter()
report_router.register(r'reports', ReportViewSet, basename='report')
report_router.register(
    r'categories', ReportCategoryViewSet, basename='report-category')

urlpatterns = [
    # Authentication URLs
    path('register', UserRegister.as_view(), name='register'),
    path('login', UserLogin.as_view(), name='login'),
    path('logout', UserLogout.as_view(), name='logout'),
    path('password-reset', PasswordResetView.as_view(), name='password_reset'),

    # Include the routes for UserProfileViewSet
    path('', include(profile_router.urls)),

    # Include the routes for ReportViewSet and ReportCategoryViewSet
    path('', include(report_router.urls)),
]
