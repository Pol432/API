from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    UserRegister,
    UserLogin,
    UserLogout,
    UserProfileViewSet,
    PasswordResetView
)

# Create a router for the UserProfileViewSet
router = DefaultRouter()
router.register(r'profile', UserProfileViewSet, basename='profile')

urlpatterns = [
    path('register', UserRegister.as_view(), name='register'),
    path('login', UserLogin.as_view(), name='login'),
    path('logout', UserLogout.as_view(), name='logout'),
    path('password-reset', PasswordResetView.as_view(), name='password_reset'),
    # Include the routes for UserProfileViewSet
    path('', include(router.urls)),
]
