from django.contrib.auth import login, logout
from django.core.exceptions import ValidationError

from rest_framework.views import APIView
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated

from .serializers import *
from .models import *
from .helpers import *


class UserRegister(APIView):
    """
    API endpoint for user registration
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.create(serializer.validated_data)
            return Response({
                'message': 'User registered successfully',
                'user_id': user.id,
                'username': user.username
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({
                'error': 'Registration failed',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class UserLogin(APIView):
    """
    API endpoint for user login
    """
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (SessionAuthentication,)

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.check_user(serializer.validated_data)
            login(request, user)
            return Response({
                'message': 'Login successful',
                'user_id': user.id,
                'username': user.username,
                'university': user.university.name if user.university else None,
                'campus': user.campus.name if user.campus else None
            }, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response({
                'error': 'Login failed',
                'details': str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)


class UserLogout(APIView):
    """
    API endpoint for user logout
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        logout(request)
        return Response({
            'message': 'Logout successful'
        }, status=status.HTTP_200_OK)


class UserProfileViewSet(viewsets.ModelViewSet):
    """
    Viewset for user profile management
    """
    queryset = Account.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Ensure users can only access their own profile
        return Account.objects.filter(id=self.request.user.id)

    @action(detail=False, methods=['put'], url_path='update-profile')
    def update_profile(self, request):
        """
        Custom action to update user profile
        """
        user = request.user
        serializer = self.get_serializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Profile updated successfully',
                'user': serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            'error': 'Profile update failed',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], url_path='integrity-stats')
    def integrity_stats(self, request):
        """
        Retrieve user's integrity statistics
        """
        user = request.user
        stats = {
            'total_integrity_points': user.integrity_points,
            'total_reports': user.reports.count(),
            # Assuming a related name exists
            'completed_challenges': user.challenges_completed.count()
        }
        return Response(stats, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    """
    API endpoint for password reset
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.reset_password()
            return Response({
                'message': 'Password reset successful'
            }, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response({
                'error': 'Password reset failed',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
