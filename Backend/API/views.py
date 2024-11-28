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


class UniversityViewSet(viewsets.ModelViewSet):
    """
    Viewset for managing universities
    """
    queryset = University.objects.all()
    serializer_class = UniversitySerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['get'], url_path='campuses')
    def list_campuses(self, request, pk=None):
        """
        Retrieve all campuses for a specific university
        """
        try:
            university = self.get_object()
            campuses = university.campus_set.all()
            serializer = CampusSerializer(campuses, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except University.DoesNotExist:
            return Response({
                'error': 'University not found'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'], url_path='search')
    def search_universities(self, request):
        """
        Search universities by name
        """
        query = request.query_params.get('name', '')
        universities = University.objects.filter(name__icontains=query)
        serializer = self.get_serializer(universities, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='add-campus')
    def add_campus(self, request, pk=None):
        """
        Add a new campus to the university
        """
        try:
            university = self.get_object()

            # Create campus with university reference
            campus_serializer = CampusSerializer(data={
                **request.data,
                'university': university.id
            })

            if campus_serializer.is_valid():
                campus = campus_serializer.save()
                return Response({
                    'message': 'Campus added successfully',
                    'campus': campus_serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({
                'error': 'Campus creation failed',
                'details': campus_serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except University.DoesNotExist:
            return Response({
                'error': 'University not found'
            }, status=status.HTTP_404_NOT_FOUND)


class CampusViewSet(viewsets.ModelViewSet):
    """
    Viewset for managing campuses
    """
    queryset = Campus.objects.all()
    serializer_class = CampusSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Optionally filter campuses by university
        """
        university_id = self.request.query_params.get('university')
        if university_id:
            return Campus.objects.filter(university_id=university_id)
        return Campus.objects.all()

    @action(detail=False, methods=['get'], url_path='by-university')
    def campuses_by_university(self, request):
        """
        List campuses for a specific university
        """
        university_id = request.query_params.get('university_id')
        if not university_id:
            return Response({
                'error': 'University ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            campuses = Campus.objects.filter(university_id=university_id)
            serializer = self.get_serializer(campuses, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], url_path='search')
    def search_campuses(self, request):
        """
        Search campuses by name or university
        """
        query = request.query_params.get('name', '')
        university_id = request.query_params.get('university_id')

        queryset = Campus.objects.all()

        if query:
            queryset = queryset.filter(name__icontains=query)

        if university_id:
            queryset = queryset.filter(university_id=university_id)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ReportCategoryViewSet(viewsets.ModelViewSet):
    """
    Viewset for managing report categories
    """
    queryset = ReportCategory.objects.all()
    serializer_class = ReportCategorySerializer
    permission_classes = [IsAuthenticated]

    def create(self, request):
        """
        Create a new report category
        """
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({
                'message': 'Report category created successfully',
                'category': serializer.data
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({
                'error': 'Report category creation failed',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class ReportViewSet(viewsets.ModelViewSet):
    """
    Viewset for managing reports
    """
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Limit queryset to reports from the user's university
        """
        return Report.objects.filter(university=self.request.user.university)

    def create(self, request):
        """
        Create a new report
        """
        # Add the current user as the poster
        request.data['posted_by'] = request.user.id

        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            report = serializer.save()
            return Response({
                'message': 'Report submitted successfully',
                'report_id': report.id,
                'title': report.title
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({
                'error': 'Report submission failed',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'], url_path='my-reports')
    def my_reports(self, request):
        """
        Retrieve reports submitted by the current user
        """
        reports = Report.objects.filter(posted_by=request.user)
        serializer = self.get_serializer(reports, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['put'], url_path='update-status')
    def update_report_status(self, request, pk=None):
        """
        Update the status of a specific report
        """
        try:
            report = self.get_object()

            # Validate status
            new_status = request.data.get('status')
            if new_status not in dict(Report.STATUS_CHOICES):
                return Response({
                    'error': 'Invalid status',
                    'valid_choices': dict(Report.STATUS_CHOICES).keys()
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer = self.get_serializer(
                report, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'message': 'Report status updated successfully',
                    'report': serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                'error': 'Status update failed',
                'details': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Report.DoesNotExist:
            return Response({
                'error': 'Report not found'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'], url_path='stats')
    def report_statistics(self, request):
        """
        Retrieve report statistics for the user's university
        """
        # Assuming we want to count reports by status
        stats = {
            'total_reports': Report.objects.filter(university=request.user.university).count(),
            'reports_by_status': {
                status: Report.objects.filter(
                    university=request.user.university,
                    status=status
                ).count() for status, _ in Report.STATUS_CHOICES
            },
            'reports_by_category': [
                {
                    'category': category.name,
                    'count': Report.objects.filter(
                        university=request.user.university,
                        category=category
                    ).count()
                } for category in ReportCategory.objects.all()
            ]
        }

        return Response(stats, status=status.HTTP_200_OK)


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
                'university': user.university.name if user.university else None
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
