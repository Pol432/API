from rest_framework import serializers
from django.utils.translation import gettext_lazy as _

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password

from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError

from .models import Account, University, Campus, ReportCategory, Report


class ReportCategorySerializer(serializers.ModelSerializer):
    """
    Serializer for ReportCategory model
    """
    class Meta:
        model = ReportCategory
        fields = ['id', 'name', 'description']
        read_only_fields = ['id']


class ReportSerializer(serializers.ModelSerializer):
    """
    Serializer for Report model with additional validation and representation
    """
    # Custom fields for enhanced representation
    category_name = serializers.SerializerMethodField(read_only=True)
    posted_by_username = serializers.SerializerMethodField(read_only=True)

    # Optional image upload with validation
    image = serializers.ImageField(
        required=False,
        validators=[FileExtensionValidator(['png', 'jpg', 'jpeg'])],
        allow_null=True
    )

    class Meta:
        model = Report
        fields = [
            'id',
            'university',
            'campus',
            'title',
            'description',
            'category',
            'category_name',
            'image',
            'specific_location',
            'status',
            'posted_by',
            'posted_by_username',
            'created_at',
            'updated_at',
            'occured_at'
        ]
        read_only_fields = [
            'id',
            'created_at',
            'updated_at',
            'posted_by_username'
        ]

    def get_category_name(self, obj):
        """
        Retrieve the name of the report category
        """
        return obj.category.name if obj.category else None

    def get_posted_by_username(self, obj):
        """
        Retrieve the username of the user who posted the report
        """
        return obj.posted_by.username if obj.posted_by else None

    def validate(self, data):
        """
        Additional validation for report creation
        """
        # Ensure title is not empty
        if not data.get('title'):
            raise serializers.ValidationError({
                'title': _('Report title cannot be empty')
            })

        # Ensure description is not too short
        if len(data.get('description', '')).strip() < 10:
            raise serializers.ValidationError({
                'description': _('Description must be at least 10 characters long')
            })

        # Validate university matches user's university
        user = self.context['request'].user
        if 'university' in data and data['university'] != user.university.name:
            raise serializers.ValidationError({
                'university': _('You can only create reports for your own university')
            })

        return data

    def create(self, validated_data):
        """
        Custom create method to set posted_by and university
        """
        user = self.context['request'].user

        # Set posted_by to current user
        validated_data['posted_by'] = user

        # Set university from user's university
        validated_data['university'] = user.university.name

        return super().create(validated_data)

    def update(self, instance, validated_data):
        """
        Custom update method with additional validation
        """
        # Prevent changing posted_by
        validated_data.pop('posted_by', None)

        # Only allow certain fields to be updated based on user role/status
        user = self.context['request'].user
        updatable_fields = ['title', 'description',
                            'image', 'specific_location']

        # If the user is the original poster, allow more updates
        if instance.posted_by == user:
            updatable_fields.extend(['category', 'status'])

        for field in validated_data:
            if field not in updatable_fields:
                raise serializers.ValidationError({
                    field: _('You are not allowed to modify this field')
                })

        return super().update(instance, validated_data)


class UniversitySerializer(serializers.ModelSerializer):
    """
    Serializer for University model
    """
    class Meta:
        model = University
        fields = ['id', 'name', 'short_code']


class CampusSerializer(serializers.ModelSerializer):
    """
    Serializer for Campus model
    """
    university = UniversitySerializer(read_only=True)

    class Meta:
        model = Campus
        fields = ['id', 'name', 'university', 'address']


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        write_only=True,
        required=True
    )
    university = serializers.PrimaryKeyRelatedField(
        queryset=University.objects.all(),
        required=False
    )

    class Meta:
        model = Account
        fields = [
            'username',
            'email',
            'password',
            'confirm_password',
            'first_name',
            'last_name',
            'university'
        ]
        extra_kwargs = {
            'username': {'required': True},
            'email': {'required': True}
        }

    def validate(self, attrs):
        """
        Validate password matching and unique username
        """
        if attrs['password'] != attrs.pop('confirm_password'):
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )

        # Check if username already exists
        if Account.objects.filter(username=attrs['username']).exists():
            raise serializers.ValidationError(
                {"username": "A user with this username already exists."}
            )

        return attrs

    def create(self, validated_data):
        """
        Create and return a new user instance
        """
        try:
            user = Account.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password'],
                first_name=validated_data.get('first_name', ''),
                last_name=validated_data.get('last_name', ''),
                university=validated_data.get('university', None)
            )
            return user
        except Exception as e:
            raise serializers.ValidationError(f"Registration failed: {str(e)}")


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(
        required=True,
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """
        Validate user credentials
        """
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(
                request=self.context.get('request'),
                username=username,
                password=password
            )

            if not user:
                raise serializers.ValidationError(
                    'Unable to log in with provided credentials.',
                    code='authorization'
                )
        else:
            raise serializers.ValidationError(
                'Must include "username" and "password"',
                code='authorization'
            )

        attrs['user'] = user
        return attrs

    def check_user(self, validated_data):
        """
        Return authenticated user
        """
        return validated_data.get('user')


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile
    """
    university = UniversitySerializer(read_only=True)

    class Meta:
        model = Account
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'university',
            'integrity_points'
        ]
        read_only_fields = ['id', 'username', 'integrity_points']


class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for password reset
    """
    email = serializers.EmailField(required=True)
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    confirm_password = serializers.CharField(
        required=True,
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        """
        Validate password reset request
        """
        # Check if passwords match
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError(
                {"new_password": "Passwords do not match."}
            )

        # Check if user exists
        try:
            user = Account.objects.get(email=attrs['email'])
        except Account.DoesNotExist:
            raise serializers.ValidationError(
                {"email": "No user found with this email address."}
            )

        attrs['user'] = user
        return attrs

    def reset_password(self):
        """
        Reset user password
        """
        user = self.validated_data['user']
        new_password = self.validated_data['new_password']

        user.set_password(new_password)
        user.save()

        return user
