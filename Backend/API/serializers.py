from rest_framework import serializers
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

from .models import Account, University, Campus


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
    password2 = serializers.CharField(
        write_only=True,
        required=True
    )
    university = serializers.PrimaryKeyRelatedField(
        queryset=University.objects.all(),
        required=False
    )
    campus = serializers.PrimaryKeyRelatedField(
        queryset=Campus.objects.all(),
        required=False
    )

    class Meta:
        model = Account
        fields = [
            'username',
            'email',
            'password',
            'password2',
            'first_name',
            'last_name',
            'university',
            'campus'
        ]
        extra_kwargs = {
            'username': {'required': True},
            'email': {'required': True}
        }

    def validate(self, attrs):
        """
        Validate password matching and unique username
        """
        if attrs['password'] != attrs.pop('password2'):
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
                university=validated_data.get('university', None),
                campus=validated_data.get('campus', None)
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
    campus = CampusSerializer(read_only=True)

    class Meta:
        model = Account
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'university',
            'campus',
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
