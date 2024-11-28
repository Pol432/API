from rest_framework import serializers
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError


from .models import *


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account


class UserLoginSerializer(serializers.Serializer):
    password = serializers.CharField()
    ##

    def check_user(self, clean_data):
        user = authenticate(
            username=clean_data['username'], password=clean_data['password']
        )

        if not user:
            raise ValidationError('user not found')
        return user
