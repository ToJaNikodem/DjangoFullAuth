import re
from .models import CustomUser
from .tokens import account_activation_token
from .messages import DEFAULT_ERROR_MESSAGES
from rest_framework import serializers
from django.core.validators import validate_email
from django.contrib.auth.tokens import default_token_generator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

def validate_password(value):
    if len(value) < 10:
        raise serializers.ValidationError('too_short')

    if len(value) > 64:
        raise serializers.ValidationError('too_long')

    if not any(char.isdigit() for char in value):
        raise serializers.ValidationError('invalid')

    special_characters = '!#$%&()*+,-./:;<=>?@[\]^_`{|}~'
    if not any(char in special_characters for char in value):
        raise serializers.ValidationError('invalid')

    return value

class PasswordResetSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True, error_messages=DEFAULT_ERROR_MESSAGES)
    reset_token = serializers.CharField(required=True, error_messages=DEFAULT_ERROR_MESSAGES)

    def validate_reset_token(self, value):
        if not default_token_generator.check_token(self.context['user'], self.context['reset_token']):
            raise serializers.ValidationError('invalid')
        return value

    def validate_new_password(self, value):
        return validate_password(value)


class EmailVerificationSerializer(serializers.Serializer):
    verification_token = serializers.CharField(required=True, error_messages=DEFAULT_ERROR_MESSAGES)

    def validate_verification_token(self, value):
        if not account_activation_token.check_token(self.context['user'], self.context['verification_token']):
            raise serializers.ValidationError('invalid')
        return value


class UsernameChangeSerializer(serializers.Serializer):
    new_nickname = serializers.CharField(required=True, error_messages=DEFAULT_ERROR_MESSAGES)

    def validate_new_nickname(self, value):
        if not re.match(r'^[a-z0-9](?:[a-z0-9]+[.\-_]?)+[a-z0-9]$', value):
            raise serializers.ValidationError('invalid')

        if len(value) < 4:
            raise serializers.ValidationError('too_short')

        if len(value) > 40:
            raise serializers.ValidationError('too_long')
        return value


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, error_messages=DEFAULT_ERROR_MESSAGES)
    new_password = serializers.CharField(required=True, error_messages=DEFAULT_ERROR_MESSAGES)

    def validate_old_password(self, value):
        user = self.context['user']
        if not user.check_password(value):
            raise serializers.ValidationError('invalid')
        return value

    def validate_new_password(self, value):
        return validate_password(value)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value):
        return validate_password(value)


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        token['nickname'] = user.nickname
        token['is_email_verified'] = user.is_email_verified

        return token
