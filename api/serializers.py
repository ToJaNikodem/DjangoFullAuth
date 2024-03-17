from rest_framework import serializers
from .models import CustomUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.validators import RegexValidator, MinLengthValidator

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_username(self, value):
        regex_validator = RegexValidator(
            regex='^[a-z0-9](?:[a-z0-9]+[.\-_]?)+[a-z0-9]$',
            message='Wrong username format!',
            code='invalid_username'
        )
        min_length_validator = MinLengthValidator(4)
        try:
            regex_validator(value)
            min_length_validator(value)
        except Exception as e:
            raise serializers.ValidationError(str(e))
        return value

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError('already_taken')
        return value
    
    def validate_password(self, value):
        if len(value) < 10:
            raise serializers.ValidationError('to_short')

        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError('no_digit')

        special_characters = '!#$%&()*+,-./:;<=>?@[\]^_`{|}~'
        if not any(char in special_characters for char in value):
            raise serializers.ValidationError('no_special')
        return value
        
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['username'] = user.username

        return token