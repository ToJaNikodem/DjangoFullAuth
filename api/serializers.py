from rest_framework import serializers
from .models import CustomUser
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.validators import RegexValidator

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}
    
    def validate_password(self, value):
        if len(value) < 10:
            raise serializers.ValidationError('too_short')

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