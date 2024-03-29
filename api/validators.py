import re
from rest_framework import serializers

def password_validator(value):
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

def username_validator(value):
    if not re.match(r'^[a-z0-9](?:[a-z0-9]+[.\-_]?)+[a-z0-9]$', value):
        raise serializers.ValidationError('invalid')

    if len(value) < 4:  
        raise serializers.ValidationError('too_short')
    
    if len(value) > 40:
        raise serializers.ValidationError('too_long')
    
def email_validator(value):
    if len(value) > 254:
        raise serializers.ValidationError('too_long')
