from django.db import models
from django.core.validators import RegexValidator, MinLengthValidator
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.forms import ValidationError
import re

def username_validator(value):
    if not re.match(r'^[a-z0-9](?:[a-z0-9]+[.\-_]?)+[a-z0-9]$', value):
        raise ValidationError('invalid')

    if len(value) < 4:
        raise ValidationError('too_short')

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True, error_messages={'blank': 'blank', 'unique': 'not_unique', 'invalid': 'invalid'})
    is_email_verified = models.BooleanField(default=False)
    objects = CustomUserManager()

    username = models.CharField(
        max_length=40,
        unique=True,
        error_messages={'blank': 'blank', 'unique': 'not_unique', 'invalid': 'invalid'},
        validators=[
            username_validator
        ],
    )

    def __str__(self):
        return self.username
