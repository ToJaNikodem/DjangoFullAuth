import re
from .messages import DEFAULT_ERROR_MESSAGES
from django.db import models
from django.forms import ValidationError
from django.contrib.auth.models import AbstractUser, BaseUserManager


def username_validator(value):
    if not re.match(r'^[a-z0-9](?:[a-z0-9]+[.\-_]?)+[a-z0-9]$', value):
        raise ValidationError('invalid')

    if len(value) < 4:
        raise ValidationError('too_short')
    
    if len(value) > 40:
        raise ValidationError('too_long')


class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user


class CustomUser(AbstractUser):
    email = models.EmailField(
        unique=True, error_messages=DEFAULT_ERROR_MESSAGES)
    is_email_verified = models.BooleanField(default=False)
    objects = CustomUserManager()

    username = models.CharField(
        max_length=40,
        unique=True,
        error_messages=DEFAULT_ERROR_MESSAGES,
        validators=[
            username_validator
        ],
    )

    nickname = models.CharField(
        default='',
        max_length=40,
        error_messages=DEFAULT_ERROR_MESSAGES,
        validators=[
            username_validator
        ],
    )

    def __str__(self):
        return self.username
