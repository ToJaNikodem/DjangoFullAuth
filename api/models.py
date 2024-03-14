from datetime import timedelta, timezone
from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, MinLengthValidator
from django.contrib.auth.models import AbstractUser, BaseUserManager

def offset_time(days):
    return timezone.now() + timedelta(days=days)

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        if password:
            user.set_password(password)
        try:
            user.full_clean()
        except ValidationError:
            pass
        user.save(using=self._db)
        return user


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    is_email_confirmed = models.BooleanField(default=False)
    objects = CustomUserManager()

    username = models.CharField(
        max_length=40,
        unique=True,
        validators=[
            RegexValidator(
                regex='^[a-z0-9](?:[a-z0-9]+[.\-_]?)+[a-z0-9]$',
                message='Wrong username!',
                code='invalid_username'
            ),
            MinLengthValidator(4)
        ]
    )

    def __str__(self):
        return self.username
