# Generated by Django 5.0.3 on 2024-03-22 19:30

import api.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_customuser_nickname_alter_customuser_email_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='nickname',
            field=models.CharField(default='', error_messages={'blank': 'blank', 'invalid': 'invalid', 'unique': 'not_unique'}, max_length=40, validators=[api.models.username_validator]),
        ),
    ]