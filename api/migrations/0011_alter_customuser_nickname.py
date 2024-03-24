# Generated by Django 5.0.3 on 2024-03-22 19:31

import api.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_alter_customuser_nickname'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='nickname',
            field=models.CharField(default='', error_messages={'blank': 'blank', 'invalid': 'invalid'}, max_length=40, validators=[api.models.username_validator]),
        ),
    ]