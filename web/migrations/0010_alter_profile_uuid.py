# Generated by Django 3.2 on 2022-04-27 09:21

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0009_alter_profile_uuid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='uuid',
            field=models.UUIDField(default=uuid.UUID('16afbbbe-6883-4fbf-add9-dddc030f916a'), unique=True),
        ),
    ]
