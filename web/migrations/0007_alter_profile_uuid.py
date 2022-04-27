# Generated by Django 3.2 on 2022-04-27 07:10

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('web', '0006_auto_20220426_2106'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='uuid',
            field=models.UUIDField(default=uuid.UUID('76cd576a-e6e5-44fb-8dd0-48abd98ac70d'), unique=True),
        ),
    ]
