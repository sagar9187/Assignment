from django.db import models
from django.contrib.auth.models import User
from uuid import uuid4
# Create your models here.
GENDERS = (('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other'))
class Profile(models.Model):
    user     = models.OneToOneField(User, on_delete=models.CASCADE)
    name     = models.CharField(max_length=1000, null=True)
    gender   = models.CharField(max_length=50, choices=GENDERS)
    height   = models.FloatField(null=True)
    weight   = models.FloatField(null=True)
    bmi      = models.FloatField(null=True)
    bmi_calculated_at = models.DateTimeField(auto_now_add=True)
    uuid = models.UUIDField(default=uuid4(), unique=True)
