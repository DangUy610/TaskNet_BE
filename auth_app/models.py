# auth_app/models.py
from django.db import models
from django.conf import settings
import uuid

def avatar_upload_to(instance, filename):
    return f'avatars/user_{instance.user.id}/{filename}'

class Profile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    avatar = models.ImageField(
        upload_to=avatar_upload_to,
        blank=True,
        null=True
    )

    def __str__(self):
        return f'Profile of {self.user.username}'
