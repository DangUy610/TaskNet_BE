# auth_app/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from .models import Profile
from boards.models import Workspace

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_profile_for_new_user(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
        if not Workspace.objects.filter(owner=instance).exists():
             Workspace.objects.create(name="Hard Spirit", owner=instance)