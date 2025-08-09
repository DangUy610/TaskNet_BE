# boards/models.py
from django.db import models
from django.contrib.auth import get_user_model
from django.conf import settings
import uuid
from datetime import datetime, timedelta

User = get_user_model()

class Workspace(models.Model):
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    
class Board(models.Model):
    name = models.CharField(max_length=255)
    background = models.TextField(blank=True)
    visibility = models.CharField(max_length=20, default='private')
    workspace = models.ForeignKey(Workspace, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    members = models.ManyToManyField(
    User,
    related_name='boards',
    through='BoardMembership',
    blank=True    
    )

    is_closed = models.BooleanField(default=False)


class List(models.Model):
    name = models.CharField(max_length=128)
    position = models.IntegerField(default=0)
    background = models.TextField(blank=True)
    visibility = models.CharField(max_length=20, default='private')
    created_at = models.DateTimeField(auto_now_add=True)
    board = models.ForeignKey(Board, on_delete=models.CASCADE)  # ✅ rename từ boardid → board

class Card(models.Model):
    name = models.CharField(max_length=255)
    background = models.TextField(blank=True)
    visibility = models.CharField(max_length=20, default='private')
    description = models.TextField(blank=True)
    due_date = models.DateTimeField(null=True, blank=True)
    completed = models.BooleanField(default=False)
    list = models.ForeignKey(List, on_delete=models.SET_NULL, null=True, blank=True)  # ✅ rename từ listid → list
    STATUS_CHOICES = [
        ('doing', 'Doing'),
        ('done', 'Done'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='doing')
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    position = models.IntegerField(default=0)
    labels = models.ManyToManyField("Label", blank=True, related_name='cards')


class Label(models.Model):
    name = models.CharField(max_length=100)
    color = models.CharField(max_length=20)
    board = models.ForeignKey(Board, on_delete=models.CASCADE, related_name='labels')

class BoardMembership(models.Model):
    board = models.ForeignKey(Board, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='board_memberships')
    role = models.CharField(
        max_length=10,
        choices=[('admin', 'Admin'), ('editor', 'Editor'), ('viewer', 'Viewer')],
        default='viewer'
    )
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('board', 'user')


class BoardInviteLink(models.Model):
    ROLE_CHOICES = [
        ('member', 'Member'),
        ('admin', 'Admin'),
        ('observer', 'Observer'),
    ]
    
    board = models.OneToOneField('Board', on_delete=models.CASCADE, related_name='invite_link')
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='member')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'boards_boardinvitelink'
        verbose_name = 'Board Invite Link'
        verbose_name_plural = 'Board Invite Links'
    
    def __str__(self):
        return f"Invite link for {self.board.name}"
    
    def is_expired(self):
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at 