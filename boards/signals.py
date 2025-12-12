# boards/signals.py
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from .models import CardAssignee, CardWatcher, BoardMembership, WorkspaceMembership, WorkspaceRole
from . import services

layer = get_channel_layer()

def _send(group, event, payload):
    async_to_sync(layer.group_send)(group, {"type": "broadcast", "event": event, "payload": payload})

def board_group(board_id): return f"board_{board_id}"
def card_group(card_id): return f"card_{card_id}"
def user_group(user_id): return f"user_{user_id}"

# Assignee
@receiver(post_save, sender=CardAssignee)
def on_assignee_added(sender, instance, created, **kwargs):
    if created:
        services.notify_assignee_added(instance.assigned_by, instance.card, instance.user)

@receiver(post_delete, sender=CardAssignee)
def on_assignee_removed(sender, instance, **kwargs):
    card, board = instance.card, instance.card.list.board
    payload = {"card_id": card.id, "board_id": board.id, "assignee_id": instance.user_id}
    _send(board_group(board.id), "assignee.removed", payload)
    _send(card_group(card.id),   "assignee.removed.card", payload)
    _send(user_group(instance.user_id), "assignee.removed.me", payload)

# Watcher
@receiver(post_save, sender=CardWatcher)
def on_watcher_added(sender, instance, created, **kwargs):
    if created:
        services.notify_watcher_added(instance.added_by, instance.card, instance.user)

@receiver(post_delete, sender=CardWatcher)
def on_watcher_removed(sender, instance, **kwargs):
    card, board = instance.card, instance.card.list.board
    payload = {"card_id": card.id, "board_id": board.id, "watcher_id": instance.user_id}
    _send(board_group(board.id), "watcher.removed", payload)
    _send(card_group(card.id),   "watcher.removed.card", payload)
    _send(user_group(instance.user_id), "watcher.removed.me", payload)

@receiver(post_save, sender=BoardMembership)
def ensure_workspace_membership_for_board_member(sender, instance, created, **kwargs):
    """
    Khi một user được thêm vào board, đảm bảo họ cũng là member của workspace đó.
    - Nếu đã có WorkspaceMembership rồi thì thôi (get_or_create).
    - Nếu là owner của workspace thì default role = admin.
    - Ngược lại default role = member.
    """
    if not created:
        return

    board = instance.board
    workspace = board.workspace
    user = instance.user

    # Nếu user này chính là owner workspace thì để role admin cho chắc
    default_role = WorkspaceRole.ADMIN if workspace.owner_id == user.id else WorkspaceRole.MEMBER

    WorkspaceMembership.objects.get_or_create(
        workspace=workspace,
        user=user,
        defaults={"role": default_role},
    )