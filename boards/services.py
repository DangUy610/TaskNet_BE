from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import transaction
from django.contrib.auth import get_user_model
from django.utils import timezone
from asgiref.sync import async_to_sync

channel_layer = get_channel_layer()

import logging

from .models import Notification, Card, CardAssignee, CardWatcher, BoardMembership
from .serializers import NotificationSerializer
logger = logging.getLogger(__name__)

User = get_user_model()

# ============================================================
# 🏢 Workspace Notifications (BỔ SUNG)
# ============================================================

def notify_workspace_member_added(actor, workspace, new_member):
    """
    Thông báo khi một user được thêm vào Workspace.
    """
    return _notify_user(
        recipient=new_member,
        verb=f'added you to workspace "{workspace.name}"',
        level="success",
        target=workspace,
        data={
            "type": "workspace_invite", 
            "workspaceId": workspace.id, 
            "action_url": f"/w/{workspace.id}/home", # Link frontend workspace home
            "actor_id": getattr(actor, "id", None)
        }
    )

def notify_workspace_ownership_transferred(old_owner, workspace, new_owner):
    """
    Thông báo cho New Owner biết họ đã nhận quyền sở hữu.
    """
    return _notify_user(
        recipient=new_owner,
        verb=f'transferred ownership of workspace "{workspace.name}" to you',
        level="warning", # Mức độ quan trọng cao
        target=workspace,
        data={
            "type": "workspace_transfer",
            "workspaceId": workspace.id,
            "action_url": f"/w/{workspace.id}/settings", # Link frontend settings
            "actor_id": getattr(old_owner, "id", None)
        }
    )

# ============================================================
# 🔔 Notification Broadcasting

def broadcast_notification(notification: Notification):
    """Gửi 1 notification tới group user_{id}."""
    group = f"user_{notification.recipient_id}"
    payload = NotificationSerializer(notification).data
    async_to_sync(channel_layer.group_send)(
        group,
        {"type": "notification.message", "payload": payload},
    )
    # Cập nhật số lượng notification chưa đọc
    unread = Notification.objects.filter(
        recipient=notification.recipient, read_at__isnull=True
    ).count()
    async_to_sync(channel_layer.group_send)(group, {"type": "notification_count", "count": unread})


def _broadcast_many(notifications):
    """Best-effort: broadcast danh sách notification, log nếu lỗi."""
    for n in notifications:
        try:
            broadcast_notification(n)
        except Exception as e:
            logger.error(f"Failed to broadcast notification {n.id}: {e}")


def _collect_recipients(actor, card):
    """Owner + assignees + watchers, loại actor, unique."""
    seen, users = set(), []
    def add(u):
        if u and u.id != actor.id and u.id not in seen:
            seen.add(u.id)
            users.append(u)
    add(getattr(card, "created_by", None))
    for uid in CardAssignee.objects.filter(card=card).values_list("user_id", flat=True):
        U = get_user_model(); add(U.objects.filter(id=uid).first())
    for uid in CardWatcher.objects.filter(card=card).values_list("user_id", flat=True):
        U = get_user_model(); add(U.objects.filter(id=uid).first())
    return users


def notify_card_comment(actor, card, comment):
    """
    Tạo Notification cho tất cả recipients liên quan, và chỉ broadcast
    SAU KHI transaction hiện tại commit thành công.
    """
    recipients = _collect_recipients(actor, card)
    if not recipients:
        return

    msg = (comment.content or "").strip()
    data = {
        "type": "card_comment",
        "cardId": card.id,
        "commentId": comment.id,
        "excerpt": (msg[:120] + "…") if len(msg) > 120 else msg,
        "action_url": f"/cards/{card.id}#comment-{comment.id}",
        "actor_id": getattr(actor, "id", None),
    }
    created = []
    with transaction.atomic():
        for u in recipients:
            n = Notification.objects.create(
                actor=actor, recipient=u, level="info",
                verb=f'commented on "{card.name}"',
                target=card, data=data
            )
            created.append(n)
        transaction.on_commit(lambda: _broadcast_many(created))

# ============================================================
# 🔔 Helper: Gửi Notification đến user
# ============================================================

def _notify_user(recipient, verb, level="info", target=None, data=None):
    """
    Tạo notification và gửi realtime qua WebSocket tới người dùng.
    """
    n = Notification.objects.create(actor=None, recipient=recipient, verb=verb, level=level, target=target, data=data or {})
    broadcast_notification(n)
    return n

def notify_board_member_added(actor, board, new_member):
    return _notify_user(
        recipient=new_member,
        verb=f'added you to board "{board.name}"',
        level="success",
        target=board,
        data={"type": "board_member_added", "boardId": board.id, "action_url": f"/boards/{board.id}",
              "actor_id": getattr(actor, "id", None)}
    )

def notify_assignee_added(actor, card, assignee):
    return _notify_user(
        recipient=assignee,
        verb=f'assigned you to "{card.name}"',
        level="success",
        target=card,
        data={"type": "card_assigned", "cardId": card.id, "action_url": f"/cards/{card.id}",
              "actor_id": getattr(actor, "id", None)}
    )


def notify_watcher_added(actor, card, watcher):
    return _notify_user(
        recipient=watcher,
        verb=f'added you as watcher of "{card.name}"',
        level="info",
        target=card,
        data={"type": "card_watch", "cardId": card.id, "action_url": f"/cards/{card.id}"}
    )

def notify_card_field_changes(actor, card, changes: dict):
    """Bắn khi card đổi thuộc tính: completed/due/status/..."""
    if not changes: return
    parts = []
    if "completed" in changes and changes["completed"][1] is True: parts.append("marked as completed")
    if "due_date" in changes:
        new_due = changes["due_date"][1]
        parts.append("removed due date" if not new_due else f'due set to {new_due.strftime("%b %d, %H:%M")}')
    if "    " in changes: parts.append(f'status → {changes["status"][1]}')
    msg = "; ".join(parts) or "updated the card"

    recipients = _collect_recipients(actor, card)
    if not recipients: return
    created = []
    with transaction.atomic():
        for u in recipients:
            n = Notification.objects.create(
                actor=actor, recipient=u, level="info", verb=f'updated "{card.name}"',
                target=card, data={"type": "card_updated", "message": msg, "cardId": card.id, "action_url": f"/cards/{card.id}"}
            )
            created.append(n)
        transaction.on_commit(lambda: _broadcast_many(created))
# ============================================================
# 📅 Reminder Scheduling
# ============================================================

def schedule_due_reminder(card):
    """
    Dựng logic 'schedule' reminder cho card.
    - Nếu có Celery: có thể dùng apply_async(eta=card.due_reminder_at)
    - Nếu không có Celery: có thể chạy cron job quét mỗi phút.
    """
    if not card.due_reminder_at:
        return  # Không có thời điểm nhắc
    # Nếu bạn dùng Celery, uncomment đoạn sau:
    # from .tasks import send_due_reminder
    # send_due_reminder.apply_async(args=[card.id], eta=card.due_reminder_at)
    #
    # Nếu chưa có Celery → noop, reminder sẽ được xử lý bởi cron hoặc thủ công.
    return


def send_due_reminder_now(card):
    """
    Gửi notification ngay lập tức khi đến giờ nhắc hạn.
    Dùng cho cron job hoặc Celery task.
    """
    if not card.due_date or card.completed:
        return
    recipients = _collect_recipients(None, card)
    if not recipients:
        return
    mins = int((card.due_date - timezone.now()).total_seconds() // 60)
    verb = f'"{card.name}" is due soon'
    data = {"type": "due_soon", "cardId": card.id, "due_at": card.due_date.isoformat(),
            "minutes_left": mins, "action_url": f"/cards/{card.id}"}
    with transaction.atomic():
        created = [Notification.objects.create(actor=None, recipient=u, verb=verb, level="warning", target=card, data=data)
                   for u in recipients]
        transaction.on_commit(lambda: _broadcast_many(created))


# ============================================================
# 🔁 Recurrence Utilities (optional)
# ============================================================

def handle_card_recurrence(card):
    """
    Khi card được đánh dấu completed=True và có recurrence != 'never',
    tự động tạo kỳ hạn kế tiếp.
    """
    if not card.recurrence or card.recurrence == "never":
        return

    next_due = card.next_recurrence_due()
    if not next_due:
        return

    card.due_date = next_due
    card.completed = False
    card.completed_at = None
    card.due_reminder_at = card.compute_due_reminder_at()
    card.save(update_fields=["due_date", "completed", "completed_at", "due_reminder_at"])

    # Ghi log activity (option)
    from .models import CardActivity
    CardActivity.objects.create(
        card=card,
        user=card.created_by,
        activity_type="due_date_changed",
        description=f"Auto scheduled next due date to {card.due_date.strftime('%b %d at %I:%M %p')}",
    )

    # Phát realtime để FE cập nhật ngay
    card_update(card)


# ============================================================
# 📡 WebSocket broadcast (Board updates)
# ============================================================

def card_update(card):
    """
    Phát realtime tới group board_{board_id} để FE đồng bộ ngay khi card thay đổi.
    """
    try:
        board_id = card.list.board_id if card.list else None
        if not board_id:
            return
        payload = {
            "type": "card_update",
            "event": "card.update",
            "payload": {
                "id": card.id,
                "name": card.name,
                "list": card.list_id,
                "start_date": card.start_date.isoformat() if card.start_date else None,
                "due_date": card.due_date.isoformat() if card.due_date else None,
                "due_reminder_at": card.due_reminder_at.isoformat() if card.due_reminder_at else None,
                "recurrence": card.recurrence,
                "completed": card.completed,
            },
        }
        async_to_sync(channel_layer.group_send)(f"board_{board_id}", payload)
    except Exception as e:
        import logging
        logging.warning(f"[broadcast_card_update] failed: {e}")


# ============================================================
# 🧹 Optional: Cron-style function
# ============================================================

def process_due_reminders():
    """
    Chạy mỗi phút (cron hoặc management command) để gửi reminder
    cho những card đến hạn nhắc.
    """
    now = timezone.now()
    cards = Card.objects.filter(
        due_reminder_at__lte=now,
        completed=False
    )
    for card in cards:
        send_due_reminder_now(card)