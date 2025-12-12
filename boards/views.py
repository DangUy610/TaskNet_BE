# boards/views.py
from rest_framework import generics, status, filters
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.pagination import PageNumberPagination

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.db import models
from django.shortcuts import get_object_or_404, redirect
from django.db import transaction
from django.http import FileResponse, Http404
from django.utils.encoding import smart_str
from django.utils import timezone
from django.conf import settings
from django.urls import reverse

from urllib.parse import urlparse
from django.utils import timezone
from .models import (
    Board, Workspace, WorkspaceRole, WorkspaceMembership, List, Card, Label,
    BoardMembership, BoardInviteLink, Comment, Checklist, ChecklistItem,
    Attachment, CardActivity, BoardCreationPolicy, Notification,CardAssignee, CardWatcher,UserActivity
)
from .serializers import (
    WorkspaceSerializer,WorkspaceMembershipSerializer,WorkspaceTransferOwnershipSerializer, 
    ListSerializer, 
    CardSerializer,LabelSerializer, UserShortSerializer, 
    BoardMembershipSerializer,BoardSerializer, BoardInviteLinkSerializer, 
    CommentSerializer, CardActivitySerializer, 
    ChecklistSerializer,ChecklistItemSerializer, 
    AttachmentSerializer,BoardTransferOwnershipSerializer, NotificationMarkReadSerializer, NotificationSerializer,NotificationCreateSerializer,
    CardAssigneeSerializer, CardAssigneeBulkSetSerializer,
    CardWatcherSerializer, CardWatcherBulkSetSerializer,
    UserActivitySerializer,
)
from auth_app.serializers import UserAvatarSerializer
from .decorators import (
    require_board_admin,
    require_board_editor,
    require_card_editor,
    require_board_viewer,
    require_board_viewer_from_list,
    require_board_editor_from_list,
    require_board_admin_from_list,
)
from .permissions import (
    check_board_admin_permission,
    check_card_edit_permission,
    check_board_edit_permission,
    check_board_view_permission,
    check_workspace_member_permission,
    check_workspace_admin_permission,
    check_workspace_view_permission,
    can_create_board_in_workspace,
    can_delete_board,
    can_transfer_board_ownership,
    IsRecipient, user_can_edit_board,
    get_user_workspace_role,
)
from .services import notify_card_comment,schedule_due_reminder, card_update
User = get_user_model()


# ===================================================================
# Workspace & Boards
# ===================================================================

class WorkspaceListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        ws_ids_member = WorkspaceMembership.objects.filter(user=user).values('workspace_id')
        ws_ids_via_board = Board.objects.filter(
            Q(created_by=user) | Q(members=user)
        ).values('workspace_id')

        workspaces = Workspace.objects.filter(
            Q(owner=user) |
            Q(id__in=ws_ids_member) |
            Q(id__in=ws_ids_via_board)
        ).prefetch_related('workspace_memberships', 'boards').distinct()

        return Response(
            WorkspaceSerializer(
                workspaces,
                many=True,
                context={'request': request}
            ).data
        )

    def post(self, request):
        # dùng context để serializer tính đúng can_create_board, effective_role, is_owner
        serializer = WorkspaceSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        workspace = serializer.save(owner=request.user)

        # Đảm bảo owner cũng là admin trong WorkspaceMembership
        WorkspaceMembership.objects.get_or_create(
            workspace=workspace,
            user=request.user,
            defaults={'role': WorkspaceRole.ADMIN},
        )

        return Response(
            WorkspaceSerializer(workspace, context={'request': request}).data,
            status=status.HTTP_201_CREATED
        )

class WorkspaceDetailView(APIView):
    """
    - GET: owner + mọi thành viên (member/guest qua board) đều xem được (dùng helper).
    - PATCH: chỉ owner hoặc workspace admin (WorkspaceRole = 'admin').
    - DELETE: CHỈ owner được xoá workspace.
    """
    permission_classes = [IsAuthenticated]

    def get_object(self, workspace_id):
        return get_object_or_404(
            Workspace.objects.prefetch_related('workspace_memberships', 'boards'),
            pk=workspace_id
        )

    def get(self, request, workspace_id):
        workspace = self.get_object(workspace_id)
        check_workspace_view_permission(workspace, request.user)
        serializer = WorkspaceSerializer(workspace, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, workspace_id):
        workspace = self.get_object(workspace_id)
        # owner hoặc admin workspace mới được sửa
        check_workspace_admin_permission(workspace, request.user)

        serializer = WorkspaceSerializer(
            workspace,
            data=request.data,
            partial=True,
            context={'request': request},
        )
        serializer.is_valid(raise_exception=True)
        workspace = serializer.save()

        return Response(
            WorkspaceSerializer(workspace, context={'request': request}).data,
            status=status.HTTP_200_OK
        )

    def delete(self, request, workspace_id):
        """
        Chỉ owner được xoá workspace.
        """
        workspace = self.get_object(workspace_id)
        if workspace.owner_id != request.user.id:
            return Response(
                {"detail": "Only workspace owner can delete this workspace."},
                status=status.HTTP_403_FORBIDDEN
            )
        workspace.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class WorkspaceTransferOwnershipView(APIView):
    """
    POST /workspaces/<workspace_id>/transfer-ownership/
    Body: { "new_owner_id": 123 }
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, workspace_id):
        workspace = get_object_or_404(Workspace, pk=workspace_id)

        # 1. Chỉ Owner hiện tại mới được chuyển quyền
        if workspace.owner_id != request.user.id:
            return Response(
                {"detail": "Only the current owner can transfer ownership."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = WorkspaceTransferOwnershipSerializer(
            data=request.data, 
            context={'workspace': workspace}
        )
        serializer.is_valid(raise_exception=True)
        
        new_owner_id = serializer.validated_data['new_owner_id']
        new_owner = User.objects.get(pk=new_owner_id)

        # Nếu chuyển cho chính mình thì báo lỗi
        if new_owner_id == request.user.id:
             return Response({"detail": "You are already the owner."}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            # 2. Cập nhật Owner mới cho Workspace trong DB
            workspace.owner = new_owner
            workspace.save()

            # 3. Đảm bảo Owner mới có role là 'admin' trong bảng Membership
            WorkspaceMembership.objects.update_or_create(
                workspace=workspace,
                user=new_owner,
                defaults={'role': WorkspaceRole.ADMIN}
            )

            # 4. Owner cũ (bạn) sẽ trở thành 'admin' (để không bị mất quyền truy cập đột ngột)
            WorkspaceMembership.objects.update_or_create(
                workspace=workspace,
                user=request.user,
                defaults={'role': WorkspaceRole.ADMIN}
            )

        # 5. Gửi thông báo (Notification) - Gọi hàm từ services.py
        from .services import notify_workspace_ownership_transferred
        notify_workspace_ownership_transferred(request.user, workspace, new_owner)

        return Response({
            "detail": f"Ownership transferred to {new_owner.username}",
            "new_owner_id": new_owner.id
        }, status=status.HTTP_200_OK)
    
    
class WorkspaceMembersView(APIView):
    permission_classes = [IsAuthenticated]

    def get_workspace(self, workspace_id):
        return get_object_or_404(Workspace, pk=workspace_id)

    def _can_manage_members(self, workspace, user):
        """Check if user can manage workspace members (owner or admin)"""
        if workspace.owner_id == user.id:
            return True
        try:
            membership = WorkspaceMembership.objects.get(workspace=workspace, user=user)
            return membership.role == WorkspaceRole.ADMIN
        except WorkspaceMembership.DoesNotExist:
            return False

    def get(self, request, workspace_id):
        """Lấy danh sách thành viên của workspace."""
        workspace = self.get_workspace(workspace_id)
        check_workspace_view_permission(workspace, request.user)

        memberships = WorkspaceMembership.objects.filter(
            workspace=workspace
        ).select_related('user', 'user__profile')

        serializer = WorkspaceMembershipSerializer(memberships, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, workspace_id):
        """
        Mời user vào workspace bằng EMAIL hoặc user_id.
        Owner hoặc Admin được gọi.
        Body: { "email": "user@example.com", "role": "admin" | "member" }
        """
        workspace = self.get_workspace(workspace_id)
        
        if not self._can_manage_members(workspace, request.user):
            return Response(
                {"detail": "Only workspace owner or admin can invite members."},
                status=status.HTTP_403_FORBIDDEN
            )

        email = request.data.get("email", "").strip().lower()
        user_id = request.data.get("user_id")
        role = request.data.get("role", WorkspaceRole.MEMBER)

        # Validate role
        valid_roles = [choice[0] for choice in WorkspaceRole.choices]
        if role not in valid_roles:
            return Response(
                {"detail": f"Invalid role. Must be one of: {', '.join(valid_roles)}."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Tìm user
        user_to_invite = None
        if email:
            try:
                user_to_invite = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                return Response(
                    {"detail": f"No user found with email: {email}"},
                    status=status.HTTP_404_NOT_FOUND
                )
        elif user_id:
            user_to_invite = get_object_or_404(User, pk=user_id)
        else:
            return Response(
                {"detail": "email or user_id is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check: user đã là owner?
        if user_to_invite.id == workspace.owner_id:
            return Response(
                {"detail": "This user is already the workspace owner."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Tạo membership
        membership, created = WorkspaceMembership.objects.get_or_create(
            workspace=workspace,
            user=user_to_invite,
            defaults={"role": role},
        )

        if not created:
            return Response(
                {"detail": "User is already a member of this workspace."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # BỔ SUNG: Gọi service bắn thông báo
        from .services import notify_workspace_member_added
        notify_workspace_member_added(request.user, workspace, user_to_invite)

        return Response(
            WorkspaceMembershipSerializer(membership).data,
            status=status.HTTP_201_CREATED
        )
    

    def patch(self, request, workspace_id):
        """
        Đổi role của một member trong workspace.
        Owner hoặc Admin được gọi.
        Body: { "user_id": 123, "role": "admin" | "member" }
        """
        workspace = self.get_workspace(workspace_id)
        
        if not self._can_manage_members(workspace, request.user):
            return Response(
                {"detail": "Only workspace owner or admin can change member roles."},
                status=status.HTTP_403_FORBIDDEN
            )

        user_id = request.data.get("user_id")
        new_role = request.data.get("role")

        if not user_id or not new_role:
            return Response(
                {"detail": "user_id and role are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        valid_roles = [choice[0] for choice in WorkspaceRole.choices]
        if new_role not in valid_roles:
            return Response(
                {"detail": f"Invalid role. Must be one of: {', '.join(valid_roles)}."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            membership = WorkspaceMembership.objects.get(
                workspace=workspace, user_id=user_id
            )
        except WorkspaceMembership.DoesNotExist:
            return Response(
                {"detail": "Membership not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Không cho đổi role của owner
        if membership.user_id == workspace.owner_id:
            return Response(
                {"detail": "Cannot change role of workspace owner."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Admin không được đổi role của admin khác (chỉ owner)
        if membership.role == WorkspaceRole.ADMIN and workspace.owner_id != request.user.id:
            return Response(
                {"detail": "Only workspace owner can change admin roles."},
                status=status.HTTP_403_FORBIDDEN
            )

        membership.role = new_role
        membership.save()
        return Response(WorkspaceMembershipSerializer(membership).data)

    def delete(self, request, workspace_id):
        """
        Gỡ một member khỏi workspace.
        Owner hoặc Admin được gọi.
        Body: { "user_id": 123 }
        """
        workspace = self.get_workspace(workspace_id)
        
        if not self._can_manage_members(workspace, request.user):
            return Response(
                {"detail": "Only workspace owner or admin can remove members."},
                status=status.HTTP_403_FORBIDDEN
            )

        user_id = request.data.get("user_id")
        if not user_id:
            return Response(
                {"detail": "user_id is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            membership = WorkspaceMembership.objects.get(
                workspace=workspace, user_id=user_id
            )
        except WorkspaceMembership.DoesNotExist:
            return Response(
                {"detail": "Membership not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Không cho xoá owner
        if membership.user_id == workspace.owner_id:
            return Response(
                {"detail": "Cannot remove workspace owner."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Admin không được xoá admin khác (chỉ owner)
        if membership.role == WorkspaceRole.ADMIN and workspace.owner_id != request.user.id:
            return Response(
                {"detail": "Only workspace owner can remove admins."},
                status=status.HTTP_403_FORBIDDEN
            )

        membership.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    

class BoardListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, workspace_id):
        user = request.user
        workspace = get_object_or_404(Workspace, pk=workspace_id)

        # role: 'owner' | 'admin' | 'member' | 'guest' | None
        role = get_user_workspace_role(user, workspace)

        qs = Board.objects.filter(workspace=workspace, is_closed=False)

        if role == 'owner':
            # Owner thấy tất cả board của workspace
            boards = qs
        elif role == 'admin':
            # ADMIN:
            # - thấy tất cả board visibility = workspace/public
            # - + các board mình tạo hoặc là member (kể cả private)
            visible_q = (
                Q(visibility__in=['workspace', 'public']) |
                Q(created_by=user) |
                Q(members=user)
            )
            boards = qs.filter(visible_q)
        elif role in ('member', 'guest'):
            # MEMBER/GUEST:
            # - chỉ thấy board mình tạo hoặc là member
            visible_q = Q(created_by=user) | Q(members=user)
            boards = qs.filter(visible_q)
        else:
            # Không thuộc workspace:
            # - tuỳ bạn: ở đây cho phép nhìn các board public trong workspace
            boards = qs.filter(visibility='public')

        boards = boards.select_related('workspace').distinct()
        serializer = BoardSerializer(boards, many=True, context={'request': request})
        return Response(serializer.data)
    
    def post(self, request, workspace_id):
        """
        Tạo Board trong workspace: chỉ owner workspace mới được tạo (theo yêu cầu bạn đầu).
        Nếu muốn cho cả admin/member workspace được tạo, bạn có thể thay bằng check_workspace_member_permission.
        """
        DEFAULT_LABEL_COLORS = ['#61bd4f', '#f2d600', '#ff9f1a', '#eb5a46', '#c377e0', '#0079bf']

        ws = get_object_or_404(Workspace, pk=workspace_id)
        
        # ✅ dùng policy workspace
        if not can_create_board_in_workspace(request.user, ws):
            return Response(
                {"error": "You are not allowed to create boards in this workspace."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = BoardSerializer(data=request.data, context={'request': request, 'workspace': ws})
        serializer.is_valid(raise_exception=True)
        board = serializer.save()

        # tạo sẵn 6 nhãn mặc định
        for color in DEFAULT_LABEL_COLORS:
            Label.objects.create(name='', color=color, board=board)

        return Response(BoardSerializer(board, context={'request': request}).data, status=status.HTTP_201_CREATED)


class BoardDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_viewer('board_id')
    def get(self, request, workspace_id, board_id):
        board = get_object_or_404(Board.objects.select_related('workspace'), pk=board_id, workspace_id=workspace_id)
        return Response(BoardSerializer(board, context={'request': request}).data)

    @require_board_admin('board_id')
    def patch(self, request, workspace_id, board_id):
        board = get_object_or_404(Board.objects.select_related('workspace'), pk=board_id, workspace_id=workspace_id)
        if 'is_closed' in request.data:
            board.is_closed = bool(request.data['is_closed'])
            board.save(update_fields=['is_closed'])
        return Response(BoardSerializer(board, context={'request': request}).data)

    def delete(self, request, workspace_id, board_id):
        board = get_object_or_404(Board.objects.select_related('workspace'), pk=board_id, workspace_id=workspace_id)
        
        if not can_delete_board(request.user, board):
            return Response({'error': 'You do not have permission to delete this board.'},status=status.HTTP_403_FORBIDDEN)
        
        board.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ClosedBoardsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        boards = (
            Board.objects
            .filter(Q(created_by=request.user) | Q(members=request.user), is_closed=True)
            .distinct()
            .select_related('workspace')
        )
        return Response(BoardSerializer(boards, many=True, context={'request': request}).data)

# ===================================================================
# Lists & Cards
# ===================================================================

class ListsCreateView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_viewer('board_id')
    def get(self, request, board_id):
        include = (request.query_params.get('include') or '').lower()
        lists = List.objects.filter(board_id=board_id).order_by('position', 'id')

        if 'cards' in include:
            from .serializers import ListWithCardsSerializer  # import tại chỗ để tránh import cycle
            ser = ListWithCardsSerializer(lists, many=True, context={'request': request})
        else:
            ser = ListSerializer(lists, many=True)

        return Response(ser.data)

    @require_board_editor('board_id')
    def post(self, request, board_id):
        ser = ListSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save(board_id=board_id)
        return Response(ser.data, status=status.HTTP_201_CREATED)


class ListDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_editor_from_list('pk')
    def patch(self, request, pk):
        lst = get_object_or_404(List, pk=pk)
        ser = ListSerializer(lst, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)

    @require_board_admin_from_list('pk')
    def delete(self, request, pk):
        lst = get_object_or_404(List, pk=pk)
        Card.objects.filter(list=lst).update(list=None)
        lst.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CardListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_viewer_from_list('list_id')
    def get(self, request, list_id):
        cards = (
            Card.objects
            .filter(list_id=list_id)
            .prefetch_related('labels')
            .order_by('position', 'id')
        )
        return Response(CardSerializer(cards, many=True, context={'request': request}).data)

    @require_board_editor_from_list('list_id')
    def post(self, request, list_id):
        ser = CardSerializer(data=request.data, context={'request': request})
        ser.is_valid(raise_exception=True)
        # gán list_id + created_by
        card = ser.save(list_id=list_id, created_by=request.user)
        return Response(CardSerializer(card, context={'request': request}).data, status=status.HTTP_201_CREATED)


class CardDetailView(APIView):
    """
    API chi tiết cho Card: GET (retrieve) + PATCH (update)
    GET /cards/{pk}/      - Lấy thông tin card
    PATCH /cards/{pk}/    - Cập nhật card
    DELETE /cards/{pk}/   - Xóa card (optional)
    """
    permission_classes = [IsAuthenticated]
    
    def get_object(self, pk, user):
        """
        Helper: Lấy card và check permission
        Returns: Card object hoặc None nếu không tìm thấy/không có quyền
        """
        try:
            card = (
                Card.objects
                .select_related("list__board", "created_by")
                .prefetch_related(
                    "labels",
                    "checklists__items",
                    "attachments",
                    "comments",
                )
                .get(pk=pk)
            )
        except Card.DoesNotExist:
            return None
        
        # Check permission
        if card.list:
            # Card trong board → check board view permission
            from .serializers import user_can_view_board
            if not user_can_view_board(user, card.list.board):
                return None
        else:
            # Card trong inbox
            if card.created_by != user:
                # Check nếu có common board
                has_common = Board.objects.filter(
                    Q(created_by=user) | Q(members=user)
                ).filter(
                    Q(created_by=card.created_by) | Q(members=card.created_by)
                ).exists()
                if not has_common:
                    return None
        
        return card

    def get(self, request, pk):
        """
        GET /cards/{pk}/
        Lấy thông tin đầy đủ của card bao gồm:
        - Basic info (name, description, status, ...)
        - Labels
        - Members
        - Checklists với items
        - Attachments
        - Comments count
        - Activities (optional)
        """
        card = self.get_object(pk, request.user)
        if not card:
            return Response(
                {"detail": "Card not found or you don't have permission to view it."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = CardSerializer(card, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, pk):
        """
        PATCH /cards/{pk}/
        Cập nhật card với activity logging và auto-scheduling
        """
        card = self.get_object(pk, request.user)
        if not card:
            return Response(
                {"detail": "Card not found or permission denied."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check edit permission
        if card.list and not user_can_edit_board(request.user, card.list.board):
            return Response(
                {"detail": "You don't have permission to edit this card."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = CardSerializer(
            card,
            data=request.data,
            partial=True,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        # Backup for activity logging
        old_data = {
            "start_date": card.start_date,
            "due_date": card.due_date,
            "due_reminder_offset": card.due_reminder_offset,
            "recurrence": card.recurrence,
            "completed": card.completed,
        }

        serializer.save()
        card.refresh_from_db()
        # 🔔 bắn notify thay đổi thuộc tính
        changes = {k: (old_data[k], getattr(card, k)) for k in old_data if old_data[k] != getattr(card, k)}
        from .services import notify_card_field_changes
        notify_card_field_changes(request.user, card, changes)

        # Activity logging helper
        def log_change(field, desc):
            CardActivity.objects.create(
                card=card,
                user=request.user,
                activity_type="card_updated",
                description=desc,
            )

        # Log changes
        if old_data["start_date"] != card.start_date:
            desc = (
                f"set start date to {card.start_date.strftime('%b %d at %I:%M %p')}"
                if card.start_date else "removed start date"
            )
            log_change("start_date", desc)

        if old_data["due_date"] != card.due_date:
            desc = (
                f"set due date to {card.due_date.strftime('%b %d at %I:%M %p')}"
                if card.due_date else "removed due date"
            )
            CardActivity.objects.create(
                card=card,
                user=request.user,
                activity_type="due_date_changed",
                description=desc,
            )

        if old_data["due_reminder_offset"] != card.due_reminder_offset:
            desc = (
                f"set reminder to {card.due_reminder_offset} minutes before due date"
                if card.due_reminder_offset else "removed reminder"
            )
            log_change("due_reminder_offset", desc)

        if old_data["recurrence"] != card.recurrence:
            desc = f"changed recurrence to {card.recurrence}"
            log_change("recurrence", desc)

        # Auto-handle recurrence
        if request.data.get("completed") is True and card.recurrence != "never":
            next_due = card.next_recurrence_due()
            if next_due:
                card.due_date = next_due
                card.completed = False
                card.completed_at = None
                card.due_reminder_at = card.compute_due_reminder_at()
                card.save(update_fields=[
                    "due_date", "completed", "completed_at", "due_reminder_at"
                ])
                CardActivity.objects.create(
                    card=card,
                    user=request.user,
                    activity_type="due_date_changed",
                    description=f"auto scheduled next due date to {card.due_date.strftime('%b %d at %I:%M %p')}",
                )

        # Schedule reminder
        schedule_due_reminder(card)

        # Broadcast update
        card_update(card)

        return Response(
            CardSerializer(card, context={'request': request}).data,
            status=status.HTTP_200_OK
        )
    
    def delete(self, request, pk):
        """
        DELETE /cards/{pk}/
        Xóa card (optional - nếu cần)
        """
        card = self.get_object(pk, request.user)
        if not card:
            return Response(
                {"detail": "Card not found or permission denied."},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check delete permission (admin only)
        if card.list:
            from .permissions import check_board_admin_permission
            check_board_admin_permission(card.list.board, request.user)
        elif card.created_by != request.user:
            return Response(
                {"detail": "Only card creator can delete inbox cards."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        card.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class InboxCardCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user_accessible_boards = (
            Board.objects
            .filter(Q(created_by=request.user) | Q(members=request.user) | Q(workspace__owner=request.user))
            .distinct()
        )

        # Lấy 1 lần, không đặt trong vòng lặp
        member_ids = set(
            BoardMembership.objects
            .filter(board__in=user_accessible_boards)
            .values_list('user_id', flat=True)
        )
        creator_ids = set(user_accessible_boards.values_list('created_by_id', flat=True))
        related_user_ids = member_ids | creator_ids | {request.user.id}  # luôn gồm chính bạn

        cards = (
            Card.objects
            .filter(list__isnull=True, created_by_id__in=related_user_ids)
            .prefetch_related('labels')
            .order_by('position', 'id')
        )
        return Response(CardSerializer(cards, many=True, context={'request': request}).data)

    def post(self, request):
        ser = CardSerializer(data=request.data, context={'request': request})
        ser.is_valid(raise_exception=True)
        card = ser.save(created_by=request.user)   # list sẽ là None nếu FE không gửi
        return Response(CardSerializer(card, context={'request': request}).data, status=status.HTTP_201_CREATED)


class CardBatchUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        updates = request.data
        if not isinstance(updates, list) or not updates:
            return Response({"error": "Request body must be a non-empty list"}, status=400)

        first_card = get_object_or_404(Card, id=updates[0].get("id"))
        if not first_card.list:
            return Response({"error": "Inbox cards cannot be batch-updated here"}, status=400)
        board = first_card.list.board
        check_board_admin_permission(board, request.user)

        with transaction.atomic():
            for upd in updates:
                card = Card.objects.select_for_update().get(id=upd["id"])
                if not card.list or card.list.board_id != board.id:
                    return Response({"error": "All cards must belong to the same board"}, status=400)
                ser = CardSerializer(card, data=upd, partial=True, context={'request': request})
                ser.is_valid(raise_exception=True)
                ser.save()

        return Response({"message": "Cards updated successfully"}, status=200)

# ===================================================================
# Members, Labels, Share Link
# ===================================================================

class BoardMembersView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_viewer('board_id')
    def get(self, request, board_id):
        memberships = BoardMembership.objects.filter(board_id=board_id).select_related('user')
        return Response(BoardMembershipSerializer(memberships, many=True).data)

    @require_board_admin('board_id')
    def post(self, request, board_id):
        board = get_object_or_404(Board, pk=board_id)
        user_id = request.data.get('user_id')
        role = request.data.get('role', 'viewer')
        if not user_id:
            return Response({'error': 'user_id is required'}, status=400)
        if role not in ['admin', 'editor', 'viewer']:
            return Response({'error': 'Invalid role'}, status=400)

        user_to_invite = get_object_or_404(User, pk=user_id)
        if BoardMembership.objects.filter(board=board, user=user_to_invite).exists() or board.created_by == user_to_invite:
            return Response({'message': 'User is already a member.'}, status=400)
        
        membership = BoardMembership.objects.create(board=board, user=user_to_invite, role=role)
        from .services import notify_board_member_added
        notify_board_member_added(request.user, board, user_to_invite)
        return Response(BoardMembershipSerializer(membership).data, status=201)


    @require_board_admin('board_id')
    def patch(self, request, board_id):
        board = get_object_or_404(Board, pk=board_id)
        user_id = request.data.get('user_id')
        new_role = request.data.get('role')
        if not user_id or not new_role:
            return Response({'error': 'user_id and role are required'}, status=400)
        if new_role not in ['admin', 'editor', 'viewer']:
            return Response({'error': 'Invalid role'}, status=400)

        try:
            membership = BoardMembership.objects.get(board=board, user_id=user_id)
            if membership.user == board.created_by:
                return Response({'error': 'Cannot change the role of the board owner.'}, status=400)
            membership.role = new_role
            membership.save()
            return Response(BoardMembershipSerializer(membership).data)
        except BoardMembership.DoesNotExist:
            return Response({'error': 'Membership not found'}, status=404)

    @require_board_admin('board_id')
    def delete(self, request, board_id):
        board = get_object_or_404(Board, pk=board_id)
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({'error': 'user_id is required'}, status=400)
        try:
            membership = BoardMembership.objects.get(board=board, user_id=user_id)
            if membership.user == board.get_owner():
                return Response({'error': 'Cannot modify board owner.'}, status=400)

            membership.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except BoardMembership.DoesNotExist:
            return Response({'error': 'Membership not found'}, status=404)


class BoardLabelListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_viewer('board_id')
    def get(self, request, board_id):
        labels = Label.objects.filter(board_id=board_id)
        return Response(LabelSerializer(labels, many=True).data)

    @require_board_admin('board_id')
    def post(self, request, board_id):
        board = get_object_or_404(Board, pk=board_id)
        ser = LabelSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        ser.save(board=board)
        return Response(ser.data, status=201)


class LabelDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_admin(lambda self, request, label_id: get_object_or_404(Label, pk=label_id).board)  # dùng board từ label -> xem dưới
    def patch(self, request, label_id):
        label = get_object_or_404(Label, pk=label_id)
        ser = LabelSerializer(label, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)

    @require_board_admin(lambda self, request, label_id: get_object_or_404(Label, pk=label_id).board)
    def delete(self, request, label_id):
        label = get_object_or_404(Label, pk=label_id)
        label.delete()
        return Response(status=204)

class LabelCreateView(APIView):
    """
    API tạo Label độc lập: POST /api/labels/
    Body: { "name": "abc", "color": "#fff", "board_id": 1 }
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # 1. Xử lý map 'boardId' từ frontend (nếu có) sang 'board_id' chuẩn Python
        data = request.data.copy()
        if 'boardId' in data and 'board_id' not in data:
            data['board_id'] = data.pop('boardId')

        # 2. Validate dữ liệu
        serializer = LabelSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        # 3. Kiểm tra quyền (Chỉ Board Admin mới được tạo label - hoặc tuỳ logic bạn)
        board = serializer.validated_data['board']
        check_board_admin_permission(board, request.user)

        # 4. Lưu và trả về
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class BoardTransferOwnershipView(APIView):
    """
    POST /workspaces/<workspace_id>/boards/<board_id>/transfer-owner/
    Body: { "new_owner_id": <int> }
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, workspace_id, board_id):
        board = get_object_or_404(Board, pk=board_id, workspace_id=workspace_id)
        # chỉ cho board owner / workspace owner / (tuỳ chọn) workspace admin
        if not can_transfer_board_ownership(request.user, board):
            return Response({'error': "You are not allowed to transfer this board's ownership."},
                            status=status.HTTP_403_FORBIDDEN)

        from .serializers import BoardTransferOwnershipSerializer
        from django.contrib.auth import get_user_model
        User = get_user_model()
        ser = BoardTransferOwnershipSerializer(data=request.data, context={'board': board, 'request': request})
        ser.is_valid(raise_exception=True)
        new_owner_id = ser.validated_data['new_owner_id']
        new_owner = get_object_or_404(User, pk=new_owner_id)

        board.transfer_ownership(new_owner)
        return Response({'message': f'Board ownership transferred to {new_owner.username}',
                         'new_owner': new_owner.username}, status=status.HTTP_200_OK)

# BoardShareLinkView giữ nguyên logic admin
class BoardShareLinkView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_admin('board_id')
    def get(self, request, board_id):
        invite = BoardInviteLink.objects.filter(board_id=board_id, is_active=True).first()
        if not invite:
            return Response({"has_active": False, "invite_link": None, "expires_at": None}, status=200)
        ser = BoardInviteLinkSerializer(invite)
        return Response({"has_active": True, "token": ser.data["token"], "expires_at": ser.data.get("expires_at")})

    @require_board_admin('board_id')
    def post(self, request, board_id):
        role = request.data.get('role', 'member')
        invite, _ = BoardInviteLink.objects.update_or_create(
            board_id=board_id,
            defaults={'role': role, 'is_active': True, 'created_by': request.user}
        )
        return Response(BoardInviteLinkSerializer(invite).data)

    @require_board_admin('board_id')
    def delete(self, request, board_id):
        BoardInviteLink.objects.filter(board_id=board_id, is_active=True).update(is_active=False)
        return Response(status=status.HTTP_204_NO_CONTENT)


class BoardJoinByLinkView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, token):
        invite = get_object_or_404(BoardInviteLink, token=token, is_active=True)
        if invite.is_expired():
            return Response({'detail': 'Invite link has expired'}, status=status.HTTP_410_GONE)

        board = invite.board
        user = request.user

        if BoardMembership.objects.filter(board=board, user=user).exists():
            return Response({'detail': 'Already a member'}, status=200)

        role_map = {'member': 'editor', 'admin': 'admin', 'observer': 'viewer'}
        membership_role = role_map.get(invite.role, 'viewer')

        BoardMembership.objects.create(board=board, user=user, role=membership_role)
        return Response({'detail': 'Joined board successfully', 'role': membership_role}, status=201)
    
class BoardEmailInvitationView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_admin(lambda self, request, board_id: Board.objects.get(id=board_id))
    def post(self, request, board_id):
        email = (request.data.get('email') or '').strip().lower()
        role  = request.data.get('role', 'member')
        if role not in ['member', 'admin', 'observer']:
            return Response({'detail': 'Invalid role'}, status=400)
        if not email:
            return Response({'detail': 'email is required'}, status=400)

        # ensure active invite link
        invite, _ = BoardInviteLink.objects.update_or_create(
            board_id=board_id,
            defaults={'role': role, 'is_active': True, 'created_by': request.user}
        )

        # build join url
        base = getattr(settings, 'FRONTEND_ORIGIN', None) or request.build_absolute_uri('/')[:-1]
        join_path = reverse('board-join-by-link', kwargs={'token': invite.token})
        invite_url = request.build_absolute_uri(join_path)  # API join URL (FE có thể deep link)
        # Hoặc nếu muốn link frontend: f"{base}/join/{invite.token}"

        # TODO: gửi email thực tế ở đây (nếu có mailer)
        # send_invite_email(email, invite_url)

        return Response({'email': email, 'token': str(invite.token), 'invite_url': invite_url}, status=201)


# ===================================================================
# Comments / Membership on Card / Watchers / Activities
# ===================================================================

class CardCommentsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, card_id):
        card = get_object_or_404(Card.objects.select_related('list__board', 'created_by'), pk=card_id)
        if card.list:
            check_board_view_permission(card.list.board, request.user)
        else:
            if card.created_by != request.user:
                has_common = Board.objects.filter(Q(created_by=request.user) | Q(members=request.user)) \
                    .filter(Q(created_by=card.created_by) | Q(members=card.created_by)).exists()
                if not has_common:
                    return Response({'detail': 'Forbidden'}, status=403)
                
        qs = Comment.objects.filter(card=card)\
            .select_related('author__profile')\
            .order_by('-created_at')
        return Response(CommentSerializer(
            qs, 
            many=True,
            context={'request': request} 
        ).data)

    def post(self, request, card_id):
        card = get_object_or_404(Card.objects.select_related('list__board'), pk=card_id)
        check_card_edit_permission(card, request.user)
        ser = CommentSerializer(data={'content': request.data.get('content', ''), 'card': card.id})
        ser.is_valid(raise_exception=True)
        cmt = Comment.objects.create(card=card, author=request.user, content=ser.validated_data['content'])
        # 🔔 Gọi service: tạo Notification + broadcast sau khi DB commit
        notify_card_comment(request.user, card, cmt)
        return Response(CommentSerializer(cmt).data, status=201)


class CommentDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, comment_id):
        cmt = get_object_or_404(Comment.objects.select_related('card__list__board'), pk=comment_id)
        if cmt.author != request.user:
            check_card_edit_permission(cmt.card, request.user)
        ser = CommentSerializer(cmt, data={'content': request.data.get('content', '')}, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(ser.data)

    def delete(self, request, comment_id):
        cmt = get_object_or_404(Comment.objects.select_related('card__list__board'), pk=comment_id)
        if cmt.author != request.user:
            check_card_edit_permission(cmt.card, request.user)
        cmt.delete()
        return Response(status=204)



# Assignees
class CardAssigneeListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, card_id):
        card = Card.objects.select_related('list__board').get(pk=card_id)
        check_board_view_permission(card.list.board, request.user)
        qs = CardAssignee.objects.filter(card=card).select_related('user', 'assigned_by')
        return Response(CardAssigneeSerializer(qs, many=True).data)

class CardAssigneeBulkSetView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, card_id):
        card = Card.objects.select_related('list__board').get(pk=card_id)
        check_board_edit_permission(card.list.board, request.user)
        ser = CardAssigneeBulkSetSerializer(data=request.data, context={'card': card, 'request': request})
        ser.is_valid(raise_exception=True)
        ser.save()
        qs = CardAssignee.objects.filter(card=card).select_related('user', 'assigned_by')
        return Response(CardAssigneeSerializer(qs, many=True).data, status=200)

# Watchers
class CardWatcherListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, card_id):
        card = Card.objects.select_related('list__board').get(pk=card_id)
        check_board_view_permission(card.list.board, request.user)
        qs = CardWatcher.objects.filter(card=card).select_related('user', 'enabled_by')
        return Response(CardWatcherSerializer(qs, many=True).data)

class CardWatcherBulkSetView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, card_id):
        card = Card.objects.select_related('list__board').get(pk=card_id)
        check_board_edit_permission(card.list.board, request.user)
        ser = CardWatcherBulkSetSerializer(data=request.data, context={'card': card, 'request': request})
        ser.is_valid(raise_exception=True)
        ser.save()
        qs = CardWatcher.objects.filter(card=card).select_related('user', 'enabled_by')
        return Response(CardWatcherSerializer(qs, many=True).data, status=200)


class CardActivityView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, card_id):
        card = get_object_or_404(Card, pk=card_id)
        if card.list:
            check_board_view_permission(card.list.board, request.user)
        
        # ✅ Prefetch profile và target_user profile
        activities = card.activities.select_related(
            'user__profile',           # User profile
            'target_user__profile'     # Target user profile
        )[:50]
        
        return Response(
            CardActivitySerializer(activities, many=True, context={'request': request}).data
        )

# ===================================================================
# Checklist CRUD
# ===================================================================

class CardChecklistListView(generics.ListCreateAPIView):
    serializer_class = ChecklistSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        card_id = self.kwargs['card_id']
        return Checklist.objects.filter(card_id=card_id)

    def perform_create(self, serializer):
        card_id = self.kwargs['card_id']
        card = get_object_or_404(Card, pk=card_id)
        serializer.save(card=card, created_by=self.request.user)


class ChecklistDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Checklist.objects.all()
    serializer_class = ChecklistSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        checklist = serializer.save()
        if 'title' in self.request.data:
            CardActivity.objects.create(
                card=checklist.card, user=self.request.user,
                activity_type='card_updated', description=f'renamed checklist to "{checklist.title}"'
            )

    def perform_destroy(self, instance):
        CardActivity.objects.create(
            card=instance.card, user=self.request.user,
            activity_type='card_updated', description=f'deleted checklist "{instance.title}"'
        )
        super().perform_destroy(instance)

# ===================================================================
# Checklist Item CRUD
# ===================================================================

class ChecklistItemListView(generics.ListCreateAPIView):
    serializer_class = ChecklistItemSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ChecklistItem.objects.filter(checklist_id=self.kwargs['checklist_id'])

    def perform_create(self, serializer):
        checklist = get_object_or_404(Checklist, pk=self.kwargs['checklist_id'])
        serializer.save(checklist=checklist)


class ChecklistItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ChecklistItem.objects.all()
    serializer_class = ChecklistItemSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        old_completed = serializer.instance.completed
        item = serializer.save()
        if 'completed' in self.request.data and old_completed != item.completed:
            action = 'completed' if item.completed else 'marked incomplete'
            CardActivity.objects.create(
                card=item.checklist.card, user=self.request.user,
                activity_type='card_updated',
                description=f'{action} "{item.text}" on {item.checklist.title}'
            )

# ===================================================================
# Special actions / Attachments
# ===================================================================

class ReorderItemsView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        checklist = get_object_or_404(Checklist, pk=pk)
        item_ids = request.data.get("item_ids", [])
        for index, item_id in enumerate(item_ids):
            ChecklistItem.objects.filter(pk=item_id, checklist=checklist).update(position=index)
        return Response({"detail": "Items reordered"}, status=200)


class ConvertItemToCardView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        item = get_object_or_404(ChecklistItem, pk=pk)
        parent = item.checklist.card
        new_card = Card.objects.create(name=item.text, list=parent.list, created_by=request.user)
        item.delete()
        return Response({"detail": "Item converted to card", "card_id": new_card.id}, status=201)

# ====== Helpers ======
def _to_bool(val):
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in {"1", "true", "yes", "on"}

def _is_http_url(url: str) -> bool:
    try:
        p = urlparse(url or "")
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

ALLOWED_MIME_PREFIXES = ("image/", "video/", "audio/", "application/pdf", "text/")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10MB


class CardAttachmentsView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def _ensure_can_view_card(self, card, user):
        if card.list:
            check_board_view_permission(card.list.board, user)
            return
        if card.created_by == user:
            return
        has_common = Board.objects.filter(Q(created_by=user) | Q(members=user)) \
            .filter(Q(created_by=card.created_by) | Q(members=card.created_by)).exists()
        if not has_common:
            raise PermissionError("Forbidden")

    def get(self, request, card_id):
        card = get_object_or_404(Card.objects.select_related("list__board", "created_by"), id=card_id)
        try:
            self._ensure_can_view_card(card, request.user)
        except PermissionError:
            return Response({'detail': 'Forbidden'}, status=403)

        qs = card.attachments.select_related("uploaded_by").all()
        try:
            limit = int(request.query_params.get("limit", 50))
            offset = int(request.query_params.get("offset", 0))
        except ValueError:
            limit, offset = 50, 0
        total = qs.count()
        items = qs[offset:offset + limit]
        ser = AttachmentSerializer(items, many=True, context={'request': request})
        return Response({"count": total, "limit": limit, "offset": offset, "results": ser.data})

    def post(self, request, card_id):
        card = get_object_or_404(Card.objects.select_related("list__board"), id=card_id)
        check_card_edit_permission(card, request.user)

        attachment_type = (request.data.get('attachment_type') or 'file').strip().lower()
        if attachment_type == 'file':
            file_obj = request.FILES.get('file')
            if not file_obj:
                return Response({'detail': 'File is required for file upload'}, status=400)
            if getattr(file_obj, "size", 0) > MAX_UPLOAD_BYTES:
                return Response({'detail': f'File size must be less than {MAX_UPLOAD_BYTES // (1024*1024)}MB'},
                                status=400)
            content_type = getattr(file_obj, "content_type", "") or ""
            if not any(content_type.startswith(pfx) for pfx in ALLOWED_MIME_PREFIXES):
                return Response({'detail': f'File type "{content_type}" not allowed.'}, status=400)
            data = {
                'name': request.data.get('name') or getattr(file_obj, 'name', 'Attachment'),
                'attachment_type': 'file',
                'file': file_obj
            }
        elif attachment_type == 'link':
            url = request.data.get('url')
            if not url or not _is_http_url(url):
                return Response({'detail': 'A valid http/https URL is required for link attachment'}, status=400)
            data = {'name': request.data.get('name') or url, 'attachment_type': 'link', 'url': url}
        else:
            return Response({'detail': 'Invalid attachment type'}, status=400)

        ser = AttachmentSerializer(data=data, context={'request': request})
        ser.is_valid(raise_exception=True)
        attachment = ser.save(card=card, uploaded_by=request.user)

        # log
        CardActivity.objects.create(card=card, user=request.user, activity_type='card_updated',
                                    description=f'added attachment "{attachment.name}"')
        return Response(ser.data, status=201)

    def patch(self, request, attachment_id):
        attachment = get_object_or_404(Attachment.objects.select_related("card__list__board"), id=attachment_id)
        check_card_edit_permission(attachment.card, request.user)

        is_cover_in = request.data.get('is_cover', None)
        will_set_cover = _to_bool(is_cover_in)

        with transaction.atomic():
            if is_cover_in is not None and will_set_cover:
                Attachment.objects.filter(card=attachment.card, is_cover=True).exclude(id=attachment.id).update(is_cover=False)

            ser = AttachmentSerializer(attachment, data=request.data, partial=True, context={'request': request})
            ser.is_valid(raise_exception=True)
            obj = ser.save()

        if 'name' in request.data:
            CardActivity.objects.create(card=attachment.card, user=request.user, activity_type='card_updated',
                                        description=f'renamed attachment to "{obj.name}"')
        if is_cover_in is not None:
            CardActivity.objects.create(
                card=attachment.card, user=request.user, activity_type='card_updated',
                description='set card cover from attachment' if will_set_cover else 'unset card cover'
            )
        return Response(ser.data)

    def delete(self, request, attachment_id):
        attachment = get_object_or_404(Attachment.objects.select_related("card__list__board"), id=attachment_id)
        check_card_edit_permission(attachment.card, request.user)

        CardActivity.objects.create(card=attachment.card, user=request.user, activity_type='card_updated',
                                    description=f'removed attachment "{attachment.name}"')
        if attachment.file:
            try:
                attachment.file.storage.delete(attachment.file.name)
            except Exception:
                pass
        attachment.delete()
        return Response(status=204)
class AttachmentDetailView(APIView):
    """Quản lý attachment cụ thể"""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request, attachment_id):
        """
        Download file attachment:
        - Nếu type = file: stream FileResponse
        - Nếu type = link: redirect 302 tới URL
        """
        attachment = get_object_or_404(
            Attachment.objects.select_related("card__list__board"),
            id=attachment_id
        )

        card = attachment.card
        if card.list:
            check_board_view_permission(card.list.board, request.user)
        else:
            if card.created_by != request.user:
                return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

        if attachment.attachment_type == 'file' and attachment.file:
            try:
                file_handle = attachment.file.storage.open(attachment.file.name, 'rb')
            except FileNotFoundError:
                return Response({'detail': 'File not found'}, status=status.HTTP_404_NOT_FOUND)

            filename = smart_str(attachment.name or attachment.file.name)
            content_type = attachment.mime_type or 'application/octet-stream'
            return FileResponse(file_handle, as_attachment=True, filename=filename, content_type=content_type)

        elif attachment.attachment_type == 'link':
            if not _is_http_url(attachment.url):
                return Response({'detail': 'Invalid URL'}, status=status.HTTP_400_BAD_REQUEST)
            return redirect(attachment.url)

        return Response({'detail': 'File not found'}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, attachment_id):
        """Cập nhật attachment (tên, cover,…)"""
        attachment = get_object_or_404(
            Attachment.objects.select_related("card__list__board"),
            id=attachment_id
        )
        check_card_edit_permission(attachment.card, request.user)

        is_cover_in = request.data.get('is_cover', None)
        will_set_cover = _to_bool(is_cover_in)

        with transaction.atomic():
            if is_cover_in is not None and will_set_cover:
                Attachment.objects.filter(card=attachment.card, is_cover=True)\
                    .exclude(id=attachment.id).update(is_cover=False)

            serializer = AttachmentSerializer(attachment, data=request.data, partial=True, context={'request': request})
            serializer.is_valid(raise_exception=True)
            obj = serializer.save()

        # Log activity
        if 'name' in request.data:
            CardActivity.objects.create(
                card=attachment.card, user=request.user,
                activity_type='card_updated',
                description=f'renamed attachment to "{obj.name}"'
            )
        if is_cover_in is not None:
            CardActivity.objects.create(
                card=attachment.card, user=request.user,
                activity_type='card_updated',
                description='set card cover from attachment' if will_set_cover else 'unset card cover'
            )

        return Response(serializer.data)

    def delete(self, request, attachment_id):
        """Xóa attachment (và file ở storage nếu có)"""
        attachment = get_object_or_404(
            Attachment.objects.select_related("card__list__board"),
            id=attachment_id
        )
        check_card_edit_permission(attachment.card, request.user)

        CardActivity.objects.create(
            card=attachment.card,
            user=request.user,
            activity_type='card_updated',
            description=f'removed attachment "{attachment.name}"'
        )

        if attachment.file:
            try:
                attachment.file.storage.delete(attachment.file.name)
            except Exception:
                pass

        attachment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class UserSearchView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        q = (request.query_params.get('q') or '').strip()
        if not q:
            return Response([], status=200)

        users = User.objects.filter(
            Q(email__icontains=q) | Q(username__icontains=q)
        ).select_related('profile').order_by('username')[:10]

        # ✅ Sử dụng serializer có sẵn từ auth_app
        profiles = [u.profile for u in users if hasattr(u, 'profile')]
        serializer = UserAvatarSerializer(profiles, many=True, context={'request': request})
        return Response(serializer.data, status=200)
    
#==================Notification=================
class NotificationListView(generics.ListAPIView):
    """
    GET /api/notifications/?unread=true|false&level=info|warning|...
    Hỗ trợ tìm kiếm theo verb & data (simple), sắp xếp theo -created_at.
    """
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["verb", "data"]
    ordering_fields = ["created_at", "level"]
    ordering = ["-created_at"]

    def get_queryset(self):
        qs = Notification.objects.filter(recipient=self.request.user)
        # Back-compat: ?unread=true|false
        unread = self.request.query_params.get("unread")
        if unread == "true":
            qs = qs.filter(is_read=False)
        elif unread == "false":
            qs = qs.filter(is_read=True)

        status_q = (self.request.query_params.get("status") or "").strip().lower()
        if status_q == "unread":
            qs = qs.filter(is_read=False)
        elif status_q == "read":
            qs = qs.filter(is_read=True)

        level = self.request.query_params.get("level")
        if level:
            qs = qs.filter(level=level)

        return qs.select_related("actor").prefetch_related()

class NotificationDetailView(generics.RetrieveDestroyAPIView):
    """
    GET /api/notifications/<id>/
    DELETE /api/notifications/<id>/
    """
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated, IsRecipient]
    queryset = Notification.objects.all()

class NotificationMarkReadView(generics.UpdateAPIView):
    """
    PATCH /api/notifications/<id>/read/
    body: {"is_read": true}  # hoặc false để “đánh dấu chưa đọc”
    """
    serializer_class = NotificationMarkReadSerializer
    permission_classes = [IsAuthenticated, IsRecipient]
    queryset = Notification.objects.all()

class NotificationUnreadCountView(APIView):
    """
    GET /api/notifications/unread-count/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        count = Notification.objects.filter(recipient=request.user, is_read=False).count()
        return Response({"unread": count})

class NotificationMarkAllReadView(APIView):
    """
    POST /api/notifications/mark-all-read/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        qs = Notification.objects.filter(recipient=request.user, is_read=False)
        updated = 0
        from django.utils import timezone
        now = timezone.now()
        updated = qs.update(is_read=True, read_at=now)
        return Response({"updated": updated}, status=status.HTTP_200_OK)
    
class NotificationCreateView(generics.CreateAPIView):
    """Cho phép FE tạo thông báo thủ công"""
    serializer_class = NotificationCreateSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(actor=self.request.user)    



class BoardPlannerDataView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_viewer('board_id')
    def get(self, request, board_id):
        # 1) Lấy lists của board
        lists = (
            List.objects
            .filter(board_id=board_id)
            .prefetch_related('cards__labels')   # prefetch cards & labels
            .order_by('position', 'id')
        )

        # 2) Lấy inbox cards liên quan đến board
        # Inbox card = card.list is null nhưng creator share board với user
        user = request.user

        inbox_cards = (
            Card.objects
            .filter(list__isnull=True)
            .filter(
                models.Q(created_by=user) |
                models.Q(created_by__boards__id=board_id)
            )
            .prefetch_related('labels')
            .order_by('position', 'id')
            .distinct()
        )

        # 3) Chuẩn hóa dữ liệu cho FE
        from .serializers import CardSerializer, ListSerializer

        list_data = []
        for lst in lists:
            list_data.append({
                "id": lst.id,
                "name": lst.name,
                "position": lst.position,
                "cards": CardSerializer(lst.cards.all(), many=True, context={'request': request}).data
            })

        inbox_data = CardSerializer(inbox_cards, many=True, context={'request': request}).data

        return Response({
            "lists": list_data,
            "inbox": inbox_data
        })


class ActivityPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"

class UserActivityListView(generics.ListAPIView):
    serializer_class = UserActivitySerializer
    permission_classes = [IsAuthenticated]
    pagination_class = ActivityPagination

    def get_queryset(self):
        user = self.request.user
        qs = UserActivity.objects.filter(user=user)

        workspace = self.request.query_params.get("workspace")
        board = self.request.query_params.get("board")

        if workspace:
            qs = qs.filter(workspace_id=workspace)
        if board:
            qs = qs.filter(board_id=board)

        return qs.select_related("card", "board", "workspace", "user")