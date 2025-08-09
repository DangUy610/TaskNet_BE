# boards/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.contrib.auth import get_user_model
from django.db.models import Q

from .models import Board, Workspace, List, Card, Label, BoardMembership, BoardInviteLink
from .serializers import (
    BoardSerializer, WorkspaceSerializer, ListSerializer, CardSerializer, LabelSerializer,
    UserShortSerializer, BoardMembershipSerializer, BoardInviteLinkSerializer
)
from .decorators import require_board_admin, require_board_editor, require_card_editor, require_board_viewer
from .permissions import check_board_admin_permission # Import hàm permission mới

User = get_user_model()


# ===================================================================
# Views cho Workspace và Board chính
# ===================================================================

class WorkspaceListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        workspaces = Workspace.objects.filter(Q(owner=request.user) | Q(board__members=request.user)).distinct()
        serializer = WorkspaceSerializer(workspaces, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = WorkspaceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(owner=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class BoardListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, workspace_id):
        boards = Board.objects.filter(
            workspace_id=workspace_id, is_closed=False
        ).filter(
            Q(created_by=request.user) | Q(members=request.user)
        ).distinct()
        serializer = BoardSerializer(boards, many=True, context={'request': request})
        return Response(serializer.data)

    def post(self, request, workspace_id):
        try:
            workspace = Workspace.objects.get(id=workspace_id, owner=request.user)
        except Workspace.DoesNotExist:
            return Response({'error': 'You do not have permission to create a board in this workspace.'}, status=status.HTTP_403_FORBIDDEN)

        serializer = BoardSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        board = serializer.save(workspace=workspace, created_by=request.user)
        
        DEFAULT_LABEL_COLORS = ['#61bd4f', '#f2d600', '#ff9f1a', '#eb5a46', '#c377e0', '#0079bf']
        for color in DEFAULT_LABEL_COLORS:
            Label.objects.create(name='', color=color, board=board)

        return Response(BoardSerializer(board, context={'request': request}).data, status=status.HTTP_201_CREATED)

class BoardDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_viewer(lambda s, r, **k: Board.objects.get(id=k['board_id']))
    def get(self, request, workspace_id, board_id):
        board = Board.objects.get(id=board_id, workspace_id=workspace_id)
        serializer = BoardSerializer(board, context={'request': request})
        return Response(serializer.data)

    @require_board_admin(lambda s, r, **k: Board.objects.get(id=k['board_id']))
    def patch(self, request, workspace_id, board_id):
        board = Board.objects.get(id=board_id, workspace_id=workspace_id)
        if 'is_closed' in request.data:
            board.is_closed = request.data['is_closed']
            board.save(update_fields=['is_closed'])
        serializer = BoardSerializer(board, context={'request': request})
        return Response(serializer.data)
        
    def delete(self, request, workspace_id, board_id):
        board = Board.objects.get(id=board_id, workspace_id=workspace_id)
        if board.created_by != request.user:
            return Response({'error': 'Only the board creator can permanently delete the board.'}, status=status.HTTP_403_FORBIDDEN)
        board.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ClosedBoardsListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user_boards = Board.objects.filter(
            Q(created_by=request.user) | Q(members=request.user),
            is_closed=True
        ).distinct().prefetch_related('workspace')
        serializer = BoardSerializer(user_boards, many=True, context={'request': request})
        return Response(serializer.data)
    
# ===================================================================
# Views cho List và Card
# ===================================================================

class ListsCreateView(APIView):
    permission_classes = [IsAuthenticated]
    @require_board_viewer(lambda s, r, **k: Board.objects.get(id=k['board_id']))
    def get(self, request, board_id):
        lists = List.objects.filter(board_id=board_id).order_by('position')
        serializer = ListSerializer(lists, many=True)
        return Response(serializer.data)

    @require_board_editor(lambda s, r, **k: Board.objects.get(id=k['board_id']))
    def post(self, request, board_id):
        serializer = ListSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(board_id=board_id)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class ListDetailView(APIView):
    permission_classes = [IsAuthenticated]
    @require_board_editor(lambda s, r, **k: List.objects.get(id=k['list_id']).board)
    def patch(self, request, list_id):
        list_obj = List.objects.get(id=list_id)
        serializer = ListSerializer(list_obj, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    @require_board_admin(lambda s, r, **k: List.objects.get(id=k['list_id']).board)
    def delete(self, request, list_id):
        list_obj = List.objects.get(id=list_id)
        Card.objects.filter(list=list_obj).update(list=None)
        list_obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class CardListCreateView(APIView):
    permission_classes = [IsAuthenticated]
    @require_board_viewer(lambda s, r, **k: List.objects.get(id=k['list_id']).board)
    def get(self, request, list_id):
        cards = Card.objects.filter(list_id=list_id).order_by('position')
        serializer = CardSerializer(cards, many=True)
        return Response(serializer.data)

    @require_board_editor(lambda s, r, **k: List.objects.get(id=k['list_id']).board)
    def post(self, request, list_id):
        serializer = CardSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(list_id=list_id, created_by=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class CardDetailView(APIView):
    permission_classes = [IsAuthenticated]
    @require_card_editor(lambda s, r, **k: Card.objects.get(id=k['card_id']))
    def patch(self, request, card_id):
        card = Card.objects.get(id=card_id)
        serializer = CardSerializer(card, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    @require_card_editor(lambda s, r, **k: Card.objects.get(id=k['card_id']))
    def delete(self, request, card_id):
        card = Card.objects.get(id=card_id)
        card.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class InboxCardCreateView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user_accessible_boards = Board.objects.filter(Q(created_by=request.user) | Q(members=request.user)).distinct()
        all_related_user_ids = set()
        for board in user_accessible_boards:
            if board.created_by: all_related_user_ids.add(board.created_by.id)
            all_related_user_ids.update(board.members.values_list('id', flat=True))
        inbox_cards = Card.objects.filter(list__isnull=True, created_by_id__in=all_related_user_ids).order_by('-created_at')
        serializer = CardSerializer(inbox_cards, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        serializer = CardSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(created_by=request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CardBatchUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_admin(lambda self, request: Board.objects.get(id=request.data[0]['board_id']))
    def patch(self, request):
        updates = request.data
        if not isinstance(updates, list):
            return Response({"error": "Request body must be a list of updates"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            board_id = None
            for update in updates:
                card_id = update.get("id")
                card = Card.objects.get(id=card_id, created_by=request.user)
                serializer = CardSerializer(card, data=update, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    if not board_id:
                        board_id = card.list.board_id if card.list else card.created_by.board_set.first().id
                else:
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            # Gửi thông báo WebSocket
            #channel_layer = get_channel_layer()
            #async_to_sync(channel_layer.group_send)(
            #    f'board_{board_id}',
            #    {'type': 'card_update'}
            #)
            return Response({"message": "Cards updated successfully"}, status=status.HTTP_200_OK)
        except Card.DoesNotExist:
            return Response({"error": "One or more cards not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# ===================================================================
# View cho Members, Labels, và Share Link 
# ===================================================================

class BoardMembersView(APIView):
    permission_classes = [IsAuthenticated]
    @require_board_viewer(lambda s, r, **k: Board.objects.get(id=k['board_id']))
    def get(self, request, board_id):
        memberships = BoardMembership.objects.filter(board_id=board_id).select_related('user')
        serializer = BoardMembershipSerializer(memberships, many=True)
        return Response(serializer.data)

    @require_board_admin(lambda s, r, **k: Board.objects.get(id=k['board_id']))
    def post(self, request, board_id):
        board = Board.objects.get(id=board_id)
        user_id_to_invite = request.data.get('user_id')
        role = request.data.get('role', 'viewer')
        if not user_id_to_invite: return Response({'error': 'user_id is required'}, status=400)
        if role not in ['admin', 'editor', 'viewer']: return Response({'error': 'Invalid role'}, status=400)
        try:
            user_to_invite = User.objects.get(id=user_id_to_invite)
        except User.DoesNotExist:
            return Response({'error': 'User to invite not found'}, status=404)
        if BoardMembership.objects.filter(board=board, user=user_to_invite).exists() or board.created_by == user_to_invite:
            return Response({'message': 'User is already a member.'}, status=400)
        membership = BoardMembership.objects.create(board=board, user=user_to_invite, role=role)
        print(f"[INVITE] Invited {user_to_invite.email} as {role}")
        serializer = BoardMembershipSerializer(membership)
        return Response(serializer.data, status=201)

    @require_board_admin(lambda s, r, **k: Board.objects.get(id=k['board_id']))
    def patch(self, request, board_id):
        board = Board.objects.get(id=board_id)
        user_id_to_update = request.data.get('user_id')
        new_role = request.data.get('role')
        if not user_id_to_update or not new_role: return Response({'error': 'user_id and role are required'}, status=400)
        if new_role not in ['admin', 'editor', 'viewer']: return Response({'error': 'Invalid role'}, status=400)
        try:
            membership = BoardMembership.objects.get(board_id=board_id, user_id=user_id_to_update)
            if membership.user == board.created_by: return Response({'error': 'Cannot change the role of the board owner.'}, status=400)
            membership.role = new_role
            membership.save()

            print(f"[ROLE CHANGE] {membership.user.email} → {new_role}")
            return Response(BoardMembershipSerializer(membership).data)
        except BoardMembership.DoesNotExist:
            return Response({'error': 'Membership not found'}, status=404)

    @require_board_admin(lambda s, r, **k: Board.objects.get(id=k['board_id']))
    def delete(self, request, board_id):
        board = Board.objects.get(id=board_id)
        user_id_to_remove = request.data.get('user_id')
        if not user_id_to_remove: return Response({'error': 'user_id is required'}, status=400)
        try:
            membership = BoardMembership.objects.get(board_id=board_id, user_id=user_id_to_remove)
            if membership.user == board.created_by: return Response({'error': 'Cannot remove the board creator.'}, status=400)
            membership.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except BoardMembership.DoesNotExist:
            return Response({'error': 'Membership not found'}, status=404)
        
class BoardLabelsView(APIView):
    @require_board_viewer(lambda self, request, board_id: Board.objects.get(id=board_id))
    def get(self, request, board_id):
        labels = Label.objects.filter(board_id=board_id)
        serializer = LabelSerializer(labels, many=True)
        return Response(serializer.data)

class LabelCreateView(APIView):
    permission_classes = [IsAuthenticated]
    @require_board_admin(lambda self, request, board_id: Board.objects.get(id=board_id))
    def post(self, request, board_id):
        try:
            board = Board.objects.get(id=board_id)
        except Board.DoesNotExist:
            return Response({"error": "Board not found"}, status=404)

        serializer = LabelSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(board=board)
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)
class LabelDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_admin(lambda self, request, label_id: Label.objects.get(id=label_id).board)
    def patch(self, request, label_id):
        try:
            label = Label.objects.get(id=label_id)
        except Label.DoesNotExist:
            return Response({"error": "Label not found"}, status=404)

        serializer = LabelSerializer(label, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    @require_board_admin(lambda self, request, label_id: Label.objects.get(id=label_id).board)
    def delete(self, request, label_id):
        try:
            label = Label.objects.get(id=label_id)
            label.delete()
            return Response(status=204)
        except Label.DoesNotExist:
            return Response({"error": "Label not found"}, status=404)


    permission_classes = [IsAuthenticated]

    @require_board_viewer
    def get(self, request, board_id):
        board = Board.objects.get(id=board_id)
        memberships = BoardMembership.objects.filter(board=board).select_related('user')
        serializer = BoardMembershipSerializer(memberships, many=True)
        return Response(serializer.data)
    
    # Mời thành viên mới cần quyền Admin
    @require_board_admin
    def post(self, request, board_id):
        board = Board.objects.get(id=board_id)
        user_id_to_invite = request.data.get('user_id')
        role = request.data.get('role', 'viewer') # Lấy role từ frontend, mặc định là viewer

        if not user_id_to_invite:
            return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        if role not in ['admin', 'editor', 'viewer']:
            return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user_to_invite = User.objects.get(id=user_id_to_invite)
        except User.DoesNotExist:
            return Response({'error': 'User to invite not found'}, status=status.HTTP_404_NOT_FOUND)

        if BoardMembership.objects.filter(board=board, user=user_to_invite).exists() or board.created_by == user_to_invite:
            return Response({'message': 'User is already a member.'}, status=status.HTTP_400_BAD_REQUEST)
        
        membership = BoardMembership.objects.create(board=board, user=user_to_invite, role=role)
        serializer = BoardMembershipSerializer(membership)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # Thay đổi vai trò cần quyền Admin
    @require_board_admin
    def patch(self, request, board_id):
        board = Board.objects.get(id=board_id)
        user_id_to_update = request.data.get('user_id')
        new_role = request.data.get('role')

        if not user_id_to_update or not new_role:
            return Response({'error': 'user_id and role are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if new_role not in ['admin', 'editor', 'viewer']:
            return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            membership = BoardMembership.objects.get(board_id=board_id, user_id=user_id_to_update)
            # Người tạo (owner) không thể bị thay đổi vai trò
            if membership.user == board.created_by:
                return Response({'error': 'Cannot change the role of the board owner.'}, status=status.HTTP_400_BAD_REQUEST)

            membership.role = new_role
            membership.save()
            serializer = BoardMembershipSerializer(membership)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except BoardMembership.DoesNotExist:
            return Response({'error': 'Membership not found'}, status=status.HTTP_404_NOT_FOUND)
        
    # Xóa thành viên cần quyền Admin
    @require_board_admin
    def delete(self, request, board_id):
        board = Board.objects.get(id=board_id)
        user_id_to_remove = request.data.get('user_id')
        
        if not user_id_to_remove:
            return Response({'error': 'user_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            membership = BoardMembership.objects.get(board_id=board_id, user_id=user_id_to_remove)
            
            if membership.user == board.created_by:
                return Response({'error': 'Cannot remove the board creator.'}, status=status.HTTP_400_BAD_REQUEST)
            
            membership.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except BoardMembership.DoesNotExist:
            return Response({'error': 'Membership not found'}, status=status.HTTP_404_NOT_FOUND)
class BoardShareLinkView(APIView):
    permission_classes = [IsAuthenticated]

    @require_board_admin(lambda self, request, board_id: Board.objects.get(id=board_id))
    def get(self, request, board_id):
        # lấy link đang hoạt động (nếu có)
        invite = BoardInviteLink.objects.filter(board_id=board_id, is_active=True).first()
        if not invite:
            return Response({'detail': 'No active invite link'}, status=404)
        serializer = BoardInviteLinkSerializer(invite)
        return Response(serializer.data)

    @require_board_admin(lambda self, request, board_id: Board.objects.get(id=board_id))
    def post(self, request, board_id):
        role = request.data.get('role', 'member')
        # tạo mới hoặc update role cho link hiện có
        invite, _ = BoardInviteLink.objects.update_or_create(
            board_id=board_id,
            defaults={'role': role, 'is_active': True, 'created_by': request.user}
        )
        serializer = BoardInviteLinkSerializer(invite)
        return Response(serializer.data)

    @require_board_admin(lambda self, request, board_id: Board.objects.get(id=board_id))
    def delete(self, request, board_id):
        BoardInviteLink.objects.filter(board_id=board_id, is_active=True).update(is_active=False)
        return Response(status=status.HTTP_204_NO_CONTENT)
class BoardJoinByLinkView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, token):
        try:
            invite = BoardInviteLink.objects.get(token=token, is_active=True)
        except BoardInviteLink.DoesNotExist:
            return Response({'detail': 'Invalid or expired link'}, status=404)

        board = invite.board
        user = request.user

        # Nếu đã là thành viên thì không cần thêm nữa
        if BoardMembership.objects.filter(board=board, user=user).exists():
            return Response({'detail': 'Already a member'}, status=400)

        # map role của link thành role trong BoardMembership
        membership_role = 'editor' if invite.role == 'member' else 'viewer'
        BoardMembership.objects.create(board=board, user=user, role=membership_role)
        return Response({'detail': 'Joined board successfully'})
