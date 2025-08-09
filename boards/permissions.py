# backends/boards/permissions.py
from rest_framework.exceptions import PermissionDenied
from django.db.models import Q
from .models import Board, BoardMembership

def get_user_role_on_board(board, user):
    """
    Trả về vai trò của người dùng trên board: 'owner', 'admin', 'editor', 'viewer', hoặc None.
    """
    if not user.is_authenticated:
        return None
    if board.created_by == user:
        return 'owner'
    try:
        membership = BoardMembership.objects.get(board=board, user=user)
        return membership.role
    except BoardMembership.DoesNotExist:
        return None

def check_board_view_permission(board, user):
    """
    KIỂM TRA QUYỀN XEM (Viewer/Observer trở lên).
    User có thể xem nếu họ là thành viên (bất kể vai trò) hoặc người tạo.
    """
    role = get_user_role_on_board(board, user)
    if role in ['owner', 'admin', 'editor', 'viewer']:
        return
    raise PermissionDenied("You do not have permission to view this board.")

def check_card_edit_permission(card, user):
    """
    KIỂM TRA QUYỀN SỬA CARD (Editor/Member trở lên).
    User có thể sửa card (kéo thả, đổi tên, etc.) nếu họ là owner, admin, hoặc editor.
    """
    # Xử lý cho card trong Inbox
    if not card.list:
        card_creator = card.created_by
        if card_creator == user:
            return
        # Kiểm tra xem người dùng hiện tại và người tạo card có chung ít nhất một board không
        user_boards = set(Board.objects.filter(Q(created_by=user) | Q(members=user)).values_list('id', flat=True))
        creator_boards = set(Board.objects.filter(Q(created_by=card_creator) | Q(members=card_creator)).values_list('id', flat=True))
        if user_boards.intersection(creator_boards):
            return
        raise PermissionDenied("You don't have permission to modify this inbox card.")
    
    # Xử lý cho card nằm trong một list
    role = get_user_role_on_board(card.list.board, user)
    if role in ['owner', 'admin', 'editor']:
        return
    raise PermissionDenied("You must be an editor, admin, or owner to modify cards on this board.")

def check_board_edit_permission(board, user):
    """
    KIỂM TRA QUYỀN SỬA BOARD (Editor/Member trở lên).
    User có thể sửa các thành phần của board (tạo list/card) nếu là owner, admin, hoặc editor.
    """
    role = get_user_role_on_board(board, user)
    if role in ['owner', 'admin', 'editor']:
        return
    raise PermissionDenied("You must be an editor, admin, or owner to modify this board.")


def check_board_admin_permission(board, user):
    """
    KIỂM TRA QUYỀN QUẢN TRỊ BOARD (Admin trở lên).
    Dùng cho các hành động nguy hiểm: mời thành viên, xóa cột, đóng board...
    User có quyền nếu họ là owner hoặc admin.
    """
    role = get_user_role_on_board(board, user)
    if role in ['owner', 'admin']:
        return
    raise PermissionDenied("You must be an admin or the board creator to perform this action.")