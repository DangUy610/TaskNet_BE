# backends/boards/decorators.py
from functools import wraps
from .permissions import (
    check_board_view_permission,
    check_card_edit_permission,
    check_board_edit_permission,
    check_board_admin_permission,
)

def require_board_viewer(board_getter):
    def decorator(view_method):
        @wraps(view_method)
        def wrapper(self, request, *args, **kwargs):
            board = board_getter(self, request, *args, **kwargs)
            check_board_view_permission(board, request.user)
            return view_method(self, request, *args, **kwargs)
        return wrapper
    return decorator

def require_card_editor(card_getter):
    def decorator(view_method):
        @wraps(view_method)
        def wrapper(self, request, *args, **kwargs):
            card = card_getter(self, request, *args, **kwargs)
            check_card_edit_permission(card, request.user)
            return view_method(self, request, *args, **kwargs)
        return wrapper
    return decorator

def require_board_editor(board_getter):
    def decorator(view_method):
        @wraps(view_method)
        def wrapper(self, request, *args, **kwargs):
            board = board_getter(self, request, *args, **kwargs)
            check_board_edit_permission(board, request.user)
            return view_method(self, request, *args, **kwargs)
        return wrapper
    return decorator

def require_board_admin(board_getter):
    def decorator(view_method):
        @wraps(view_method)
        def wrapper(self, request, *args, **kwargs):
            board = board_getter(self, request, *args, **kwargs)
            check_board_admin_permission(board, request.user)
            return view_method(self, request, *args, **kwargs)
        return wrapper
    return decorator