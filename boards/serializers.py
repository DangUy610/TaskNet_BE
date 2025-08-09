# backends/boards/serializers.py
from rest_framework import serializers
from .models import Board, Workspace, List, Card, Label, BoardMembership,BoardInviteLink
from django.contrib.auth import get_user_model

User = get_user_model()

# ===================================================================
# Serializers chính cho các model
# ===================================================================

# Serializer nhỏ này chỉ để lồng thông tin workspace vào các serializer khác
class WorkspaceShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Workspace
        fields = ['id', 'name']


# Serializer đầy đủ cho Workspace (dùng cho API lấy list workspace)
class WorkspaceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Workspace
        fields = ['id', 'name']


class BoardSerializer(serializers.ModelSerializer):
    # ✅ SỬA Ở ĐÂY: Lồng thông tin workspace vào BoardSerializer
    # Thay vì chỉ trả về ID, nó sẽ trả về một object { id, name }
    workspace = WorkspaceShortSerializer(read_only=True)
    
    class Meta:
        model = Board
        # Vẫn trả về 'workspace' ID khi ghi (create/update)
        # Nhưng khi đọc (get), nó sẽ sử dụng serializer lồng ở trên
        fields = ['id', 'name', 'workspace', 'created_by', 'background', 'visibility', 'is_closed']
        read_only_fields = ['created_by']
        # Để cho phép tạo board chỉ bằng cách gửi `workspace` ID
        extra_kwargs = {
            'workspace': {'write_only': True}
        }


class ListSerializer(serializers.ModelSerializer):
    class Meta:
        model = List
        fields = ['id', 'name', 'background', 'board', 'visibility', 'position']

class CardSerializer(serializers.ModelSerializer):
    class Meta:
        model = Card
        fields = [
            'id', 'name', 'status', 'background', 'visibility', 'list', 
            'description', 'due_date', 'completed', 'position', 
            'created_at','labels'
        ]
        read_only_fields = ['created_by']
        extra_kwargs = {
            'list': {'required': False, 'allow_null': True}
        }
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
        return super().create(validated_data)

class LabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Label
        fields = ['id', 'name', 'color']

# ===================================================================
# Serializers phụ
# ===================================================================

class UserShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class BoardMembershipSerializer(serializers.ModelSerializer):
    user = UserShortSerializer(read_only=True)

    class Meta:
        model = BoardMembership
        fields = ['id', 'user', 'role', 'joined_at']


class BoardInviteLinkSerializer(serializers.ModelSerializer):
    class Meta:
        model = BoardInviteLink
        fields = ['token', 'role', 'created_at', 'expires_at', 'is_active']
        read_only_fields = ['token', 'created_at']
