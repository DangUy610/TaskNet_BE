# backends/boards/serializers.py
from rest_framework import serializers
from .models import Board, List, Card, Label, BoardMembership,BoardInviteLink,Comment
from django.contrib.auth import get_user_model
import hashlib

User = get_user_model()

# ===================================================================
# Serializers chính cho các model
# ===================================================================




class BoardSerializer(serializers.ModelSerializer):

    
    class Meta:
        model = Board
        # Vẫn trả về 'workspace' ID khi ghi (create/update)
        # Nhưng khi đọc (get), nó sẽ sử dụng serializer lồng ở trên
        fields = ['id', 'name', 'created_by', 'background', 'visibility', 'is_closed']
        read_only_fields = ['created_by']



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
    name = serializers.SerializerMethodField()
    avatar = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'name', 'avatar']

    def get_name(self, obj):
        full = getattr(obj, "get_full_name", lambda: "")() or ""
        return full.strip() or obj.username
    
    def get_avatar(self, obj):
        # Nếu có field avatar trên model:
        if hasattr(obj, "avatar") and obj.avatar:
            try:
                return obj.avatar.url  # ImageField/FileField
            except Exception:
                return str(obj.avatar)
        # Fallback Gravatar theo email (tuỳ chọn)
        if obj.email:
            h = hashlib.md5(obj.email.lower().encode()).hexdigest()
            return f"https://www.gravatar.com/avatar/{h}?d=identicon"
        return None
    
    
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



class UserPublicSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'name']  

    def get_name(self, obj):
        full = (getattr(obj, "get_full_name", lambda: "")() or "").strip()
        return full or obj.username

class CommentSerializer(serializers.ModelSerializer):
    author = UserPublicSerializer(read_only=True)

    class Meta:
        model = Comment
        fields = ['id', 'card', 'author', 'content', 'created_at', 'updated_at']
        read_only_fields = ['author', 'created_at', 'updated_at']