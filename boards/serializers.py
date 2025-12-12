# backends/boards/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.contrib.contenttypes.models import ContentType
from .models import (
    Board, Workspace, List, Card, Label,Notification,
    BoardMembership, BoardInviteLink, Comment, CardActivity, CardAssignee, CardWatcher,
    Checklist, ChecklistItem, Attachment,
    WorkspaceMembership, WorkspaceRole, BoardVisibility, BoardRole,BoardCreationPolicy,
    UserActivity,
    
)
from .permissions import can_view_board, can_edit_board
import hashlib

User = get_user_model()

# ========================
# Helpers (permission-lite)
# ========================
def _is_workspace_owner(user, workspace: Workspace) -> bool:
    return bool(user and user.is_authenticated and workspace.owner_id == user.id)

def _user_workspace_role(user, workspace: Workspace):
    return WorkspaceMembership.objects.filter(user=user, workspace=workspace).values_list("role", flat=True).first()

def _user_board_role(user, board: Board):
    return BoardMembership.objects.filter(user=user, board=board).values_list("role", flat=True).first()

def user_can_view_board(user, board: Board) -> bool:
    return can_view_board(user, board)

def user_can_edit_board(user, board: Board) -> bool:
    return can_edit_board(user, board)

def _nullish(v):
    return v is None or (isinstance(v, str) and v.strip().lower() in ("", "null", "none"))


# ===================================================================
# Serializers chính
# ===================================================================

class WorkspaceShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Workspace
        fields = ['id', 'name']


# serializers.py
class WorkspaceSerializer(serializers.ModelSerializer):
    board_creation_policy = serializers.ChoiceField(
        choices=BoardCreationPolicy.choices, 
        required=False
    )
    can_create_board = serializers.SerializerMethodField(read_only=True)
    effective_role = serializers.SerializerMethodField(read_only=True)
    is_owner = serializers.SerializerMethodField(read_only=True)
    
    # THÊM MỚI: owner_display cho frontend
    owner_display = serializers.SerializerMethodField(read_only=True)
    owner_id = serializers.IntegerField(source='owner.id', read_only=True)

    class Meta:
        model = Workspace
        fields = [
            'id', 
            'name', 
            'board_creation_policy', 
            'can_create_board', 
            'effective_role', 
            'is_owner',
            'owner_id',        # THÊM
            'owner_display',   # THÊM
        ]
        read_only_fields = [
            'can_create_board', 
            'effective_role', 
            'is_owner', 
            'owner_id',
            'owner_display',
        ]

    def get_owner_display(self, obj):
        """Trả về tên hiển thị của owner"""
        if not obj.owner:
            return None
        owner = obj.owner
        # Ưu tiên full_name, fallback về username, rồi email
        if hasattr(owner, 'get_full_name'):
            full_name = owner.get_full_name()
            if full_name and full_name.strip():
                return full_name.strip()
        if owner.username:
            return owner.username
        return owner.email

    def get_can_create_board(self, obj):
        request = self.context.get('request')
        user = getattr(request, 'user', None)
        return bool(user and user.is_authenticated and obj.can_create_board(user))

    def get_is_owner(self, obj):
        request = self.context.get('request')
        user = getattr(request, 'user', None)
        return bool(user and user.is_authenticated and obj.owner_id == user.id)

    def get_effective_role(self, obj):
        request = self.context.get('request')
        user = getattr(request, 'user', None)
        if not (user and user.is_authenticated):
            return None
        if obj.owner_id == user.id:
            return 'owner'
        role = WorkspaceMembership.objects.filter(
            workspace=obj, user=user
        ).values_list('role', flat=True).first()
        if role:
            return role
        if BoardMembership.objects.filter(board__workspace=obj, user=user).exists():
            return 'guest'
        return None

class WorkspaceTransferOwnershipSerializer(serializers.Serializer):
    new_owner_id = serializers.IntegerField(required=True)

    def validate_new_owner_id(self, value):
        # Kiểm tra user có tồn tại không
        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = get_object_or_404(User, pk=value)
        
        # Lấy workspace từ context (truyền từ View)
        workspace = self.context.get('workspace')
        if not workspace:
            raise serializers.ValidationError("Workspace context missing.")

        # Kiểm tra user mới có phải là thành viên của workspace không
        # Phải là thành viên mới được nhận quyền sở hữu
        is_member = WorkspaceMembership.objects.filter(
            workspace=workspace, 
            user=user
        ).exists()
        
        if not is_member:
            raise serializers.ValidationError("New owner must be a member of this workspace.")

        return value
    
    
class UserShortSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    avatar = serializers.SerializerMethodField()
    initials = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'name', 'avatar', 'initials']

    def get_name(self, obj):
        """
        Ưu tiên display_name từ Profile, fallback về username
        """
        # Try to get display_name from profile
        if hasattr(obj, 'profile'):
            try:
                display_name = obj.profile.get_display_name()
                # Chỉ dùng display_name nếu nó khác email username
                if display_name and display_name != obj.email.split('@')[0]:
                    return display_name
            except Exception:
                pass
        
        # Fallback to get_full_name() or username
        full = getattr(obj, "get_full_name")() or ""
        return full.strip() or obj.username

    def get_avatar(self, obj):
        """
        Ưu tiên avatar từ Profile, fallback về Gravatar
        """
        # Try to get avatar from profile
        if hasattr(obj, 'profile'):
            try:
                if obj.profile.avatar:
                    request = self.context.get('request')
                    if request:
                        return request.build_absolute_uri(obj.profile.avatar.url)
                    return obj.profile.avatar.url
            except Exception:
                pass
        
        # Fallback to Gravatar
        if obj.email:
            import hashlib
            h = hashlib.md5(obj.email.lower().encode()).hexdigest()
            return f"https://www.gravatar.com/avatar/{h}?d=identicon"
        return None
    
    def get_initials(self, obj):
        """
        Lấy initials từ Profile hoặc generate từ username
        """
        if hasattr(obj, 'profile'):
            try:
                return obj.profile.get_initials()
            except Exception:
                pass
        
        # Fallback: lấy 2 ký tự đầu của username
        name = obj.username or obj.email.split('@')[0] if obj.email else 'U'
        return name[:2].upper()
    
        
class WorkspaceMembershipSerializer(serializers.ModelSerializer):
    """
    Dùng để trả về danh sách member của workspace
    """
    user = UserShortSerializer(read_only=True)

    class Meta:
        model = WorkspaceMembership
        fields = ['id', 'user', 'role', 'joined_at']

class BoardSerializer(serializers.ModelSerializer):
    workspace = WorkspaceShortSerializer(read_only=True)
    workspace_id = serializers.PrimaryKeyRelatedField(
        source='workspace',
        queryset=Workspace.objects.all(),
        write_only=True,
        required=False
    )
    
    # NEW: Thông tin ownership
    created_by = UserShortSerializer(read_only=True)
    owned_by = UserShortSerializer(read_only=True)
    current_owner = serializers.SerializerMethodField()
    
    # Permission flags
    is_owner = serializers.SerializerMethodField()
    can_transfer_ownership = serializers.SerializerMethodField()

    class Meta:
        model = Board
        fields = [
            'id', 'name', 'workspace', 'workspace_id', 
            'created_by', 'owned_by', 'current_owner',
            'background', 'visibility', 'is_closed',
            'is_owner', 'can_transfer_ownership',
            'created_at'
        ]
        read_only_fields = ['created_by', 'owned_by', 'created_at']

    def get_current_owner(self, obj):
        """Lấy owner hiện tại (owned_by or created_by)"""
        owner = obj.get_owner()
        if owner:
            return UserShortSerializer(owner).data
        return None
    
    def get_is_owner(self, obj):
        """Check user hiện tại có phải owner không"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        owner = obj.get_owner()
        return owner and owner.id == request.user.id
    
    def get_can_transfer_ownership(self, obj):
        """Check user có quyền transfer ownership"""
        request = self.context.get('request')
        if not request or not request.user.is_authenticated:
            return False
        from .permissions import can_transfer_board_ownership
        return can_transfer_board_ownership(request.user, obj)

    def validate_visibility(self, value):
        valid = {c for c, _ in BoardVisibility.choices}
        if value not in valid:
            raise serializers.ValidationError(
                f"Invalid visibility. Must be one of: {sorted(valid)}"
            )
        return value

    def validate(self, attrs):
        """
        Check quyền tạo board theo workspace policy
        """
        request = self.context.get('request')
        ws = attrs.get('workspace') or self.context.get('workspace')
        
        if request and ws and not self.instance:  # Chỉ check khi CREATE
            from .permissions import can_create_board_in_workspace
            if not can_create_board_in_workspace(request.user, ws):
                policy = ws.board_creation_policy
                if policy == 'owner':
                    msg = 'Only workspace owner can create boards.'
                elif policy == 'admins':
                    msg = 'Only workspace owner and admins can create boards.'
                else:
                    msg = 'You must be a workspace member to create boards.'
                raise serializers.ValidationError({'workspace_id': msg})
        
        return attrs

    def create(self, validated_data):
        workspace = validated_data.get('workspace') or self.context.get('workspace')
        if not workspace:
            raise serializers.ValidationError({'workspace_id': 'This field is required.'})
        
        user = self.context['request'].user
        
        # Tạo board với created_by và owned_by
        board = Board.objects.create(
            created_by=user,
            owned_by=user,  # Owner ban đầu = creator
            workspace=workspace,
            **{k: v for k, v in validated_data.items() if k != 'workspace'}
        )
        return board

class BoardTransferOwnershipSerializer(serializers.Serializer):
    """Serializer cho transfer ownership"""
    new_owner_id = serializers.IntegerField(required=True)
    
    def validate_new_owner_id(self, value):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        if not User.objects.filter(id=value).exists():
            raise serializers.ValidationError("User not found.")
        
        # Check new owner có phải board member không (optional)
        board = self.context.get('board')
        if board:
            from .models import BoardMembership
            if not BoardMembership.objects.filter(board=board, user_id=value).exists():
                # Auto thêm vào board nếu chưa có - được handle ở model
                pass
        
        return value
    

class ListSerializer(serializers.ModelSerializer):
    class Meta:
        model = List
        fields = ['id', 'name', 'background', 'board', 'visibility', 'position']

class LabelSerializer(serializers.ModelSerializer):
    board_id = serializers.PrimaryKeyRelatedField(
        source='board',
        queryset=Board.objects.all(),
        write_only=True
    )
    board = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Label
        fields = ['id', 'name', 'color', 'board', 'board_id', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_name(self, value):
        """Validate và chuẩn hóa tên label"""
        if not value or not value.strip():
            raise serializers.ValidationError("Label name cannot be empty.")
        
        value = value.strip()
        if len(value) > 100:
            raise serializers.ValidationError("Label name too long (max 100 chars).")
        
        return value
    
    def validate_color(self, value):
        """Validate định dạng màu hex"""
        import re
        if not re.match(r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$', value):
            raise serializers.ValidationError(
                "Invalid color format. Use hex format: #RRGGBB"
            )
        return value.upper()
    
    def validate(self, attrs):
        """
        Kiểm tra trùng tên Label trong cùng một Board (Case-insensitive).
        Logic này hoạt động cho cả Create và Update.
        """
        # 1. Xác định Board (Lấy từ input nếu tạo mới, hoặc lấy từ DB nếu đang update)
        board = attrs.get('board')
        if not board and self.instance:
            board = self.instance.board
            
        # 2. Xác định Name (Lấy từ input nếu có sửa, hoặc lấy từ DB nếu giữ nguyên)
        name = attrs.get('name')
        if not name and self.instance:
            name = self.instance.name
        
        # Chuẩn hóa tên
        if name:
            name = name.strip()

        # 3. Kiểm tra trùng lặp
        if board and name:
            # Tìm xem có label nào khác trong board này có cùng tên không
            qs = Label.objects.filter(
                board=board,
                name__iexact=name
            )
            
            # Nếu đang Update, phải loại trừ chính label này ra khỏi kết quả tìm kiếm
            if self.instance:
                qs = qs.exclude(id=self.instance.id)
            
            if qs.exists():
                raise serializers.ValidationError({
                    'name': f'Label "{name}" already exists in this board.'
                })
        
        return attrs
class CardSerializer(serializers.ModelSerializer):
    """Serializer đầy đủ cho Card — hỗ trợ start_date, due_date, reminder, recurrence."""
    board_id = serializers.IntegerField(source='list.board_id', read_only=True)
    labels = LabelSerializer(many=True, read_only=True)

    # Dùng source='labels' để khi validate, field này sẽ trả về list các Label Object thay vì ID
    label_ids = serializers.PrimaryKeyRelatedField(
        queryset=Label.objects.all(),
        many=True,
        write_only=True,
        required=False,
        source='labels'
    )

    start_date = serializers.DateTimeField(required=False, allow_null=True)
    due_reminder_offset = serializers.IntegerField(required=False, allow_null=True)
    due_reminder_at = serializers.DateTimeField(read_only=True)
    recurrence = serializers.ChoiceField(
        choices=[
            ('never', 'Never'),
            ('daily', 'Daily'),
            ('weekly', 'Weekly'),
            ('monthly', 'Monthly'),
        ],
        required=False,
        default='never'
    )

    list = serializers.PrimaryKeyRelatedField(
        queryset=List.objects.all(),
        required=False,
        allow_null=True
    )

    class Meta:
        model = Card
        fields = [
            'id', 'name', 'status', 'background', 'visibility', 'list',
            'description', 'start_date', 'due_date', 'due_reminder_offset',
            'due_reminder_at', 'recurrence', 'completed', 'position',
            'created_at', 'labels', 'label_ids', 'board_id'  
        ]
        read_only_fields = ['id', 'created_by', 'created_at', 'due_reminder_at']

    def to_internal_value(self, data):
        """Chuẩn hoá dữ liệu null/empty string thành None"""
        data = data.copy()
        if 'list' in data and _nullish(data['list']):
            data['list'] = None
        if 'start_date' in data and _nullish(data['start_date']):
            data['start_date'] = None
        if 'due_date' in data and _nullish(data['due_date']):
            data['due_date'] = None
        if 'due_reminder_offset' in data and _nullish(data['due_reminder_offset']):
            data['due_reminder_offset'] = None
        return super().to_internal_value(data)

    def validate(self, attrs):
        request = self.context.get('request')
        
        # 1. Logic Check Permission Di Chuyển/Tạo Card (Giữ nguyên)
        target_list = attrs.get('list', getattr(self.instance, 'list', None))
        
        if request and target_list:
            board = target_list.board
            # Giả định user_can_edit_board đã được import
            if not user_can_edit_board(request.user, board):
                raise serializers.ValidationError("You do not have permission to edit cards on this board.")

        # 2. Logic Check Label Integrity (MỚI THÊM)
        # Đảm bảo Label được gắn phải thuộc về Board chứa Card này
        labels_to_assign = attrs.get('labels') # Đây là list các object Label
        
        if labels_to_assign is not None:
            current_board = None
            
            # Trường hợp A: Đang di chuyển card hoặc tạo mới vào một list
            if target_list:
                current_board = target_list.board
            # Trường hợp B: Đang update card cũ, không đổi list
            elif self.instance and self.instance.list:
                current_board = self.instance.list.board
            
            # Nếu xác định được Board, tiến hành kiểm tra
            if current_board:
                for label in labels_to_assign:
                    if label.board_id != current_board.id:
                        raise serializers.ValidationError({
                            'label_ids': f"Label '{label.name}' does not belong to Board '{current_board.name}'."
                        })

        # 3. Logic Validate Thời Gian (Giữ nguyên)
        start = attrs.get('start_date', getattr(self.instance, 'start_date', None))
        due = attrs.get('due_date', getattr(self.instance, 'due_date', None))
        if start and due and start > due:
            raise serializers.ValidationError({'start_date': 'Start date must be before due date.'})

        # 4. Auto gán created_by
        if not self.instance and request:
            attrs.setdefault('created_by', request.user)
            
        return attrs

    def create(self, validated_data):
        """Tạo card mới + tính due_reminder_at."""
        labels = validated_data.pop('labels', [])
        card = Card.objects.create(**validated_data)
        if labels:
            card.labels.set(labels)
        
        card.due_reminder_at = card.compute_due_reminder_at()
        card.save(update_fields=['due_reminder_at'])
        return card

    def update(self, instance, validated_data):
        """Cập nhật card + auto tính lại due_reminder_at."""
        # Labels sẽ được xử lý tự động bởi source='labels' trong validated_data nếu dùng super().update
        # Nhưng để chắc chắn M2M hoạt động tốt, ta để mặc định DRF xử lý
        card = super().update(instance, validated_data)
        
        # Tính lại nhắc nhở nếu cần
        card.due_reminder_at = card.compute_due_reminder_at()
        card.save(update_fields=['due_reminder_at'])
        return card



# ===================================================================
# Serializers phụ
# ===================================================================

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
        full = (getattr(obj, "get_full_name")() or "").strip()
        return full or obj.username


class CommentSerializer(serializers.ModelSerializer):
    author = UserShortSerializer(read_only=True)

    class Meta:
        model = Comment
        fields = ['id', 'card', 'author', 'content', 'created_at', 'updated_at']
        read_only_fields = ['author', 'created_at', 'updated_at']


class CardAssigneeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CardAssignee
        fields = ('id', 'card', 'user', 'assigned_by', 'assigned_at')
        read_only_fields = ('assigned_by', 'assigned_at')

    def create(self, validated_data):
        validated_data['assigned_by'] = self.context['request'].user
        return super().create(validated_data)


class CardAssigneeBulkSetSerializer(serializers.Serializer):
    user_ids = serializers.ListField(child=serializers.IntegerField(), allow_empty=True)

    def validate(self, data):
        card = self.context['card']
        board = card.list.board if card.list else None
        invalid = []
        from .models import BoardMembership
        for uid in data['user_ids']:
            if board and not BoardMembership.objects.filter(board=board, user_id=uid).exists():
                invalid.append(uid)
        if invalid:
            raise serializers.ValidationError({"user_ids": f"Không phải member của board: {invalid}"})
        return data

    def save(self, **kwargs):
        from models import CardAssignee
        card = self.context['card']
        actor = self.context['request'].user
        new_ids = set(self.validated_data['user_ids'])
        from .models import CardAssignee
        old_ids = set(CardAssignee.objects.filter(card=card).values_list('user_id', flat=True))

        to_add = new_ids - old_ids
        CardAssignee.objects.bulk_create(
            [CardAssignee(card=card, user_id=uid, assigned_by=actor) for uid in to_add],
            ignore_conflicts=True
        )
        # 🔔 notify cho từng assignee mới
        from django.contrib.auth import get_user_model
        from .services import notify_assignee_added
        U = get_user_model()
        for uid in to_add:
            u = U.objects.filter(id=uid).first()
            if u: notify_assignee_added(actor, card, u)

        to_remove = old_ids - new_ids
        if to_remove:
            CardAssignee.objects.filter(card=card, user_id__in=to_remove).delete()

        return card
    
class CardWatcherSerializer(serializers.ModelSerializer):
    class Meta:
        model = CardWatcher
        fields = ('id', 'card', 'user', 'enabled_by', 'enabled_at')
        read_only_fields = ('enabled_by', 'enabled_at')

    def create(self, validated_data):
        validated_data['enabled_by'] = self.context['request'].user
        return super().create(validated_data)


class CardWatcherBulkSetSerializer(serializers.Serializer):
    user_ids = serializers.ListField(child=serializers.IntegerField(), allow_empty=True)

    def validate(self, data):
        card = self.context['card']
        board = card.list.board if card.list else None
        invalid = []
        from .models import BoardMembership 
        for uid in data['user_ids']:
                if board and not BoardMembership.objects.filter(board=board, user_id=uid).exists():
                    invalid.append(uid)
        if invalid:
            raise serializers.ValidationError({"user_ids": f"Không phải member của board: {invalid}"})
        return data

    def save(self, **kwargs):
        from .models import CardWatcher
        card = self.context['card']
        actor = self.context['request'].user
        new_ids = set(self.validated_data['user_ids'])
        old_ids = set(CardWatcher.objects.filter(card=card).values_list('user_id', flat=True))

        to_add = new_ids - old_ids
        CardWatcher.objects.bulk_create(
            [CardWatcher(card=card, user_id=uid, enabled_by=actor) for uid in to_add],
            ignore_conflicts=True
        )
        # 🔔 notify watchers mới
        from django.contrib.auth import get_user_model
        from .services import notify_watcher_added
        U = get_user_model()
        for uid in to_add:
            u = U.objects.filter(id=uid).first()
            if u: notify_watcher_added(actor, card, u)

        to_remove = old_ids - new_ids
        if to_remove:
            CardWatcher.objects.filter(card=card, user_id__in=to_remove).delete()

        return card

class CardActivitySerializer(serializers.ModelSerializer):
    user = UserShortSerializer(read_only=True)
    target_user = UserShortSerializer(read_only=True)

    class Meta:
        model = CardActivity
        fields = ['id', 'user', 'activity_type', 'description', 'target_user', 'created_at']


class EnhancedCardSerializer(serializers.ModelSerializer):
    """Card mở rộng: member roles, watchers, activities, labels, creator"""
    watchers = UserShortSerializer(many=True, read_only=True)
    activities = CardActivitySerializer(many=True, read_only=True)
    labels = LabelSerializer(many=True, read_only=True)
    created_by = UserShortSerializer(read_only=True)

    class Meta:
        model = Card
        fields = [
            'id', 'name', 'status', 'background', 'visibility', 'list',
            'description', 'due_date', 'completed', 'position',
            'created_at', 'created_by', 'labels',
            'watchers', 'activities'
        ]


class ChecklistItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChecklistItem
        fields = [
            'id',
            'checklist',
            'text',
            'completed',
            'position',
            'due_date',
            'assigned_to',
            'created_at',
            'updated_at',
            'completed_at',
            'completed_by',
        ]
        read_only_fields = ['id', 'checklist', 'created_at', 'updated_at', 'completed_at', 'completed_by']


class ChecklistSerializer(serializers.ModelSerializer):
    items = ChecklistItemSerializer(many=True, read_only=True)
    completion_percentage = serializers.ReadOnlyField()

    class Meta:
        model = Checklist
        fields = [
            'id',
            'card',
            'title',
            'position',
            'created_at',
            'updated_at',
            'created_by',
            'items',
            'completion_percentage',
        ]
        read_only_fields = ['id', 'card', 'created_at', 'updated_at', 'created_by', 'completion_percentage']


class AttachmentSerializer(serializers.ModelSerializer):
    uploaded_by = UserShortSerializer(read_only=True)
    file_size_human = serializers.ReadOnlyField()
    is_image = serializers.ReadOnlyField()
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = Attachment
        fields = [
            'id', 'name', 'attachment_type', 'file', 'file_url', 'file_size',
            'file_size_human', 'mime_type', 'url', 'uploaded_by',
            'created_at', 'is_cover', 'is_image'
        ]
        read_only_fields = ['uploaded_by', 'created_at', 'file_size', 'mime_type']

    def get_file_url(self, obj):
        request = self.context.get('request')
        if obj.attachment_type == 'file' and obj.file:
            return request.build_absolute_uri(obj.file.url) if request else obj.file.url
        if obj.attachment_type == 'link' and obj.url:
            return obj.url
        return None

    def validate(self, attrs):
        a_type = attrs.get('attachment_type') or getattr(self.instance, 'attachment_type', None)
        file_obj = attrs.get('file')
        link_url = attrs.get('url')

        if a_type == 'file':
            if not file_obj and not (self.instance and self.instance.file):
                raise serializers.ValidationError("File attachment requires a file.")
            if link_url:
                raise serializers.ValidationError("File attachment should not include a URL.")
        elif a_type == 'link':
            if not link_url and not (self.instance and self.instance.url):
                raise serializers.ValidationError("Link attachment requires a URL.")
            if file_obj:
                raise serializers.ValidationError("Link attachment should not include a file.")
        else:
            raise serializers.ValidationError("Invalid attachment_type. Use 'file' or 'link'.")

        return attrs

    def create(self, validated_data):
        file_obj = validated_data.get('file')
        if file_obj:
            validated_data['file_size'] = getattr(file_obj, 'size', None)
            validated_data['mime_type'] = getattr(file_obj, 'content_type', '') or ''
            validated_data.setdefault('name', getattr(file_obj, 'name', 'Attachment'))
        else:
            if not validated_data.get('name'):
                from urllib.parse import urlparse
                parsed = urlparse(validated_data.get('url', ''))
                default_name = (parsed.netloc + parsed.path).strip('/') or 'Link'
                validated_data['name'] = default_name
        return super().create(validated_data)
    
#========Notification Serializer==========
class GenericTargetField(serializers.Field):
    """
    Trả về thông tin cơ bản của target (model, pk, str)
    để FE có thể điều hướng (deep-link).
    """
    def to_representation(self, obj):
        if obj is None:
            return None
        return {
            "model": obj._meta.label_lower,  # ví dụ "boards.board"
            "id": str(obj.pk),
            "string": str(obj),
        }

class NotificationSerializer(serializers.ModelSerializer):
    actor_name  = serializers.SerializerMethodField()
    target      = GenericTargetField(read_only=True)  # bạn đã có
    action_url  = serializers.SerializerMethodField()
    priority    = serializers.SerializerMethodField()
    
    title       = serializers.SerializerMethodField()
    message     = serializers.SerializerMethodField()
    cover_url   = serializers.SerializerMethodField()
    is_mention  = serializers.SerializerMethodField()
    type        = serializers.SerializerMethodField()
    class Meta:
        model = Notification
        fields = [
            "id",
            "type",
            "priority",
            "verb",
            "actor",
            "actor_name",
            "recipient",
            "target",
            "is_read",
            "read_at",
            "action_url",
            "data",
            "created_at",
            "title", 
            "message", 
            "cover_url", 
            "is_mention",
        ]
        read_only_fields = [
            "id", "recipient", "actor", "actor_name", "target",
            "is_read", "read_at", "created_at",
        ]

    def get_actor_name(self, obj):
        if obj.actor:
            return getattr(obj.actor, "get_full_name")() or obj.actor.username
        return None

    def get_type(self, obj):
        """
        Ưu tiên 'data.type' nếu có; fallback từ verb thành snake_case.
        VD: "Assigned to you" -> "card_assigned"
        """
        t = (obj.data or {}).get("type")
        if t: return t
        import re
        slug = re.sub(r'[^a-z0-9]+', '_', (obj.verb or '').strip().lower()).strip('_')
        return slug or "notification"

    def get_title(self, obj):
        # FE sẽ ưu tiên title này trước khi fallback
        return obj.verb or "Notification"

    def get_message(self, obj):
        d = obj.data or {}
        return d.get("message") or d.get("preview") or ""

    def get_cover_url(self, obj):
        d = obj.data or {}
        return d.get("cover_url")

    def get_is_mention(self, obj):
        d = (obj.data or {})
        t = (obj.type or "").lower() if hasattr(obj, "type") else ""
        return bool(d.get("is_mention") or ("mention" in t))
    
    def get_action_url(self, obj):
        # Nếu data có sẵn action_url thì trả luôn
        url = (obj.data or {}).get("action_url")
        if url: return url
        # Thử xây từ target (card/board/comment)
        try:
            model = obj.target_ct.model if obj.target_ct else None
            tid = obj.target_id
            if model == "card" and tid:
                # yêu cầu FE deep-link dạng /cards/<id>/ (tuỳ app)
                return f"/cards/{tid}"
            if model == "board" and tid:
                return f"/boards/{tid}"
        except Exception:
            pass
        return None

    def get_priority(self, obj):
        """
        Map tạm thời từ level -> priority theo nghiệp vụ:
          error|warning -> high
          success -> medium
          info -> low
        """
        lvl = (obj.level or "info").lower()
        if lvl in ("error","warning"): return "high"
        if lvl in ("success",): return "medium"
        return "low"

class NotificationMarkReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["is_read"]
        extra_kwargs = {
            "is_read": {"required": True}
        }

    def update(self, instance, validated_data):
        if validated_data.get("is_read") is True:
            instance.mark_read(commit=True)
        else:
            # Cho phép “đánh dấu chưa đọc” nếu muốn
            instance.is_read = False
            instance.read_at = None
            instance.save(update_fields=["is_read", "read_at", "updated_at"])
        return instance
class NotificationCreateSerializer(serializers.ModelSerializer):
    # Cho phép client gửi tên model thay vì content type id
    target_type = serializers.CharField(required=False, write_only=True)

    class Meta:
        model = Notification
        fields = ["recipient", "verb", "target_type", "target_id", "level", "data"]

    def create(self, validated_data):
        target_type_str = validated_data.pop("target_type", None)

        # Nếu có target_type và target_id, convert sang ContentType
        if target_type_str and validated_data.get("target_id"):
            try:
                ct = ContentType.objects.get(model=target_type_str.lower())
                validated_data["target_ct"] = ct
            except ContentType.DoesNotExist:
                # Log nhẹ nếu model name sai
                import logging
                logging.warning(f"Invalid target_type '{target_type_str}' trong NotificationCreateSerializer.")
                # Không raise để tránh crash API

        return Notification.objects.create(**validated_data)
    

class UserActivitySerializer(serializers.ModelSerializer):
    user = UserShortSerializer(read_only=True)
    card = CardSerializer(read_only=True)
    board = BoardSerializer(read_only=True)
    workspace = WorkspaceShortSerializer(read_only=True)

    class Meta:
        model = UserActivity
        fields = [
            "id", "user", "verb", "description",
            "card", "board", "workspace", "created_at"
        ]
