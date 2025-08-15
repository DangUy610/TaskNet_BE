
from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate

User = get_user_model()

# ----------------- 1. Serializer để HIỂN THỊ thông tin User -----------------
# Dùng cho MeView hoặc khi trả về thông tin user ở các API khác.
class UserSerializer(serializers.ModelSerializer):
    """
    Serializer để hiển thị thông tin người dùng một cách an toàn.
    """
    # SerializerMethodField cho phép ta định nghĩa logic tùy chỉnh để lấy giá trị.
    avatar = serializers.SerializerMethodField(read_only=True)
    role = serializers.SerializerMethodField(read_only=True)

    # ✅ THÊM MỘT TRƯỜNG MỚI ĐỂ LÀM TÊN HIỂN THỊ
    display_name = serializers.SerializerMethodField(read_only=True)
    class Meta:
        model = User
        # Các trường sẽ được trả về trong API response.
        fields = ('id', 'username', 'email', 'avatar', 'role','display_name')

    def get_avatar(self, user):
        """
        Lấy URL đầy đủ của avatar.
        Cần có 'request' trong context để xây dựng URL tuyệt đối.
        """
        request = self.context.get('request')
        profile = getattr(user, 'profile', None)
        if profile and profile.avatar and request:
            return request.build_absolute_uri(profile.avatar.url)
        return None

    def get_role(self, user):
        """
        Xác định vai trò của người dùng.
        """
        return "admin" if user.is_superuser else "user"
    
    def get_display_name(self, user):
        """
        Trả về phần tên người dùng từ email.
        Ví dụ: 'john.doe@example.com' -> 'john.doe'
        Hoặc nếu có first_name, last_name thì trả về chúng.
        """
        # Nếu bạn có trường first_name và last_name, ưu tiên chúng
        if user.first_name:
            return user.first_name
            
        # Nếu không, trích xuất từ email
        return user.email.split('@')[0]


# ----------------- 2. Serializer cho chức năng ĐĂNG KÝ -----------------
class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer để xử lý việc đăng ký của người dùng mới.
    Validate dữ liệu và tạo user.
    """
    password = serializers.CharField(
        write_only=True,  # Chỉ dùng để ghi, không hiển thị trong response
        required=True,
        min_length=8,
        error_messages={
            "min_length": "Mật khẩu phải có ít nhất 8 ký tự."
        }
    )

    class Meta:
        model = User
        fields = ('email', 'password')

    def validate_email(self, value):
        """
        Kiểm tra xem email đã tồn tại hay chưa.
        """
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email này đã được đăng ký.")
        return value

    def create(self, validated_data):
        """
        Tạo user mới với mật khẩu đã được hash.
        """
        user = User.objects.create_user(
            username=validated_data['email'], # Dùng email làm username mặc định
            email=validated_data['email'],
            password=validated_data['password']
        )
        # Signal 'post_save' sẽ tự động tạo Profile và Workspace cho user này.
        return user


# ----------------- 3. Serializer cho chức năng ĐĂNG NHẬP -----------------
class LoginSerializer(serializers.Serializer):
    """
    Serializer để xử lý việc đăng nhập.
    Không kế thừa từ ModelSerializer vì nó không tạo hay cập nhật model.
    """
    email = serializers.CharField(label="Email/Username", write_only=True)
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email_or_username = data.get('email')
        password = data.get('password')

        if not email_or_username or not password:
            raise serializers.ValidationError(
                "Phải cung cấp cả email/username và mật khẩu.",
                code='authorization'
            )

        # Thử tìm user bằng email trước
        try:
            user_obj = User.objects.get(email=email_or_username)
            username = user_obj.username
        except User.DoesNotExist:
            # Nếu không thấy, coi như người dùng đã nhập username
            username = email_or_username

        user = authenticate(username=username, password=password)

        if not user:
            raise serializers.ValidationError(
                "Email hoặc mật khẩu không đúng.",
                code='authorization'
            )

        # Nếu xác thực thành công, trả về đối tượng user
        data['user'] = user
        return data


# ----------------- 4. Serializer cho chức năng ĐĂNG NHẬP GOOGLE -----------------
class GoogleLoginSerializer(serializers.Serializer):
    """
    Serializer để validate token từ Google.
    """
    token = serializers.CharField(write_only=True, required=True)

# ----------------- 5. Serializer cho chức năng INVITE -----------------


