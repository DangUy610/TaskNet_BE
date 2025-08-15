from django.contrib.auth import authenticate, login, logout, get_user_model
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
import requests
from django.core.files.base import ContentFile
import traceback
from django.db.models import Q

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    UserSerializer,
    GoogleLoginSerializer,
)

User = get_user_model()

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True) # Tự động trả về lỗi 400 nếu dữ liệu không hợp lệ
        user = serializer.save() 

        tokens = get_tokens_for_user(user)
        return Response({
            "ok": True,
            "user": UserSerializer(user).data, # Dùng UserSerializer để hiển thị thông tin
            "token": tokens["access"],
            "refresh": tokens["refresh"]
        }, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user'] # Lấy user đã được xác thực từ serializer

        login(request, user) # Cần cho Django Admin và các tính năng session-based khác
        tokens = get_tokens_for_user(user)


        return Response({
            "ok": True,
            "user": UserSerializer(user).data, 
            "token": tokens["access"],
            "refresh": tokens["refresh"]
        })

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication] # Thêm dòng này để chắc chắn nó xác thực bằng JWT

    def post(self, request):
        logout(request)
        return Response({"ok": True, "message": "Logged out successfully."})

class MeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Chỉ cần truyền user và context có request vào UserSerializer
        serializer = UserSerializer(request.user, context={'request': request})
        return Response(serializer.data)

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        input_serializer = GoogleLoginSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        token = input_serializer.validated_data['token']

        try:
            # 1. Xác minh với Google
            verify_url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token}"
            google_res = requests.get(verify_url)
            google_res.raise_for_status() # Tự động báo lỗi nếu status code không phải 2xx

            data = google_res.json()
            email = data.get('email')

            # (1) Kiểm tra email ngay từ đầu
            if not email:
                return Response({'error': 'No email in token'}, status=status.HTTP_400_BAD_REQUEST)

            # (2) Lấy hoặc tạo user DỰA TRÊN EMAIL và xóa bỏ logic thừa
            try:
                user = User.objects.get(email=email)
                created = False # User đã tồn tại
            except User.DoesNotExist:
                # Dùng email làm username mặc định
                user = User.objects.create_user(username=email, email=email)
                created = True # User vừa được tạo

            # Signal 'post_save' sẽ tự động tạo Profile và Workspace nếu user được tạo mới
            profile = user.profile

            login(request, user)
            tokens = get_tokens_for_user(user)

            # (3) Xử lý avatar một cách thông minh hơn
            # Chỉ tải avatar nếu là user mới hoặc user chưa có avatar
            picture = data.get('picture')
            if picture and (created or not profile.avatar):
                try:
                    resp_img = requests.get(picture, timeout=5)
                    resp_img.raise_for_status()
                    fname = f'user_{user.id}.jpg'
                    profile.avatar.save(fname, ContentFile(resp_img.content), save=True)
                except Exception as e:
                    print(f"Failed to fetch Google avatar for {email}: {e}")

            user_data = UserSerializer(user, context={'request': request}).data
            
            # (4) Trả về response gọn gàng
            return Response({
                'ok': True,
                'user': user_data,
                'token': tokens['access'],
                'refresh': tokens['refresh'],
            })

        except requests.exceptions.HTTPError as e:
            print('[GoogleLogin] HTTP Error:', str(e))
            return Response({'error': 'Invalid or expired Google token.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print('[GoogleLogin] General Exception:', str(e))
            traceback.print_exc()
            return Response({'error': 'An internal server error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserSearchView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '')
        if len(query) < 2: # Chỉ tìm kiếm khi có ít nhất 2 ký tự
            return Response([], status=status.HTTP_200_OK)

        users = User.objects.filter(
            Q(username__icontains=query) | Q(email__icontains=query)
        )[:10] # Giới hạn kết quả trả về

        # Dùng lại UserSerializer nhưng không cần context
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)        
    

