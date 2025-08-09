from django.contrib.auth import authenticate, login, logout, get_user_model
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
import requests
from boards.models import Workspace
from django.core.files.base import ContentFile
import traceback
from django.db.models import Q
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as grequests

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

        # Logic kiểm tra workspace cho user cũ có thể vẫn giữ lại nếu cần
        if not Workspace.objects.filter(owner=user).exists():
            Workspace.objects.create(name="Hard Spirit", owner=user)

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
        ser = GoogleLoginSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        token = ser.validated_data['token']

        try:
            idinfo = google_id_token.verify_oauth2_token(token, grequests.Request())
            email = idinfo.get('email')
            name = idinfo.get('name') or ''
            picture = idinfo.get('picture')

            if not email:
                return Response({'error': 'No email in token'}, status=400)

            user, created = User.objects.get_or_create(
                email=email,
                defaults={'username': email, 'first_name': name}
            )

            # login(request, user)  # chỉ cần nếu dùng session/cookie

            # avatar: chỉ tải khi mới tạo hoặc chưa có
            profile = user.profile  # theo code hiện có
            if picture and (created or not profile.avatar):
                try:
                    img = requests.get(picture, timeout=5)
                    img.raise_for_status()
                    profile.avatar.save(f'user_{user.id}.jpg', ContentFile(img.content), save=True)
                except Exception as e:
                    print('Avatar fetch failed:', e)

            tokens = get_tokens_for_user(user)
            return Response({
                'ok': True,
                'user': UserSerializer(user, context={'request': request}).data,
                'token': tokens['access'],
                'refresh': tokens['refresh'],
            })

        except ValueError:
            return Response({'error': 'Invalid or expired Google token.'}, status=400)
        except Exception as e:
            print('[GoogleLogin] Exception:', e)
            return Response({'error': 'Internal server error'}, status=500)
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
    

