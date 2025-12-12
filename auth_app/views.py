# auth_app/views.py - Updated MeProfileView
import logging
import traceback
from datetime import timedelta
from urllib.parse import urljoin
import pyotp
import secrets
import uuid
import requests

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.hashers import make_password, check_password
from django.core.files.base import ContentFile
from django.core.cache import cache
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny

from boards.models import Workspace
from .emails import send_password_reset_email
from .models import AuthToken, Profile, UserSession
from .serializers import (
    GoogleLoginSerializer,
    LoginSerializer,
    PasswordResetSerializer,
    ProfileSerializer,
    RegisterSerializer,
    SetNewPasswordSerializer,
    UserAvatarSerializer,
    UserSerializer,
    ChangePasswordSerializer,
)

from django_ratelimit.decorators import ratelimit


logger = logging.getLogger(__name__)
User = get_user_model()


# --------------------------------------------
# Session Management
# --------------------------------------------
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_active_sessions(request):
    user = request.user
    sessions = UserSession.objects.filter(user=user).order_by('-last_activity')
    
    # Lấy JTI của JWT hiện tại
    current_jti = request.auth.get('jti')
    
    data = [{
        'id': s.id,
        'device': s.device or 'Unknown Device',
        'ip_address': s.ip_address,
        'location': s.location or 'Unknown',
        'last_activity': s.last_activity.isoformat(),
        'created_at': s.created_at.isoformat(),
        'is_current': s.session_token == current_jti
    } for s in sessions]
    
    return Response(data)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def revoke_session(request, session_id):
    user = request.user
    try:
        session = UserSession.objects.get(id=session_id, user=user)
        
        # Don't allow revoking current session
        current_token = request.auth
        if str(session.session_token) == str(current_token):
            return Response({'error': 'Cannot revoke current session'}, status=400)
        
        session.delete()
        return Response({'message': 'Session revoked'})
    except UserSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_all_sessions(request):
    user = request.user
    current_token = request.auth
    
    # Delete all except current
    UserSession.objects.filter(user=user).exclude(
        session_token=str(current_token)
    ).delete()
    
    return Response({'message': 'All other sessions revoked'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def enable_mfa(request):
    """
    Step 1: Generate a new TOTP secret and return QR provisioning URI.
    """
    user = request.user
    secret = pyotp.random_base32()

    # Cache secret for 15 minutes during setup
    cache.set(f"mfa_setup:{user.id}", secret, timeout=900)

    totp = pyotp.TOTP(secret)
    qr_url = totp.provisioning_uri(
        name=user.email,
        issuer_name="TaskNest"
    )

    return Response({
        "qr_code_url": qr_url,
    })
# --------------------------------------------
# Verify MFA setup (user scans QR & enters code)
# --------------------------------------------
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_mfa_setup(request):
    user = request.user
    code = request.data.get("code")

    backup_codes = user.profile.backup_codes or []
    if any(check_password(code, hashed_code) for hashed_code in backup_codes):
        # nếu dùng backup code → xoá code đã dùng
        user.profile.backup_codes = [
            h for h in backup_codes if not check_password(code, h)
        ]
        user.profile.save()
        authenticated = True
    else:
        authenticated = False

    secret = cache.get(f"mfa_setup:{user.id}")
    if not secret:
        return Response({"error": "Setup expired"}, status=400)

    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        return Response({"error": "Invalid code"}, status=400)

    # Save secret to profile
    profile = getattr(user, "profile", None)
    if not profile:
        profile = Profile.objects.create(user=user)

    profile.mfa_secret = secret
    profile.mfa_enabled = True

    raw_codes = [secrets.token_hex(4) for _ in range(10)]
    hashed_codes = [make_password(code) for code in raw_codes]

    profile.backup_codes = hashed_codes
    profile.save()

    return Response({"backup_codes": raw_codes})


# --------------------------------------------
# MFA-aware login
# --------------------------------------------
@ratelimit(key='ip', rate='5/m', block=True)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_mfa(request):
    """
    Step 1: Try normal login. If user has MFA enabled,
    return a temp token to verify MFA code in next step.
    """
    email = request.data.get("email")
    password = request.data.get("password")

    user = authenticate(username=email, password=password)
    if not user:
        return Response({"error": "Invalid credentials"}, status=401)

    # If MFA enabled — return pending token
    profile = getattr(user, "profile", None)
    if profile and profile.mfa_enabled and profile.mfa_secret:
        temp_token = secrets.token_urlsafe(32)
        cache.set(f"mfa_pending:{temp_token}", user.id, timeout=300)

        return Response({
            "mfa_required": True,
            "temp_token": temp_token
        })

    # Otherwise login directly
    tokens = get_tokens_for_user(user)
    return Response({
        "token": tokens["access"],
        "refresh": tokens["refresh"],
        "user": UserSerializer(user).data
    })


# --------------------------------------------
# Verify MFA login step (2FA code)
# --------------------------------------------
@api_view(['POST'])
@permission_classes([AllowAny])
def verify_mfa_login(request):
    """
    Step 2: Client submits temp_token + 6-digit MFA code.
    """
    temp_token = request.data.get("temp_token")
    code = request.data.get("code")

    user_id = cache.get(f"mfa_pending:{temp_token}")
    if not user_id:
        return Response({"error": "Session expired"}, status=400)

    try:
        user = Profile.objects.select_related("user").get(user_id=user_id).user
    except Profile.DoesNotExist:
        return Response({"error": "User not found"}, status=404)

    totp = pyotp.TOTP(user.profile.mfa_secret)
    if not totp.verify(code):
        return Response({"error": "Invalid code"}, status=400)

    # Successful MFA — clear pending state and return JWT
    cache.delete(f"mfa_pending:{temp_token}")
    tokens = get_tokens_for_user(user)

    return Response({
        "ok": True,
        "token": tokens["access"],
        "refresh": tokens["refresh"],
        "user": UserSerializer(user).data
    })


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class MeProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = request.user.profile
        return Response(ProfileSerializer(profile, context={"request": request}).data)

    def patch(self, request):
        profile = request.user.profile
        
        try:
            # Handle FormData from frontend
            data = request.data.copy()
            
            # Clean up FormData values - frontend có thể gửi string thay vì boolean
            boolean_fields = ['is_discoverable', 'show_boards_on_profile']
            for field in boolean_fields:
                if field in data:
                    value = data[field]
                    if isinstance(value, str):
                        # Convert string to boolean
                        data[field] = value.lower() in ('true', '1', 'on', 'yes')
                    elif value is None:
                        data[field] = False
            
            # Clean up text fields
            text_fields = ['display_name', 'bio']
            for field in text_fields:
                if field in data and data[field] is None:
                    data[field] = ""
            
            # Debug log (remove in production)
            print(f"Received data: {dict(data)}")
            
            serializer = ProfileSerializer(profile, data=data, partial=True, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            
            # Return updated data
            return Response(ProfileSerializer(profile, context={"request": request}).data)
            
        except Exception as e:
            print(f"Profile update error: {e}")
            traceback.print_exc()
            return Response(
                {"error": f"Profile update failed: {str(e)}"}, 
                status=status.HTTP_400_BAD_REQUEST
            )


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save() 

        tokens = get_tokens_for_user(user)
        logger.info(f"New user registered: {user.email}")
        return Response({
            "ok": True,
            "user": UserSerializer(user, context={"request": request}).data,
            "token": tokens["access"],
            "refresh": tokens["refresh"]
        }, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        login(request, user)
        tokens = get_tokens_for_user(user)

        # Lấy access token object để lấy jti
        refresh = RefreshToken(tokens["refresh"])
        access_token = refresh.access_token
        jti = access_token["jti"]

        # Tạo session mới
        UserSession.objects.create(
            user=user,
            session_token=jti,
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", "")
        )

        if not Workspace.objects.filter(owner=user).exists():
            Workspace.objects.create(name=f"{user.username}'s workspace", owner=user)

        return Response({
            "ok": True,
            "user": UserSerializer(user, context={"request": request}).data, 
            "token": tokens["access"],
            "refresh": tokens["refresh"]
        })

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        # Lưu email trước khi logout để không bị AnonymousUser
        user_email = getattr(request.user, "email", None)

        # Thực hiện logout (chủ yếu xóa session, với JWT thì không cần)
        logout(request)

        if user_email:
            logger.info(f"User logged out: {user_email}")
        else:
            logger.info("Anonymous user attempted logout")

        return Response({"ok": True, "message": "Logged out successfully."}, status=status.HTTP_200_OK)


class MeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user, context={'request': request})
        return Response(serializer.data)

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        input_serializer = GoogleLoginSerializer(data=request.data)
        input_serializer.is_valid(raise_exception=True)
        token = input_serializer.validated_data['token']

        try:
            id_info = id_token.verify_oauth2_token(
                token, 
                google_requests.Request(), 
                settings.GOOGLE_OAUTH2_CLIENT_ID # Lấy Client ID từ file settings.py
            )

            # Lấy email từ kết quả đã được xác thực
            email = id_info.get('email')

            if not email:
                return Response({'error': 'No email in token'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(email=email)
                created = False
            except User.DoesNotExist:
                user = User.objects.create_user(username=email, email=email)
                created = True

            profile, _ = Profile.objects.get_or_create(user=user)

            login(request, user)
            tokens = get_tokens_for_user(user)

            picture = id_info.get('picture')

            if picture and (created or not profile.avatar):
                try:
                    resp_img = requests.get(picture, timeout=5)
                    resp_img.raise_for_status()
                    fname = f'user_{user.id}.jpg'
                    profile.avatar.save(fname, ContentFile(resp_img.content), save=True)
                except Exception as e:
                    print(f"Failed to fetch Google avatar for {email}: {e}")

            user_data = UserSerializer(user, context={'request': request}).data
            if not Workspace.objects.filter(owner=user).exists():
                Workspace.objects.create(name=f"{user.username}'s workspace", owner=user)
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
        if len(query) < 2:
            return Response([], status=status.HTTP_200_OK)

        users = User.objects.filter(
            Q(username__icontains=query) | Q(email__icontains=query)
        )[:10]

        # Use UserAvatarSerializer for search results
        serializer = UserAvatarSerializer([u.profile for u in users], many=True, context={'request': request})
        return Response(serializer.data)
    

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Không tiết lộ email có tồn tại hay không để tránh dò
            return Response(
                {"ok": True, "message": "If this email exists, a reset link has been sent."},
                status=status.HTTP_200_OK
            )

        token_obj = AuthToken.objects.create(
            user=user,
            purpose="reset",
            hours=1
        )

        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token_obj.token}"

        send_password_reset_email(email, reset_link)

        return Response(
            {"ok": True, "message": "Password reset email sent."},
            status=status.HTTP_200_OK
        )
    
class ChangePasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        logger.info(f"User {request.user.email} changed password.")

        # Optional: có thể revoke các session khác tại đây nếu sau này bạn dùng UserSession 
        # UserSession.objects.filter(user=request.user).exclude(session_token=str(request.auth)).delete()

        return Response(
            {"ok": True, "message": "Password changed successfully."},
            status=status.HTTP_200_OK
        )

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SetNewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"ok": True, "message": "Password updated successfully."})    


class ValidateResetTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token_str = request.data.get('token')
        if not token_str:
            return Response({'error': 'Token missing'}, status=400)

        try:
            token_obj = AuthToken.objects.get(token=token_str, purpose='reset')
        except AuthToken.DoesNotExist:
            return Response({'error': 'Invalid token'}, status=400)

        if token_obj.is_expired or token_obj.used:
            return Response({'error': 'Expired or used token'}, status=400)

        # Tạo session tạm để tránh dùng lại token gốc
        session_id = uuid.uuid4()
        cache.set(f'reset-session:{session_id}', token_obj.user_id, timeout=900)  # 15 phút

        return Response({'session_id': str(session_id)})
