from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView, MeView, GoogleLoginView,
    UserSearchView, MeProfileView, ForgotPasswordView, ResetPasswordView,ValidateResetTokenView,
    ChangePasswordView
)

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('me/', MeView.as_view()),
    path('google-login/', GoogleLoginView.as_view()),  
    path('users/search/', UserSearchView.as_view(), name='user-search'), 
    path("me/profile/", MeProfileView.as_view(), name="me-profile"),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('validate-reset-token/', ValidateResetTokenView.as_view(), name='validate-reset-token'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]
