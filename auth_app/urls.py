from django.urls import path
from .views import RegisterView, LoginView, LogoutView, MeView, GoogleLoginView,UserSearchView   

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('me/', MeView.as_view()),
    path('google/', GoogleLoginView.as_view(), name='google-login'),
    path('users/search/', UserSearchView.as_view(), name='user-search')
]
