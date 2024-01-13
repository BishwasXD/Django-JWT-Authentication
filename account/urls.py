
from . import views
from django.urls import path

urlpatterns = [
    
    path('register', views.UserRegistrationView.as_view(), name='user_registration'),
    path('login',views.UserLoginView.as_view(),name="user_login"),
    path('profile', views.UserProfileView.as_view(), name='profile'),
    path('change_password', views.UserChangePasswordView.as_view(), name='change_password'),
    path('reset/', views.SendPasswordResetEmailView.as_view(), name='reset_password'),

]