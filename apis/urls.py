from django.urls import path, include
from apis.views import *
urlpatterns = [
    path('signup/', SignupView.as_view(), name="Signup"),
    path('login/',  LoginView.as_view(), name="Sign In"),
    path('forgotpassword/', ResetPasswordView.as_view(), name="Reset Password"),
    path('logout/', LogoutView.as_view(), name="Change Password"),
    path('reset<int:id>/<str:uuid>', ChangePassword.as_view(), name="Change Password"),
    path('profile/<int:user_id>', ProfileView.as_view(), name="View Profile"),
]
