from django.contrib import admin
from django.urls import path
from web.views import *

urlpatterns = [
    path('', home, name="Home"),
    path('signup/', signup, name="Signup"),
    path('login/', signin, name="Signin"),
    path('forgotpassword/', forgotpassword, name="Forgot Password"),
    path('forgotpassword/', forgotpassword, name="Forgot Password"),
    path('profile/', profile, name="View Profile"),
    path('reset<int:id>/<str:uuid>', resetpass, name="Change Password"),
]
