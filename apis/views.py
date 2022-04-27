from rest_framework.authtoken.views import ObtainAuthToken

from uuid import uuid4
from django.contrib.auth import login, logout
from rest_framework.generics import *
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from web.models import *
from apis.serializer import *
from rest_framework.status import *
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
from Assignment import settings
from django.core.mail import send_mail

app_name = "apis"

class SignupView(CreateAPIView):
    """
        Signup new user with email
    """
    serializer_class = SignupSerializer
    
    def post(self, request):
        try:
            if self.request.user.is_anonymous:
                data = request.data
                validated_data = self.serializer_class.validate(self.serializer_class.validate, data)
                signup = self.serializer_class.create(self.serializer_class.validate, data)
                if signup['status']:
                    return Response(status=HTTP_201_CREATED, data={ "message": "User Created Successfully."})
                else:
                    return Response(status=HTTP_500_INTERNAL_SERVER_ERROR, data={ "message": signup['message']})
            else:
                return Response(status=HTTP_403_FORBIDDEN, data={ "message": "Logout before signing up."})
        except Exception as e:
            return Response(status=HTTP_500_INTERNAL_SERVER_ERROR, data={"message": "Exception occurred"})

 
class LoginView(ObtainAuthToken):
    """
        Login a new user using email and password
    """
    serializer_class = LoginSerializer
    
    def post(self, request):
        try:
            data = request.data
            authenticated = self.serializer_class.validate(self.serializer_class, request)
            if authenticated["status"] == True:
                id = authenticated.get('id')
                login(request, authenticated["user"])
                token, created = Token.objects.get_or_create(user=self.request.user)
                profile = Profile.objects.get(user = request.user)
                profile.last_seen = request.user.last_login
                profile.save()
                msg = "Login successful !"
            else:
                id = "None"
                msg = authenticated.get("message")
            return Response(status=HTTP_200_OK, data={"message": msg, "user_id": id, "token": token.key})
        except Exception as e:
            return Response(status=HTTP_500_INTERNAL_SERVER_ERROR, data={"message": "Exception occurred"})

class LogoutView(GenericAPIView):
    """
        Log out a user if he's logged in
    """
    seserializer_class = LoginSerializer
    
    def get(self, request):
        try:
            if not self.request.user.is_anonymous:
                user = self.request.user
                request.user.auth_token.delete()
                logout(self.request)
                return Response(status=HTTP_200_OK, data={"message": "Logout Successful !"})
            else:
                return Response(status=HTTP_200_OK, data={"message": "No logged in User !"})
        except Exception as e:
            return Response(status=HTTP_500_INTERNAL_SERVER_ERROR, data={"message": "Exception occurred"})

class ResetPasswordView(GenericAPIView):
    """
        Reset password of a user using email
    """
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        validated_data = request.data
        try:
            receiver =  validated_data['email']
            get_user = User.objects.get(email=receiver)
            profile = Profile.objects.get(user=get_user)
            mail_content = "Hello {},\n here is your password reset link http://127.0.0.1:5001/api/reset{}/{}".format(get_user.first_name, int(get_user.id), profile.uuid)
            mail = send_mail('Reset Password ', mail_content, settings.EMAIL_HOST_USER, [receiver])
            if mail == 1:
                msg = "Reset password link sent successfully to {}".format(receiver)
            else:
                msg = "Currently we are unable to send message to {}, please try again ".format(receiver)
        except User.DoesNotExist:
            print("This user not exist")
            mail_content = "Hello User,\n You have requested for reset password since your account doesn't exist please check http://127.0.0.1:5001/signup"
            mail = send_mail('Reset Password ', mail_content, settings.EMAIL_HOST_USER, [receiver])
            if mail == 1:
                msg = "Reset password link sent successfully to {}".format(receiver)
            else:
                msg = "Currently we are unable to send message to {}, please try again ".format(receiver)
        except Exception as e:
            print(e)
        return Response(status=HTTP_200_OK, data={"message ": msg})

class ChangePassword(RetrieveUpdateAPIView):
    """
    Change users password if he's logged in
    """
    serializer_class = ChangePasswordSerializer
    lookup_field = 'id'
    queryset = User.objects.all()

    def retrieve(self, request, *args, **kwargs):
        try:
            id, url_uuid = kwargs.get('id'), kwargs.get('uuid')
            profile = Profile.objects.get(user=id)
            if str(profile.uuid) == url_uuid:
                msg = "Enter Password to Upodate"
            else:
                msg = "This link is expired please request for new Link"    
            return Response(status=HTTP_200_OK,data={"message": msg})
        except Exception as e:
            return Response(status=HTTP_500_INTERNAL_SERVER_ERROR, data={"message": "Exception occurred"})
        

    def update(self, request, *args, **kwargs):
        try:
            data = request.data
            id, url_uuid = kwargs.get('id'), kwargs.get('uuid')
            current_user = User.objects.get(id=id)
            profile = Profile.objects.get(user=id)
            if str(profile.uuid) == url_uuid:
                current_user.set_password(data['password'])
                current_user.save()
                Profile.objects.filter(user=id).update(uuid=uuid4())
                msg = "Password Updated"
            else:
                msg = "Link Expired please request for new One"
        except Exception as we:
            print(we)
            msg = "User associated with email {} does not exist"
        return Response(status=HTTP_200_OK, data={"message ": msg})

class ProfileView(RetrieveUpdateAPIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()
    lookup_field = 'user_id'

    def retrieve(self, request, *args, **kwargs):
        try:
            id = kwargs.get('user_id')
            current_user = User.objects.get(id=request.user.id)
            queryset = self.get_queryset()
            user = get_object_or_404(queryset, pk=current_user)
            serializer = ProfileSerializer(user)
            return Response(status=HTTP_200_OK, data=serializer.data)
        except Exception as e:
            logger.error(e)
            return Response(status=HTTP_500_INTERNAL_SERVER_ERROR, data={"message": "Exception occurred"})

    def update(self, request, *args, **kwargs):
        if 'PATCH' in request.method:
            partial = True
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if not serializer.is_valid():
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response(serializer.data)
        # return super().update(request, *args, **kwargs)
