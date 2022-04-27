import logging
from rest_framework import serializers, settings
from web.models import * 
from rest_framework.authtoken.models import Token
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate, login
from uuid import uuid4

logger = logging.getLogger(__name__)


class SignupSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField()
    
    class Meta:
        model = User
        fields = [ 'email','name', 'password']
    
    def create(self, validated_data):
        try:
            match = User.objects.get(username=validated_data['email'])
            print(match)
            return {"status": False, "message": "user with email {} already exists".format(validated_data['email'])}
        except User.DoesNotExist:
            user =  User.objects.create(username = validated_data['email'],
                                        email = validated_data['email'],
                                        password = validated_data['password'],
                                        )
            user.set_password(validated_data['password'])
            user.save()
            token = Token.objects.create(user=user)
            profile = Profile.objects.create(user=user,
                                            name = validated_data['name'],
                                            uuid = uuid4(),)
            profile.save()
            return {"status": True, "message": "user created with email {}".format(validated_data['email'])}

    def validate(self, attrs):
        msg = None
        email = attrs.get("email", "")
        if not email:
            msg = "'email' is not provided"
        password = attrs.get("password", "")
        if not password:
            msg = "'password' is not provided"
        
        name = attrs.get("name", "")
        if not name:
            msg = "'name' is not provided"
        if msg:
            return msg
        return attrs

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=4)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    
    class Meta:
        model = User
        fields = ["email", "password"]

    def validate(self, request):
        try:
            data = request.POST
            msg = None
            username = data.get("email", "")
            if not username:
                msg = "'username' is not provided"
            password = data.get("password", "") 
            if not password:
                msg = "'password' is not provided"
            if msg:
                return {"status": False, 'message': msg}
            user = User.objects.get(email=username)
            user = authenticate(request, username=user.username, password=password)
            if user:
                return {"status": True, "user": user, "id":user.id}
            else:
                return {"status": False, "message": "Invalid credentials, try again"}
        except User.DoesNotExist:
            return {"status": False, "message": "No such user"}
        except Exception as e:
            logger.error(e)
            return {"status": False, "message": e}

class ProfileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Profile 
        fields = ['user_id', 'name', 'gender', 'weight', 'height', 'bmi', 'bmi_calculated_at']

    def validate(self, attrs):
        return super().validate(attrs)

    def update(self, instance, validated_data):
        instance.save()
        return super().update(instance, validated_data)

class ResetPasswordSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User 
        fields = ['email']

    def update(self, instance, validated_data):
        instance.save()
        return super().update(instance, validated_data)

class ChangePasswordSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User 
        fields = ['password']
