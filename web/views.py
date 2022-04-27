from rest_framework.authtoken.models import Token

from django.shortcuts import redirect, render
from django.contrib import messages
import requests
from django.contrib.auth import authenticate, login

from web.models import Profile

API_URL = 'http://127.0.0.1:5001/api/'
# Create your views here.

def home(request):
    return render(request, 'home.html')

def signup(request):
    if request.user.is_authenticated:
        return redirect('/profile')
    if request.method == "POST":
        data = request.POST
        print(data)
        url = API_URL + 'signup/'
        response = requests.post(url, data=data)
        print(response)
        response_json  = response.json()
        if response.status_code>201:
            messages.add_message(request, messages.ERROR, response_json['message'])
        else:
            messages.add_message(request, messages.SUCCESS, 'Signup Successfull.')
    return render(request, 'signup.html')

def signin(request):
    if request.user.is_authenticated:
        return redirect('/profile')
    if request.method == "POST":
        data = request.POST
        print(data)
        username = request.POST['email']
        password = request.POST['password']
        url = API_URL + 'login/'
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            
            response = requests.post(url, data=data,)
            print(response.json())
            # response_json  = response.json()
            messages.add_message(request, messages.SUCCESS, 'Login Successfull.')
            return redirect('/profile')
        else:
            messages.add_message(request, messages.ERROR, 'Invalid credentials, try again.')        
    return render(request, 'signin.html')

def forgotpassword(request):
    if request.method == "POST":
        data = request.POST
        print(data)
        url = API_URL + 'forgotpassword/'
        response = requests.post(url, data=data)
        print(response)
        response_json  = response.json()
        # if response.status_code>200:
        #     messages.add_message(request, messages.ERROR, response_json['message'])
        # else:
        messages.add_message(request, messages.SUCCESS, 'Sent email to the email, please check your email.')
    return render(request, 'forgotpass.html')

def resetpass(request, id, uuid):
    if request.method == "POST":
        data = request.POST
        url = API_URL + 'reset{}/{}'.format(id, uuid)
        response = requests.patch(url, data=data)
        print(response)
        response_json  = response.json()
        if response.status_code>200:
            messages.add_message(request, messages.ERROR, response_json['message'])
        else:
            messages.add_message(request, messages.SUCCESS, 'Password successfully updated.')
    return render(request, 'resetpass.html')

def profile(request):
    print(request.user)
    if request.user.is_authenticated:
        if request.method == "POST":
            data = request.POST
            for key, value in list(data.items()):
                if value is None:
                    del data[key]
            token, created = Token.objects.get_or_create(user=request.user)
            url = API_URL + 'profile/{}'.format(request.user.id, )
            headers={'Authorization': 'Token {}'.format(token.key)}
            response = requests.patch(url, data=data, headers={'Authorization': 'Token {}'.format(token.key)})
            print(response.json())
            response_json  = response.json()
            if response.status_code>201:
                messages.add_message(request, messages.ERROR, response_json['message'])
            else:
                messages.add_message(request, messages.SUCCESS, 'your BMI Profile Updated sucessfully !')
        profile = Profile.objects.get(user=request.user)
        return render(request, 'profile.html', context={'profile': profile})
    return redirect('/login')