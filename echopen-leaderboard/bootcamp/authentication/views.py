from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from bootcamp.authentication.forms import SignUpForm, ResetForm
from django.contrib.auth.models import User
from bootcamp.feeds.models import Feed
from django.conf import settings
from django.contrib.auth.models import User
import random

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if not form.is_valid():
            return render(request, 'authentication/signup.html',
                          {'form': form})

        else:
            username = form.cleaned_data.get('username')
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            User.objects.create_user(username=username, password=password,
                                     email=email)
            user = authenticate(username=username, password=password)
            login(request, user)
            welcome_post = u'{0} has joined the network.'.format(user.username,
                                                                 user.username)
            feed = Feed(user=user, post=welcome_post)
            feed.save()
            return redirect('/leaderboard')

    else:
        return render(request, 'authentication/signup.html',
                      {'form': SignUpForm()})





from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template import loader
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from bootcamp.settings import DEFAULT_FROM_EMAIL
from django.views.generic import *
from forms  import ResetForm
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models.query_utils import Q




def reset_password(request):
    if request.method == 'POST':
            form = ResetForm(request.POST)
            data = form
            try:
                user = User.objects.get(email=data.data['email'])
                print(user, data.data['email'])
                password = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
                user.set_password(password)
                user.save()
                send_mail('subject', "your echopen password has been reset %s" % password, DEFAULT_FROM_EMAIL , [data.data["email"]], fail_silently=False)
                return render(request, 'authentication/request_password.html', {'form': ResetForm()})

            except:

                return render(request, 'authentication/request_password.html', {'form': ResetForm()})

    else:
        return render(request, 'authentication/request_password.html', {'form': ResetForm()})
