from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.views.generic import CreateView
from django import forms


class CustomUserCreationForm(UserCreationForm):
    """
    Custom user creation form with email field
    """
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


def register_view(request):
    """
    View for user registration
    """
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            # Log the user in after registration
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            messages.success(request, f'Account created successfully! Welcome to the Threat Detection Platform, {username}!')
            return redirect('detector:dashboard')
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration/register.html', {'form': form})


def login_redirect_view(request):
    """
    View for redirecting after login with a countdown
    """
    return render(request, 'registration/login_redirect.html')


@login_required
def profile_view(request):
    """
    View for user profile
    """
    # Get user activity logs (could be expanded in the future)
    context = {
        'user': request.user,
    }
    return render(request, 'registration/profile.html', context)
