from django.contrib.auth import get_user_model
from django import forms

User = get_user_model()


class UserCreateForm(forms.ModelForm):
    salt = forms.CharField(widget=forms.HiddenInput())
    vkey = forms.CharField(widget=forms.HiddenInput())

    class Meta:
        model = User
        fields = (
            'username',
            'salt',
            'vkey',
        )


class GenerateChallengeForm(forms.ModelForm):
    A = forms.CharField(widget=forms.HiddenInput())

    class Meta:
        model = User
        fields = (
            'A',
            'username',
        )
