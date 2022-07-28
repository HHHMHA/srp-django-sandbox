from django.contrib.auth import get_user_model
from django import forms

User = get_user_model()


class UserCreateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = (
            'username',
            'salt',
            'vkey',
        )


class GenerateChallengeForm(forms.ModelForm):
    A = forms.CharField()

    class Meta:
        model = User
        fields = (
            'A',
            'username',
        )
