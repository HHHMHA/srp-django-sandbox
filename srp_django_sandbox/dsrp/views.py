import srp
from .verifier import Verifier
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views import View
from django.views.generic import CreateView
from dsrp.forms import UserCreateForm, User, GenerateChallengeForm


class RegisterView(CreateView):
    template_name = 'register.html'
    form_class = UserCreateForm
    success_url = '/'


class GenerateChallengeView(CreateView):
    template_name = 'challenge.html'
    form_class = GenerateChallengeForm

    def post(self, request, *args, **kwargs):
        user = get_object_or_404(User, username=request.POST.get('username', None))
        A = request.POST.get('A', None) # NOQA
        A = bytes.fromhex(A)
        # RFC
        svr = Verifier(user.username, user.get_salt(), user.get_vkey(), A)
        s, B = svr.get_challenge()  # NOQA

        if s is None or B is None:
            raise ValidationError("Couldn't login with provided credentials.")

        request.session['srp'] = {
            'salt': user.get_salt(),
            'vkey': user.get_vkey(),
            'A': A,
            'username': user.username,
        }
        return JsonResponse(data={
            's': s.hex(),
            'B': B.hex(),
        })


class LoginUserView(View):
    def post(self, request, *args, **kwargs):
        user = get_object_or_404(User, username=request.POST.get('username', None))
        A = request.POST.get('A', None) # NOQA
        A = bytes.fromhex(A)
        svr = srp.Verifier(user.username, user.get_salt(), user.get_vkey(), A)
        s, B = svr.get_challenge()  # NOQA

        if s is None or B is None:
            raise ValidationError("Couldn't login with provided credentials.")

        return JsonResponse(data={
            's': s.hex(),
            'B': B.hex(),
        })

# https://github.com/alax/jsrp
# https://pythonhosted.org/srp/srp.html#example
