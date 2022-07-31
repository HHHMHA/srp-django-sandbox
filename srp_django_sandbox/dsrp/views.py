from django.contrib.auth import login, authenticate
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse
from srp._pysrp import long_to_bytes

from .verifier import Verifier
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.views import View
from django.views.generic import CreateView, TemplateView
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
        A = request.POST.get('A', None)  # NOQA
        A = bytes.fromhex(A)
        # RFC
        svr = Verifier(user.username, user.get_salt(), user.get_vkey(), A)
        s, B = svr.get_challenge()  # NOQA

        if s is None or B is None:
            raise ValidationError("Couldn't login with provided credentials.")

        request.session['srp'] = {
            'salt': user.salt,
            'vkey': user.vkey,
            'A': A.hex(),
            'username': user.username,
            'b': long_to_bytes(svr.b).hex(),  # Needed for keeping public key of server the same
        }
        return JsonResponse(data={
            's': s.hex(),
            'B': B.hex(),
        })


class LoginView(View):
    def post(self, request, *args, **kwargs):
        M = request.POST.get('M', None)

        user = authenticate(request, M=M, **request.session.get('srp', {}))

        if not user:
            return JsonResponse({"message": "Fuck you!"}, status=400)

        login(request, user)
        request.session['srp'] = {}
        request.session.modified = True
        return redirect(reverse('user_home'))


class HomePageView(LoginRequiredMixin, TemplateView):
    template_name = 'home.html'

# https://github.com/alax/jsrp
# https://pythonhosted.org/srp/srp.html#example
