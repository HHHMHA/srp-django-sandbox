from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from dsrp.verifier import Verifier

UserModel = get_user_model()


class SRPBackend(ModelBackend):
    def authenticate(self, request, username=None, salt=None, vkey=None, A=None, M=None, b=None, **kwargs):
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        if not all([username, salt, vkey, A, M]):
            return
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            pass
        else:
            # H
            if self._check_challenge(username, salt, vkey, A, M, b) and self.user_can_authenticate(user):
                return user

    @staticmethod
    def _check_challenge(username, salt, vkey, A, M, b):
        verifier = Verifier(username, bytes.fromhex(salt), bytes.fromhex(vkey), bytes.fromhex(A), bytes_b=bytes.fromhex(b))
        result = verifier.verify_session(bytes.fromhex(M))
        return result is not None
