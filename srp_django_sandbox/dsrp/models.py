from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    salt = models.TextField()
    vkey = models.TextField()

    def get_salt(self):
        return bytes.fromhex(self.salt)

    def get_vkey(self):
        return bytes.fromhex(self.vkey)
