from django.db import models

from datetime import datetime
from django.contrib.auth.models import PermissionsMixin, AbstractUser
from django.db import models
from django.db.models import signals
from django.dispatch import receiver
from django.utils import timezone


class Facultys (models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


class Users (models.Model):
    name = models.CharField(max_length = 255)
    uniq = models.CharField(max_length=255)
    is_voted = models.BooleanField(default=False)
    faculty = models.ForeignKey('Facultys', on_delete=models.PROTECT)


class Candidates (models.Model):
    name = models.CharField(max_length=255)
    faculty = models.ForeignKey('Facultys', on_delete=models.PROTECT)
    vote_for = models.IntegerField(default=0)
    vote_against = models.IntegerField(default=0)
    def __str__(self):
        return self.name


class Voting (models.Model):
    start = models.DateTimeField(default=datetime.now())
    finish = models.DateTimeField(default=datetime.now())
    name = models.CharField(max_length=200, default='')
    faculty = models.ForeignKey('Facultys', on_delete=models.PROTECT)

    def __str__(self):
        return self.name


class Goals (models.Model):
    code = models.CharField(max_length=255)
    voting = models.CharField(max_length=255)
    candidate = models.CharField(max_length=255)
    result = models.CharField(max_length=255)
    

class uniqField (models.Model):
    number = models.CharField(max_length=255)
    is_voted = models.BooleanField(default=False)

class codeVote (models.Model):
    code = models.CharField(max_length = 1000)
    vote = models.CharField(max_length = 1000, default='0')

