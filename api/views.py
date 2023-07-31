import random
from django.shortcuts import render
from django.http import JsonResponse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa

from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer

from django.core.serializers import serialize
from django.utils import timezone

import json
import base64
import string
from .models import *
from .serializers import *


def generate_unique_number():
    while True:
        # Generate a random number between 1 and 1000
        number = random.randint(1, 1000)
        # Check if the number exists in the model
        if not uniqField.objects.filter(number=number).exists():
            return number


def generate_unique_string():
    # Define the characters to use for generating the string
    characters = string.ascii_letters + string.digits

    while True:
        # Generate a random string of length 50
        random_string = ''.join(random.choices(characters, k=255))

        # Check if the string exists in the `uniq` table
        if not uniqField.objects.filter(number=random_string).exists():

            return random_string


def check_time(start, finish):
    return True if start < timezone.now() < finish else False


def decodeData(data):
    decoded_data = base64.b64decode(data)

    # Convert the decoded data to string
    data_string = decoded_data.decode('utf-8')

    # Parse the JSON string to get the original data
    decoded = json.loads(data_string)
    return decoded


def check_sign(reqdata):
    public_key_pem = reqdata['publicKey']
    signature = reqdata['signature']
    data = reqdata['data']
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    # Перевірка підпису
    public_key.verify(
        signature=bytes.fromhex(signature),
        data=data.encode(),
        padding=padding.PKCS1v15(),
        algorithm=SHA256()
    )
    return True


def sign(data_to_sign):
    # Генерація закритого та відкритого ключів
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    # Конвертування словника даних у формат JSON
    data_json = json.dumps(data_to_sign).encode()
    # Підписування даних закритим ключем
    signature = private_key.sign(
        data_json,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Конвертування відкритого ключа у PEM формат
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {'signature': signature.hex(),
            'public_key': pem_public_key.decode()}


@api_view(["POST"])
def send_bulletin(request: Request):
    reqdata = request.data
    try:
        check_sign(reqdata)
    except Exception as e:
        return JsonResponse({'valid': False, 'error': str(e)})
    req = decodeData(reqdata['data'])
    user = Users.objects.get(name=req['name'])
    vote = Voting.objects.get(faculty=1)
    if not check_time(vote.start, vote.finish):
        return JsonResponse({'value': 'timeoff'})
    if user.uniq == req['password'] and not user.is_voted:
        user.is_voted = 1
        user.save()
        number = generate_unique_string()
        uniqField(number=number).save()
        candidates = list(Candidates.objects.filter(
            faculty=user.faculty).values('name', 'id'))
        vote = list(Voting.objects.filter(
            faculty=user.faculty).values('name', 'faculty', 'id'))
        data_to_sign = {
            'name': req['name'],
            'candidates': candidates,
            'vote': vote,
            'token': number,
        }

        signat = sign(data_to_sign)

        return JsonResponse({
            'data': data_to_sign,
            'signature': signat['signature'],
            'public_key': signat['public_key']
        })
    else:
        return JsonResponse({'valid': 'you voted'})

    # except Exception as e:
    #     return JsonResponse({'valid': False, 'error': str(e)})


@api_view(["POST"])
def get_vote(request):
    reqdata = request.data
    req = decodeData(reqdata['data'])
    uniq = req['uniq']
    vote = req['ccode']
    try:
        check_sign(reqdata)
    except Exception as e:
        return JsonResponse({'valid': False, 'error': str(e)})
        
    token = uniqField.objects.get(number=req["token"])
    voting = Voting.objects.get(id=req["voting"])
    if not check_time(voting.start, voting.finish):
        return ''
    if token.is_voted:
        return JsonResponse({'status': 'ви вже брали участь в голосуванні'})
    codeVote(code=uniq, vote=vote).save()
    token.is_voted = 1
    token.save()
    # candidate = Candidates.objects.get(name=req["candidate"])
    # if req['vote'] == "yes":
    #     candidate.vote_for = candidate.vote_for + 1
    #     codeVote(code=uniq, vote=candidate.name).save()
    #     candidate.save()
    # if vote == "no":
    #     candidate.vote_against = candidate.vote_against + 1
    #     candidate.save()
    return JsonResponse({'valid': True, 'code': uniq, 'status': 'ваш голос зарахований'})
    # except Exception as e:
    #     return JsonResponse({'valid': False, 'error': str(e)})

    # data = request.data
    # number = uniqField.objects.get(uniq=data["token"])
    # voting = Voting.objects.get(name=data["voting"])

    # candidate = Candidates.objects.get(name=data["name"])

    # vote = data["vote"]

    # if vote == "yes":
    #     candidate.vote_for = candidate.vote_for + 1
    #     candidate.save()
    # if vote == "no":
    #     candidate.vote_against = candidate.vote_against + 1
    #     candidate.save()

    # goal = Goals(code=data["code"], voting=voting.name,
    #              candidate=candidate.name, result=vote)
    # goal.save()
    # return True
