from django.contrib import admin
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.shortcuts import render
from .models import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import requests


def check_time(start, finish):
    if start < timezone.now() < finish:
        return True
    else:
        return False


def delete_voting(modeladmin, request, queryset):
    for v in queryset:
        if v.start > timezone.now():
            Candidates.objects.filter(faculty=v.faculty).delete()
            v.delete()


def decrypt_AES(ciphertext, key):
    # Розшифровуємо зашифроване повідомлення з формату base64
    ciphertext_bytes = base64.b64decode(ciphertext)

    # Перетворення ключа на формат, який приймає AES
    formatted_key = key.encode('utf-8')

    # Ініціалізуємо об'єкт AES з використанням ключа та режиму ECB
    cipher = Cipher(algorithms.AES(formatted_key),
                    modes.ECB(), backend=default_backend())

    # Розшифровуємо повідомлення
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(
        ciphertext_bytes) + decryptor.finalize()

    # Видаляємо вирівнювання
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

    # Повертаємо розшифроване повідомлення у вигляді рядка
    return plaintext.decode('utf-8')


def get_result(modeladmin, request, queryset):
    results_list = []

    response = requests.get('http://127.0.0.1:9583/get_key')
    data = response.json()  # отримати дані у форматі JSON
    key = data['key']

    for v in queryset:
        if not check_time(v.start, v.finish):
            candidates = Candidates.objects.filter(faculty=v.faculty).values()
            cand_list = []
            codeList = []
            sum = 0
            votes = codeVote.objects.all().values()
            for v in votes:
                voteCode = decrypt_AES(v['vote'], key).split()
                candidate = voteCode[1] + ' ' + voteCode[2]
                goal = Candidates.objects.get(name=candidate)
                goal.vote_for += 1
                goal.save()
                code = codeVote.objects.get(code=v['code'])
                code.vote = candidate
                code.save()
                codeList.append({'code': code.code, 'vote': code.vote})
            for c in candidates:

                cand_list.append(
                    {"candidate_name": c['name'], "resultyes": c['vote_for']})
            results_list.append({"candidates": cand_list})
    context = {
        "result": results_list,
        'code': codeList
    }
    print(context)
    return render(request, 'results.html', context=context)


def delete_candidates(modeladmin, request, queryset):
    for c in queryset:
        if Voting.objects.get(faculty=c.faculty).start > timezone.now():
            c.delete()


class VotingsAdmin(admin.ModelAdmin):
    list_display = ['name']

    def get_actions(self, request):
        actions = super().get_actions(request)
        if request.user.username[0].upper() != 'J':
            if 'delete_selected' in actions:
                del actions['delete_selected']
        return actions

    def has_change_permission(self, request, obj=None):
        if obj:
            if check_time(obj.start, obj.finish):
                return False
        return True

    def has_delete_permission(self, request, obj=None):
        # Disable delete
        return False

    actions = [get_result, delete_voting]


class CandidatesAdmin(admin.ModelAdmin):
    ordering = ('-faculty',)
    fields = ('name', 'faculty')

    def has_add_permission(self, request, obj=None):
        if obj:
            vote = Voting.objects.get(faculty=obj.faculty)
            if check_time(vote.start, vote.finish):
                return False
        return True

    def has_change_permission(self, request, obj=None):
        if obj:
            vote = Voting.objects.get(faculty=obj.faculty)
            if check_time(vote.start, vote.finish):
                return False
        return True

    def has_delete_permission(self, request, obj=None):
        # Disable delete
        return False
    actions = [delete_candidates]


admin.site.register(Voting, VotingsAdmin)
admin.site.register(Candidates, CandidatesAdmin)
admin.site.register(Facultys)
