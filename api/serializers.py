from rest_framework import serializers
from .models import *


class VotingSerializer (serializers.Serializer):
    class Meta:
        model = Voting
        fields = '__all__'


class CandidatesSerializer (serializers.Serializer):
    class Meta:
        model = Candidates
        fields = '__all__'
