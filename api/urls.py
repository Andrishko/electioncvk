from . import views
from django.urls import path

urlpatterns = [
    path('api/', views.get_vote),
    path('api/send_bulletin', views.send_bulletin),
    path('api/vote', views.get_vote),

]
