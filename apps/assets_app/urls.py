
from django.urls import path
from .views import InformationAssetCreateView, InformationAssetListView

app_name = 'assets'

urlpatterns = [
    path('', InformationAssetListView.as_view(), name='list'),
    path('create/', InformationAssetCreateView.as_view(), name='create'),
]
