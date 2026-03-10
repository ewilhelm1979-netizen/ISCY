from django.urls import path
from .views import ProductDetailView, ProductListView, ProductRoadmapView

app_name = 'product_security'

urlpatterns = [
    path('', ProductListView.as_view(), name='list'),
    path('<int:pk>/', ProductDetailView.as_view(), name='detail'),
    path('<int:pk>/roadmap/', ProductRoadmapView.as_view(), name='roadmap'),
]
