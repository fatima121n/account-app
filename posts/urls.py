from django.urls import path
from . views import PostListCreateView, PostRetrieveUpdateDestroyView, CommentListCreateView,\
ToggleLikeView

urlpatterns = [
    path('', PostListCreateView.as_view(), name='post-list-create'),
    path('<int:pk>/', PostRetrieveUpdateDestroyView.as_view(), name='post-detail'),
    path('<int:post_id>/comments/', CommentListCreateView.as_view(), name='comment-list-create'),
    path('<int:post_id>/like/', ToggleLikeView.as_view(), name='toggle-like'),
]