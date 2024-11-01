from django.urls import path

from post.views import PostListApiView, PostCreateApiView, PostRetrieveUpdateDestroy, PostCommentListApiView, \
    PostCommentCreateApiView, PostLikeListApiView, PostLikeApiView

urlpatterns = [
    path('posts/', PostListApiView.as_view()),
    path('create/', PostCreateApiView.as_view()),
    path('<uuid:pk>/', PostRetrieveUpdateDestroy.as_view()),
    path('comments/', PostCommentListApiView.as_view()),
    path('create-comments/', PostCommentCreateApiView.as_view()),
    path('likes/', PostLikeListApiView.as_view()),
    path('me-liked/', PostLikeApiView.as_view())
]