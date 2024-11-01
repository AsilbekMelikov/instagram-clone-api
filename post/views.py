from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from .models import Post, PostLike, PostComment, CommentLike
from .serializers import PostSerializer, PostLikeSerializer, PostCommentSerializer, CommentLikeSerializer
from rest_framework import generics
from shared.custom_pagination import CustomPagination

# Create your views here.

class PostListApiView(generics.ListAPIView):
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticatedOrReadOnly, ]
    pagination_class = CustomPagination

    def get_queryset(self):
        return Post.objects.all()


class PostCreateApiView(generics.CreateAPIView):
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated, ]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class PostRetrieveUpdateDestroy(generics.RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticatedOrReadOnly, ]

    def put(self, request, *args, **kwargs):
        post = self.get_object()
        serializer = self.serializer_class(post, data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer.save()
        return Response(serializer.data)

    def delete(self, request, *args, **kwargs):
        post = self.get_object()
        post.delete()

        return Response({
            "success": True,
            "code": status.HTTP_204_NO_CONTENT,
            "message": "Post successfully deleted",
        })


class PostCommentListApiView(generics.ListAPIView):
    serializer_class = PostCommentSerializer
    permission_classes = [AllowAny, ]
    pagination_class = CustomPagination
    queryset = PostComment.objects.all()

    def get_queryset(self):
        return self.queryset

# Give the post id in the URL

# class PostCommentCreateApiView(generics.CreateAPIView):
#     serializer_class = PostCommentSerializer
#     permission_classes = [IsAuthenticated, ]
#
#     def perform_create(self, serializer):
#         serializer.save(author=self.request.user)
#
#         return serializer.data


class PostCommentCreateApiView(generics.CreateAPIView):
    serializer_class = PostCommentSerializer
    permission_classes = [IsAuthenticated, ]

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class PostLikeListApiView(generics.ListCreateAPIView):
    serializer_class = PostLikeSerializer
    permission_classes = [IsAuthenticated, ]

    def get_queryset(self):
        return PostLike.objects.all()

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class PostLikeApiView(APIView):
    permission_classes = [IsAuthenticated, ]

    def post(self, request):
        post_id = self.request.data['post']
        user = self.request.user
        try:
            post_liking = PostLike.objects.get(author=user, post_id=post_id)
            post_liking.delete()
            data = {
                "success": True,
                "message": "You have successfully deleted the love in the post",
            }
            return Response(data, status=status.HTTP_204_NO_CONTENT)
        except PostLike.DoesNotExist:
            post_liking = PostLike.objects.create(author=user, post_id=post_id)
            serializer = PostLikeSerializer(post_liking)
            data = {
                "success": True,
                "message": "You have successfully loved the post",
                "data": serializer.data
            }
            return Response(data, status=status.HTTP_201_CREATED)








