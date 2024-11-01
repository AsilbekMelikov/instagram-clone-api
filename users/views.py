from datetime import datetime

from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework import permissions
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from shared.utility import send_email, check_email_or_phone
from .serializers import SignUpSerializer, ChangeUserInformation, ChangePhotoSerializer, LoginSerializer, \
    LoginRefreshSerializer, LogoutSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from .models import User, NEW, CODE_VERIFIED, VIA_EMAIL, VIA_PHONE


# Create your views here.

class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = SignUpSerializer

class VerifyAPIView(APIView):
    # permission_classes = (IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        user = self.request.user
        code = self.request.data.get('code')

        self.check_verification(user, code)
        return Response({
            "status": True,
            "auth_status": user.auth_status,
            "access": user.token()['access'],
            "refresh": user.token()['refresh_token']
        })

    @staticmethod
    def check_verification(user, code):
        user_confirmation = user.verify_codes.filter(expiration_time__gte=datetime.now(), code=code, is_confirmed=False)

        if not user_confirmation.exists():
            data = {
                "message": "Tasdiqlash kodingiz xato yoki eskirgan yoki siz bu bosqichdan o'tgansiz"
            }
            raise ValidationError(data)

        user_confirmation.update(is_confirmed=True)
        if user.auth_status == NEW:
            user.auth_status = CODE_VERIFIED
            user.save()
        return True


class SendCodeAgainAPIView(APIView):

    def get(self, request, *args, **kwargs):
        user = self.request.user

        self.check_verification(user)

        if user.auth_status == NEW:
            if user.auth_type == VIA_EMAIL:
                code = user.create_verify_code(VIA_EMAIL)
                send_email(user.email, code)
            elif user.auth_type == VIA_PHONE:
                code = user.create_verify_code(VIA_PHONE)
                send_email(user.phone_number, code)
        else:
            raise ValidationError({
                "message": "Siz allaqachon keyingi bosqichga o'tgansiz"
            })
        return Response(
            {
                "success": True,
                "message": "Tasdiqlash kodingiz qaytadan jo'natildi"
            }
        )


    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)

        if verifies.exists():
            raise ValidationError({
                "message": "Sizga allaqachon code yuborilgan. Agar qabul qilmagan bo'lsangiz, kod eskirishini kuting"
            })

class ChangeUserInformationView(UpdateAPIView):
    serializer_class = ChangeUserInformation
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, **kwargs)

        return Response({
            "success": True,
            "message": "User updated successfully",
            "auth_status": self.request.user.auth_status
        }, status=200)

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, **kwargs)

        return Response({
            "success": True,
            "message": "User updated successfully",
            "auth_status": self.request.user.auth_status
        }, status=200)


class ChangePhotoView(APIView):


    def put(self, request, *args, **kwargs):
        serializer = ChangePhotoSerializer(data=self.request.data)

        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)

            return Response({
                "message": "Photo updated successfully"
            }, status=200)
        return Response(serializer.errors, status=400)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer

class LogoutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)

        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                "success": True,
                "message": "You are logged out"
            }
            return Response(data, status=205)
        except TokenError:
            return Response(status=400)


class ForgotPasswordView(APIView):
    permission_classes = [AllowAny, ]
    serializer_class = ForgotPasswordSerializer


    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        email_or_phone = serializer.validated_data.get('email_or_phone')
        user = serializer.validated_data.get('user')
        code_type = check_email_or_phone(email_or_phone)

        if code_type == 'email':
            code = user.create_verify_code(VIA_EMAIL)
            send_email(email_or_phone, code)
        elif code_type == 'phone':
            code = user.create_verify_code(VIA_PHONE)
            send_email(email_or_phone, code)
        else:
            raise ValidationError({
                "success": False,
                "message": "Your input is neither email, nor phone number"
            })

        return Response({
            "success": True,
            "message": "Verification code has been sent successfully",
            "access": user.token()['access'],
            "refresh": user.token()['refresh_token'],
            "auth_status": user.auth_status
        }, status=200)


class ResetPasswordView(UpdateAPIView):
    permission_classes = [IsAuthenticated, ]
    serializer_class = ResetPasswordSerializer
    http_method_names = ['put', 'patch']

    def get_object(self):
        return self.request.user

    def put(self, request, *args, **kwargs):
        super(ResetPasswordView, self).update(request, *args, **kwargs)

        return Response({
            "success": True,
            "message": "Your password updated successfully",
            "auth_status": self.request.user.auth_status
        }, status=200)

    def partial_update(self, request, *args, **kwargs):
        super(ResetPasswordView, self).update(request, *args, **kwargs)

        return Response({
            "success": True,
            "message": "Your password updated successfully",
            "auth_status": self.request.user.auth_status
        }, status=200)


































