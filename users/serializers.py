from pickle import FALSE

from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.validators import FileExtensionValidator
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken

from shared.utility import check_email_or_phone, send_email, check_email_username_phone
from .models import User, UserConfirmation, VIA_PHONE, VIA_EMAIL, \
    NEW, CODE_VERIFIED, DONE, PHOTO_STEP
from rest_framework import exceptions, serializers
from django.db.models import Q
from rest_framework.exceptions import ValidationError, PermissionDenied, NotFound


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    # auth_type = serializers.CharField(read_only=True, required=False)  Bu yerda ham yozish mumkin edi

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status',
        )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': False},
            'auth_status': {'read_only': True, 'required': False},
        }

    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        # user -> email -> email jo'natish
        # user -> phone -> phone jo'natish
        if user.auth_type == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
            # send_phone(user.phone_number, code)
        user.save()
        return user


    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)

        return data

    @staticmethod
    def auth_validate(data):
        user_input = str(data.get('email_phone_number')).lower()
        input_type = check_email_or_phone(user_input)

        if input_type == 'email':
            data = {
                "email": user_input,
                "auth_type": VIA_EMAIL
            }
        elif input_type == "phone":
            data = {
                "phone_number": user_input,
                "auth_type": VIA_PHONE
            }
        else:
            data = {
                "status": False,
                "message": "You must send email or phone number"
            }
            raise ValidationError(data)
        return data

    def validate_email_phone_number(self, email_or_phone):
        email_or_phone = email_or_phone.lower()

        if email_or_phone and User.objects.filter(email=email_or_phone).exists():
            raise ValidationError({
                "status": False,
                "message": "Email bir xil bo'lishi mumkin emas, boshqa email kiriting"
            })
        elif email_or_phone and User.objects.filter(phone_number=email_or_phone).exists():
            raise ValidationError({
                "status": False,
                "message": "Phone number bir xil bo'lishi mumkin emas, boshqa phone number kiriting"
            })
        return email_or_phone

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(instance.token())

        return data


class ChangeUserInformation(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    username = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        password = data.get('password', None)
        confirm_password = data.get('confirm_password', None)

        if password and confirm_password:
            if password != confirm_password:
                raise ValidationError({
                    "message": "Parollar bir-biriga mos emas."
                })
        if password:
            validate_password(password)

        return data

    def validate_username(self, username):
        n = len(username)
        if n < 5 or n > 30:
            raise ValidationError({
                "message": "Username must be between 5 and 30 characters"
            })
        if username.isdigit():
            raise ValidationError({
                "message": "This username is entirely numeric"
            })

        if User.objects.filter(username=username).exists():
            raise ValidationError({
                "message": "Username is occupied, enter another one"
            })

        return username

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)
        instance.password = validated_data.get('password', instance.password)

        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        if instance.auth_status == CODE_VERIFIED:
            instance.auth_status = DONE

        instance.save()
        return instance


class ChangePhotoSerializer(serializers.Serializer):
    photo = serializers.ImageField(validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'heif', 'heic'])])

    def update(self, instance, validated_data):

        if validated_data.get('photo'):
            instance.photo =validated_data.get('photo', instance.photo)
            instance.auth_status = PHOTO_STEP
            instance.save()
        return instance

class LoginSerializer(TokenObtainPairSerializer):

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['user_input'] = serializers.CharField(required=True)
        self.fields['username'] = serializers.CharField(required=False, read_only=True)

    # def validate(self, data):
    #

    def auth_validate(self, data):
        user_input = data.get('user_input')
        user_input_type = check_email_username_phone(user_input)

        if user_input_type == 'email':
            user = self.get_user(email__iexact=user_input)
            self.check_user_status(user.auth_status)
            username = user.username
        elif user_input_type == 'phone':
            user = self.get_user(phone_number=user_input)
            self.check_user_status(user.auth_status)
            username = user.username
        elif user_input_type == 'username':
            self.get_user(username=user_input)
            username = user_input
        else:
            raise ValidationError({
                "message": "Email, Phone yoki Username to'g'ri kiriting"
            })

        authentication_kwargs = {
            self.username_field: username,
            "password": data['password']
        }
        user = authenticate(**authentication_kwargs)

        if user is not None:
            self.user = user
        else:
            raise ValidationError({
                "message": "Please, check your credentials again because they are incorrect"
            })

    def validate(self, data):
        self.auth_validate(data)
        if self.user.auth_status not in [DONE, PHOTO_STEP]:
            raise PermissionDenied("Siz login qila olmaysiz, ruxsatnomangiz yo'q, to'liq ro'yhatdan o'ting")

        data = self.user.token()
        data['auth_status'] = self.user.auth_status
        data['full_name'] = self.user.full_name
        return data

    def get_user(self, **kwargs):
        users = User.objects.filter(**kwargs)
        if not users.exists():
            raise ValidationError({
                "message": "No active users found"
            })
        return users.first()

    def check_user_status(self, user_status):
        if user_status in [NEW, CODE_VERIFIED]:
            raise ValidationError({
                "message": "You haven't entirely registered yet, so you can't log in"
            })

class LoginRefreshSerializer(TokenRefreshSerializer):

    def validate(self, attr):
        data = super().validate(attr)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)

        return data

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class ForgotPasswordSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        email_or_phone = attrs.get('email_or_phone', None)

        if email_or_phone is None:
            raise ValidationError({
                "message": "Email yoki phone number is required"
            })

        user = User.objects.filter(Q(phone_number=email_or_phone) | Q(email=email_or_phone))

        if not user.exists():
            raise NotFound(detail="No active users found")
        attrs['user'] = user.first()
        return attrs

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)


    def validate(self, attrs):
        password = attrs.get('password', None)
        confirm_password = attrs.get('confirm_password', None)

        if password and confirm_password:
            if password != confirm_password:
                raise ValidationError({
                    "message": "Your passwords don't match with each other"
                })
        if password:
            validate_password(password)

        return attrs

    def update(self, instance, validated_data):
        instance.password = validated_data.get('password', instance.password)

        if validated_data.get('password'):
            instance.set_password(validated_data.get('password'))
        instance.save()

        return instance



