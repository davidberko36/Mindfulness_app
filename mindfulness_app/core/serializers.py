from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from .models import User, AudioTrack, ScheduledSession, FriendRequest
from django.contrib.auth.password_validation import validate_password
from django.core.files.base import ContentFile
import base64
import uuid
from django.conf import settings
from cloudinary.uploader import upload



User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'last_name', 'first_name', 'username', 'email', 'is_active', 'is_staff', 'is_superuser',
                  'gender', 'profile_image', 'date_of_birth', 'phone_number' )


class UserSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'username', 'first_name', 'last_name', 'phone_number')
        read_only_fields = ('email',)


class UserCreateSerializer(serializers.ModelSerializer):
    profile_image = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'first_name', 'last_name', 'username', 'is_active', 'is_superuser', 'gender',
                  'profile_image', 'date_of_birth', 'phone_number')
        extra_kwargs = {'username': {'required': False}}

    def create(self, validated_data):
        profile_image_data = validated_data.pop('profile_image', None)
        password = validated_data.pop('password')
        is_superuser = validated_data.pop('is_superuser', False)
        email = validated_data.pop('email')

        if is_superuser:
            user = User.objects.create_superuser(email, password, **validated_data)
        else:
            user = User.objects.create_user(email, password, **validated_data)

        if profile_image_data:
            self.save_profile_image(user, profile_image_data)

        return user

    def save_profile_image(self, user, profile_image_data):
        if isinstance(profile_image_data, str) and profile_image_data.startswith('data:image'):
            format, imgstr = profile_image_data.split(';base64,')
            ext = format.split('/')[-1]

            # Upload to Cloudinary
            result = upload(profile_image_data)

            # Save the Cloudinary URL to the user's profile_image field
            user.profile_image = result['url']
            user.save()

    def validate(self, data):
        if not data.get('email'):
            raise serializers.ValidationError("Email is required")
        if not data.get('first_name'):
            raise serializers.ValidationError("First name is required")
        if not data.get('last_name'):
            raise serializers.ValidationError("Last name is required")
        return data


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            if not user:
                raise serializers.ValidationError('Invalid email or password.')
        else:
            raise serializers.ValidationError('Email and password are required.')

        data['user'] = user
        return data


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value


class AudioTrackSerializer(serializers.ModelSerializer):
    class Meta:
        model = AudioTrack
        fields = '__all__'


class ScheduledSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScheduledSession
        fields = '__all__'


class FriendRequestSerializer(serializers.ModelSerializer):
    sender = UserSerializer()
    recipient = UserSerializer()

    class Meta:
        model = FriendRequest
        fields = ['id', 'sender', 'recipient', 'status', 'created_at']

