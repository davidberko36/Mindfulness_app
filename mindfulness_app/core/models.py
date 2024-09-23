from django.db import models
from django.contrib.auth.models import UserManager, AbstractUser, Group, Permission
from cloudinary.models import CloudinaryField
from django.utils import timezone


# Create your models here.
# class CustomUserManager(UserManager):
#     def create_user(self, email, password, **extra_fields):
#         if not email:
#             raise ValueError('Users must have an email address')
#
#         email = self.normalize_email(email)
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#
#         return user
#
#     def create_superuser(self, email=None, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
#         extra_fields.setdefault('is_active', True)
#         return self.create_user(email, password, **extra_fields)


class CustomUserManager(UserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    last_name = models.CharField(max_length=50, blank=False, null=False)
    first_name = models.CharField(max_length=50, blank=False, null=False)
    username = models.CharField(max_length=30, blank=True, null=True)
    email = models.EmailField(unique=True, blank=False, null=False)
    gender = models.CharField(max_length=20, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    profile_image = CloudinaryField('image', blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    friends = models.ManyToManyField('self', blank=True, symmetrical=True)

    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set',
        blank=True,
        help_text="The groups this user belongs to.",
        verbose_name="groups",
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_permissions_set',
        blank=True,
        help_text="Specific permissions for this user.",
        verbose_name="user permissions",
    )

    objects = CustomUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['last_name', 'first_name']

    def add_friend(self, friend):
        self.friends.add(friend)
        friend.friends.add(self)

    def remove_friend(self, friend):
        self.friends.remove(friend)
        friend.friends.remove(self)

    def __str__(self):
        return self.first_name


class AudioTrack(models.Model):
    title = models.CharField(max_length=30, null=False, blank=False)
    description = models.TextField()
    audio = CloudinaryField('audio', resource_type='video')
    mood = models.CharField(max_length=20)

    def __str__(self):
        return self.title
    

class MoodTrack(models.Model):
    title = models.CharField(max_length=30, null=False, blank=False, unique=True)
    description = models.TextField()
    audio = CloudinaryField('audio', resource_type='video')

    def __str__(self):
        return self.title


class ScheduledSession(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    audio_track = models.ForeignKey(AudioTrack, on_delete=models.SET_NULL, null=True)
    scheduled_time = models.DateTimeField()
    completed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.first_name}'s session at {self.scheduled_time}"


class Playlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, null=False, blank=False)
    description = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}'s playlist, {self.name}"


class PlayListItem(models.Model):
    playlist = models.ForeignKey(Playlist, on_delete=models.CASCADE)
    AudioTrack = models.ForeignKey(AudioTrack, on_delete=models.SET_NULL, null=True)


class FriendRequest(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recipient')
    status = models.CharField(max_length=10, choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected')], default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender.first_name} sent a request to {self.recipient.first_name}"