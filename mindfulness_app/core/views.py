from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.views import APIView
from django.contrib.auth import login, logout
from .serializers import UserCreateSerializer, LoginSerializer, AudioTrackSerializer, ScheduledSessionSerializer, UserSerializer, UserSettingsSerializer, PasswordChangeSerializer
from django.contrib.auth import authenticate
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import AccessToken
# from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from .models import AudioTrack, ScheduledSession, User, FriendRequest
from django.shortcuts import get_object_or_404
import logging
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated

logger = logging.getLogger(__name__)


@api_view(['POST'])
def signup_view(request):
    logger.info("Received signup request")
    if request.method == 'POST':
        logger.info(f"Request data: {request.data}")
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            logger.info("Serializer is valid")
            try:
                user = serializer.save()
                logger.info(f"User created: {user.email}")
                return Response({
                    'message': 'User created successfully',
                    'user': UserCreateSerializer(user).data
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error creating user: {str(e)}")
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        logger.warning(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@csrf_exempt
@api_view(['POST'])
def login_view(request):
    if request.method == 'POST':
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.validated_data['user']
            login(request, user)  # This logs the user in (using Django session)

            # Get the JWT token
            token = get_token_for_user(user)

            return Response({
                'message': 'Login successful',
                'user': UserCreateSerializer(user).data,
                'token': token
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def get_token_for_user(user):
    access_token = AccessToken.for_user(user)
    return str(access_token)


@api_view(['POST'])
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserSettingsView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSettingsSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)


class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if user.check_password(serializer.data.get('old_password')):
                user.set_password(serializer.data.get('new_password'))
                user.save()
                return Response({'message': 'Password updated successfully.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'POST'])
def audio_track_list(request):
    if request.method == 'GET':
        tracks = AudioTrack.objects.all()
        serializer = AudioTrackSerializer(tracks, many=True)

        # Concatenate the full Cloudinary URL for each track's audio field
        cloudinary_prefix = "https://res.cloudinary.com/dkpnqajrx/"
        for track_data in serializer.data:
            # Modify the 'audio' field to include the full URL
            track_data['audio'] = f"{cloudinary_prefix}{track_data['audio']}"

        return Response(serializer.data)

    if request.method == 'POST':
        serializer = AudioTrackSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def audio_track_detail(request, title):
    try:
        track = AudioTrack.objects.get(title=title)
    except AudioTrack.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = AudioTrackSerializer(track)
        return Response(serializer.data)

    if request.method == 'PUT':
        serializer = AudioTrackSerializer(track, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'DELETE':
        track.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ScheduledSession Views

@api_view(['GET', 'POST'])
def session_list(request):
    if request.method == 'GET':
        sessions = ScheduledSession.objects.all()
        serializer = ScheduledSessionSerializer(sessions, many=True)
        return Response(serializer.data)

    if request.method == 'POST':
        serializer = ScheduledSessionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def session_detail(request, pk):
    try:
        session = ScheduledSession.objects.get(pk=pk)
    except ScheduledSession.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = ScheduledSessionSerializer(session)
        return Response(serializer.data)

    if request.method == 'PUT':
        serializer = ScheduledSessionSerializer(session, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == 'DELETE':
        session.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['POST'])
def send_friend_request(request, recipient_id):
    recipient = get_object_or_404(User, id=recipient_id)
    friend_request, created = FriendRequest.objects.get_or_create(
        sender=request.user,
        recipient=recipient
    )
    
    if not created:
        return Response({"message": "Friend request already sent."}, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({"message": "Friend request sent."}, status=status.HTTP_201_CREATED)


@api_view(['POST'])
def respond_to_friend_request(request, request_id, action):
    friend_request = get_object_or_404(FriendRequest, id=request_id, recipient=request.user)

    if action == 'accept':
        friend_request.status = 'accepted'
        friend_request.sender.add_friend(friend_request.recipient)
        friend_request.save()
        return Response({"message": "Friend request accepted."}, status=status.HTTP_200_OK)

    elif action == 'reject':
        friend_request.status = 'rejected'
        friend_request.save()
        return Response({"message": "Friend request rejected."}, status=status.HTTP_200_OK)

    return Response({"message": "Invalid action."}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def friends_list(request, user_id):
    user = get_object_or_404(User, id=user_id)
    friends = user.friends.all()
    serializer = UserSerializer(friends, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)
