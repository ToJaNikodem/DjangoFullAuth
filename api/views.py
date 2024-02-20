from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate

from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token

from .serializers import UserSerializer

@api_view(['POST'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def logout(request):
    username = request.data.get('username')

    if username:
        user = User.objects.filter(username=username).first()
        if user:
            Token.objects.filter(user=user).delete()
            return Response("Logged out!")
        else:
            return Response("User not found", status=status.HTTP_404_NOT_FOUND)
    else:
        return Response("No username provided", status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['POST'])
def signup(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        user = User.objects.get(username=request.data['username'])
        user.set_password(request.data['password'])
        user.save()
        token = Token.objects.create(user=user)
        return Response({'token': token.key, 'user': serializer.data})
    return Response(serializer.errors, status=status.HTTP_200_OK)

@api_view(['POST'])
def login(request):
    username_or_email = request.data.get('username_or_email', None)
    password = request.data.get('password', None)

    if username_or_email is None or password is None:
        return Response("Username/email and password are required.", status=status.HTTP_400_BAD_REQUEST)

    if '@' in username_or_email:
        user = User.objects.filter(email=username_or_email).first()
    else:
        user = User.objects.filter(username=username_or_email).first()

    user = authenticate(username=user.username, password=password)

    if user is None:
        return Response("Invalid credentials", status=status.HTTP_401_UNAUTHORIZED)

    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(user)
    return Response({'token': token.key, 'user': serializer.data})
# def login(request):
#     user = get_object_or_404(User, username=request.data['username'])
#     if not user.check_password(request.data['password']):
#         return Response("missing user", status=status.HTTP_404_NOT_FOUND)
#     token, created = Token.objects.get_or_create(user=user)
#     serializer = UserSerializer(user)
#     return Response({'token': token.key, 'user': serializer.data})

@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response("passed!")