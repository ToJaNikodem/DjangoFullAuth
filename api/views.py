from .models import CustomUser
from .serializers import UserSerializer
from rest_framework import status
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.exceptions import ObjectDoesNotExist
from django.template.loader import render_to_string
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.tokens import default_token_generator


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def token_test(request):
    return Response(status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_delete(request):
    data = request.data
    username = data.get('username')
    password = data.get('password')

    try:
        user = CustomUser.objects.get(username=username)
        if user.check_password(password):
            user.delete()
            return Response({'message': 'User deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)
    except ObjectDoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def email_verification(request):
    data = request.data
    token = data.get('token')
    user_id = data.get('user_id')
    try:
        uid = urlsafe_base64_decode(user_id)
        user = CustomUser.objects.get(pk=uid)
    except Exception as e:
        return Response({'message': 'error'}, status=status.HTTP_400_BAD_REQUEST)
        

    if default_token_generator.check_token(user, token):
        user.is_email_verified = True
        user.save()
        return Response({'detail': 'Email verified successfully'}, status=status.HTTP_200_OK)
    else:
        return Response({'detail': 'Invalid verification link'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def signup(request):
    data = request.data

    serializer = UserSerializer(data=data)

    if serializer.is_valid():
        CustomUser.objects.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password']
        )
        user = CustomUser.objects.get(username=data['username'])

        try:
            subject = 'Activate Your Account'
            message = render_to_string('verification_email.html', {
                'user': user,
                'domain': 'http://localhost:8080',
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            email = EmailMessage(subject, message, to=[user.email])
            email.content_subtype = "html"
            email.send()
        except Exception as e:
            print (e)
            return Response({'message': 'Email not send'}, status=status.HTTP_200_OK)

        return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
