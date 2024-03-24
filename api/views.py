from .models import CustomUser
from .serializers import UserSerializer
from rest_framework import status
from django.core.mail import EmailMessage
from django.contrib.auth import authenticate
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.exceptions import ObjectDoesNotExist
from django.template.loader import render_to_string
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from .tokens import account_activation_token


def send_activation_email(user):
    try:
        subject = 'Activate Your Account'
        message = render_to_string('verification_email.html', {
            'user': user,
            'domain': 'http://localhost:8080',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
        })
        email = EmailMessage(subject, message, to=[user.email])
        email.content_subtype = 'html'
        email.send()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resend_verification_email(request):
    data = request.data
    try:
        username = data.get('username', '')
        user = CustomUser.objects.get(username=username)
        if send_activation_email(user):
            return Response({'message': 'Verification email send successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': "Couldn't send email!"}, status=status.HTTP_400_BAD_REQUEST)
    except ObjectDoesNotExist:
        return Response({'message': 'User does not exist!'}, status=status.HTTP_404_NOT_FOUND)    
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def token_test(request):
    return Response({'message': 'Token is valid!'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def username_change(request):
    data = request.data
    try: 
        new_username = data.get('new_username', '')
        username = data.get('username', '')
        user = CustomUser.objects.get(username=username)
        user.nickname = new_username
        user.save()
        return Response({'message': 'Username changed successfully!'}, status=status.HTTP_200_OK)
    except ObjectDoesNotExist:
        return Response({'message': 'User does not exist!'}, status=status.HTTP_404_NOT_FOUND)    
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password_change(request):
    data = request.data
    try:
        username = data.get('username', '')
        password = data.get('password', '')
        new_password = data.get('new_password', '')
        
        user = CustomUser.objects.get(username=username)
        
        if not authenticate(username=user.username, password=password):
            return Response({'message': 'Current password is incorrect!'}, status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(new_password)
        user.save()
        return Response({'message': 'Password changed successfully!'}, status=status.HTTP_200_OK)
    except ObjectDoesNotExist:
        return Response({'message': 'User does not exist!'}, status=status.HTTP_404_NOT_FOUND)    
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_delete(request):
    data = request.data
    try:
        username = data.get('username', '')
        password = data.get('password', '')
        user = CustomUser.objects.get(username=username)

        if user.check_password(password):
            user.delete()
            return Response({'message': 'User deleted successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid password!'}, status=status.HTTP_400_BAD_REQUEST)
    except ObjectDoesNotExist:
        return Response({'message': 'User does not exist!'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def email_verification(request):
    data = request.data
    try:
        verification_token = data.get('token', '')
        user_id = data.get('user_id', '')
        try:
            decoded_user_id = urlsafe_base64_decode(user_id)
        except TypeError:
            print('123')
            return Response({'message': 'Invalid verification link!'}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.get(pk=decoded_user_id)

        if user and account_activation_token.check_token(user, verification_token):
            user.is_email_verified = True
            user.save()
            return Response({'message': 'Email verified successfully!'}, status=status.HTTP_200_OK)
        else:
            print('321')
            return Response({'message': 'Invalid verification link!'}, status=status.HTTP_400_BAD_REQUEST)

    except CustomUser.DoesNotExist:
        print('opr')
        return Response({'message': 'Invalid verification link!'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def signup(request):
    data = request.data
    try:
        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            CustomUser.objects.create_user(
                username=data.get('username', ''),
                email=data.get('email', ''),
                password=data.get('password', '')
            )
            user = CustomUser.objects.get(username=data.get('username', ''))
            user.nickname = data.get('username', '')
            user.save()

            if send_activation_email(user):
                return Response({'message': 'User created successfully!'}, status=status.HTTP_201_CREATED)
            else:
                return Response({'message': 'User created successfully!', 'email': 'Email not send!'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
