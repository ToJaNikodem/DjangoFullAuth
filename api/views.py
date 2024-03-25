from .models import CustomUser
from .serializers import UserSerializer, PasswordChangeSerializer, UsernameChangeSerializer, EmailVerificationSerializer, PasswordResetSerializer
from rest_framework import status
from django.utils.http import urlsafe_base64_decode
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from .utils import send_activation_email, send_password_reset_email


@api_view(['POST'])
def signup(request):
    try:
        data = request.data
        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            CustomUser.objects.create_user(
                username=data.get('username', ''),
                email=data.get('email', ''),
                password=data.get('password', ''),
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_delete(request):
    try:
        data = request.data
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
    try:
        data = request.data
        user_id = data.get('user_id', '')
        decoded_user_id = urlsafe_base64_decode(user_id)
        verication_token = data.get('verification_token', '')
        user = CustomUser.objects.get(pk=decoded_user_id)

        serializer = EmailVerificationSerializer(
            data=data, context={'user': user, 'verification_token': verication_token})

        if serializer.is_valid():
            user.is_email_verified = True
            user.save()
            return Response({'message': 'Email verified successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except TypeError:
        return Response({'message': 'Invalid verification link!'}, status=status.HTTP_400_BAD_REQUEST)
    except CustomUser.DoesNotExist:
        return Response({'message': 'Invalid verification link!'}, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resend_verification_email(request):
    try:
        data = request.data
        username = data.get('username', '')
        user = CustomUser.objects.get(username=username)
        if send_activation_email(user):
            return Response({'message': 'Verification email send successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Email sending failed!'}, status=status.HTTP_400_BAD_REQUEST)
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
    try:
        data = request.data
        username = data.get('username', '')
        user = CustomUser.objects.get(username=username)

        serializer = UsernameChangeSerializer(
            data=data, context={'user': user})
        if serializer.is_valid():
            user.nickname = serializer.validated_data['new_nickname']
            user.save()
            return Response({'message': 'Username changed successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except ObjectDoesNotExist:
        return Response({'message': 'User does not exist!'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password_change(request):
    try:
        data = request.data
        username = data.get('username', '')
        user = CustomUser.objects.get(username=username)

        serializer = PasswordChangeSerializer(
            data=data, context={'user': user})
        if serializer.is_valid():
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({'message': 'Password changed successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except ObjectDoesNotExist:
        return Response({'message': 'User does not exist!'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def send_password_reset_email(request):
    try:
        data = request.data
        email = data.get('email', '')
        user = CustomUser.objects.get(email=email)

        if send_password_reset_email(user):
            return Response({'message': 'Password reset email send successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Email sending failed!'}, status=status.HTTP_400_BAD_REQUEST)

    except ObjectDoesNotExist:
        return Response({'message': 'User does not exist!'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def password_reset(request):
    try:
        data = request.data
        user_id = data.get('user_id', '')
        decoded_user_id = urlsafe_base64_decode(user_id)
        reset_token = data.get('reset_token', '')
        user = CustomUser.objects.get(pk=decoded_user_id)

        serilizer = PasswordResetSerializer(
            data=data, context={'user': user, 'reset_token': reset_token})

        if serilizer.is_valid():
            new_password = serilizer.validated_data['new_password']
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password reseted successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid password reset link!'}, status=status.HTTP_400_BAD_REQUEST)
    except TypeError:
        return Response({'message': 'Invalid password reset link!'}, status=status.HTTP_400_BAD_REQUEST)
    except ObjectDoesNotExist:
        return Response({'message': 'User does not exist!'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
