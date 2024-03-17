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
    return Response({'message': 'Token is valid!'}, status=status.HTTP_200_OK)


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
            return Response({'message': 'Invalid verification link!'}, status=status.HTTP_400_BAD_REQUEST)

        user = CustomUser.objects.get(pk=decoded_user_id)

        if user and default_token_generator.check_token(user, verification_token):
            user.is_email_verified = True
            user.save()
            return Response({'message': 'Email verified successfully!'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid verification link!'}, status=status.HTTP_400_BAD_REQUEST)

    except CustomUser.DoesNotExist: 
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
            user.full_clean()
            user.save()
            
            try:
                subject = 'Activate Your Account'
                message = render_to_string('verification_email.html', {
                    'user': user,
                    'domain': 'http://localhost:8080',
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                })
                email = EmailMessage(subject, message, to=[user.email])
                email.content_subtype = 'html'
                email.send()
            except Exception:
                return Response({'message': 'User created successfully!', 'email': 'Email not send!'}, status=status.HTTP_201_CREATED)

            return Response({'message': 'User created successfully!'}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'message': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
