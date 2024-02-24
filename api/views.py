from .models import CustomUser
from .serializers import UserSerializer
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

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
            # Delete the user
            user.delete()
            return Response({'message': 'User deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)
    except ObjectDoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
        return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)