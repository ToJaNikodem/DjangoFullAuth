from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from .serializers import UserSerializer
from .models import CustomUser
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

    user = CustomUser.objects.filter(username=username).first()
    if user is not None and user.check_password(password):
        # Delete the user
        user.delete()
        return Response({'message': 'User deleted successfully'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)

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
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)