from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import UserSerializer
from .models import CustomUser


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