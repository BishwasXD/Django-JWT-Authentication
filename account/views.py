from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

from account.renderers import UserRenderer
from account.serializers import UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer, UserChangePasswordSerializer, SendPasswordResetEmailSerializer


"""Generates token"""
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request):
        serializer = UserRegistrationSerializer(data = request.data) 
        print('this is userdata: ', request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token' : token, 'message' : "User Registered Successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request):
        serializer = UserLoginSerializer(data = request.data)
        serializer.is_valid()
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        user = authenticate(email = email, password = password)
        if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token' : token, 'message':'User logged in successfully'}, status=status.HTTP_202_ACCEPTED)
        return Response({'message' : 'Following credentials didnot matched'}, status=status.HTTP_404_NOT_FOUND)
        
                
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]

    """worked without this aswell, dont know why"""
    #permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
 
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = UserChangePasswordSerializer(data = request.data, context = {'user' : request.user})
        if serializer.is_valid():
            return Response({'messsage' : 'password changed successfully'}, status = status.HTTP_200_OK )
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
      

class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
      serializer = SendPasswordResetEmailSerializer(data = request.data)
      serializer.is_valid(raise_exception=True)
      return Response({'message' : 'password reset link sent successfully, check your email'}, status=status.HTTP_200_OK)


