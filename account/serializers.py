from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from account.models import User


class UserRegistrationSerializer(serializers.ModelSerializer):

    password2 = serializers.CharField(style = {'input_type':'password'}, write_only = True)
    class Meta:
        model = User
        fields = ['email', 'name', 'tc','password', 'password2']
        extra_kwargs = {
            'password':{'write_only' : True}
        }

    """ validating password and confirm password """
    def validate(self, attrs):
            password = attrs.get('password')
            password2 = attrs.get('password2')
            if password != password2:
                raise serializers.ValidationError('password and confirm password didnt matched')
            return attrs
        
    """ Since we have custom user model we need to overide the default create method provided by the ModelSerializer """
    def create(self, validate_data):     
            return User.objects.create_user(**validate_data)

class UserLoginSerializer(serializers.ModelSerializer):
      class Meta:
            model = User
            fields = ['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
      class Meta:
            model = User
            fields = ['name', 'id', 'email', 'tc']


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(style = {'input_type':'password'}, write_only = True)
    confirm_password = serializers.CharField(style = {'input_type':'password'}, write_only = True)

    def validate(self, attrs):
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            user = self.context.get('user')

            if password != confirm_password:
                raise serializers.ValidationError('password and confirm password didnt matched')
            user.set_password(password)
            user.save()
            return attrs
    
class SendPasswordResetEmailSerializer(serializers.Serializer):
      email = serializers.EmailField(max_length = 255)
      
      def validate(self, attrs):
            email = attrs.get('email')
            if User.objects.filter(email = email).exists():
                  user = User.objecs.get(email = email)
                  uid = urlsafe_base64_encode(force_bytes(user.id))
                  token = PasswordResetTokenGenerator().make_token(user)
                  print('Password reset token: ',token)
                  link = 'http://localhost:3000/reset/' +uid+ '/' +token
                  print(link)
                  return attrs                  
            raise serializers.ValidationError('Email not registered')
            
class changePasswordView(serializers.Serializer):
      pass