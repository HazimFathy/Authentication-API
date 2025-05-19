import random
from django.contrib.auth import authenticate, get_user_model
from django.core.cache import cache
from django.utils import timezone
from django.core.mail import send_mail
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password



User = get_user_model()

class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)
    
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("The passwords don't match.")
        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError({"username": "Username already taken"})
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({"email": "Email address already exists"})
        return data
    
    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user
    
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(min_length=8)
    password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)
        
    def validate(self, attrs):
        user = self.context['request'].user
        old_password = attrs.get('old_password')
        
        if not check_password(old_password, user.password):
            raise serializers.ValidationError({"error":"old password miss match"})
        
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"error": "Passwords do not match."})
        
        
        if old_password == attrs['password'] :
            raise serializers.ValidationError({"error":"New password must be different from the old password."})
        
        return attrs
    
    def save(self, **kwargs):
        user = self.context['request'].user
        password = self.validated_data['password']
        user.set_password(password)
        user.save()
        return user
    
class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField()
    password = serializers.CharField(write_only=True)
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, attrs):
        username_or_email = attrs.get('username_or_email')
        password = attrs.get('password')

        
        user = None
        if '@' in username_or_email:
            try:
                user_obj = User.objects.get(email=username_or_email)
                username = user_obj.username
            except User.DoesNotExist:
                raise serializers.ValidationError("No user with this email.")
        else:
            username = username_or_email

        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError("invaild Username or Password.")


        refresh = RefreshToken.for_user(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
     
class UserDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "username",
        )
        
class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate(self, attrs):
        email = attrs.get('email')
        
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("User with this email not found.")
        user = User.objects.get(email=email)
        
        if user.profile.request_new_otp():
            raise serializers.ValidationError("You can request a new OTP after 1.5 minutes.")
        return attrs
        
    def save(self, **kwargs):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        otp = random.randint(1000, 9999)
        
        user_profile = user.profile
        user_profile.otp = otp
        user_profile.otp_created_at = timezone.now()
        user_profile.save()
        
        send_mail(
            subject="Your OTP Number to reset your password.",
            message=f"Your OTP number is: {otp},It's valid for 10 minutes",
            from_email="hazimfathy977@gmail.com",
            recipient_list=[email],
        )
        
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    password = serializers.CharField(min_length=8)
    confirm_password = serializers.CharField(min_length=8)
    
    def validate(self, attrs):
        email = attrs.get('email')
        otp = attrs.get('otp')
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        
        try:
            user = User.objects.get(email=email)
            user_profile = user.profile
        except ObjectDoesNotExist:
            raise serializers.ValidationError({"error": "User or profile not found."})
        
        if user_profile.is_otp_expired():
            raise serializers.ValidationError({"error":"OTP has expired. Please request a new one."})
        
        if str(user_profile.otp) != str(otp):
            raise serializers.ValidationError({"error": "Invalid OTP number."})
        
        if password != confirm_password:
            raise serializers.ValidationError({"error":"passwords don't match."})
        
        self.user = user
        self.user_profile = user_profile
        return attrs
    
    def save(self, **kwargs):
        password = self.validated_data['password']
        
        self.user.set_password(password)
        self.user.save()
        
        self.user_profile.otp = None
        self.user_profile.otp_created_at = None
        self.user_profile.save()

        return self.user
    
        
        
        
        
        
        