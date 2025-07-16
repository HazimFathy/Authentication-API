from django.shortcuts import render
from django.contrib.auth.models import User
from rest_framework import mixins, viewsets , status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from .serializers import (
    RegisterSerializer,
    UserDataSerializer,
    ChangePasswordSerializer,
    LoginSerializer,
    SendOTPSerializer,
    ResetPasswordSerializer,
)


class UserViewSet(mixins.RetrieveModelMixin,viewsets.GenericViewSet):
    
    queryset = User.objects.all()
    serializer_class = UserDataSerializer

    def get_serializer_class(self):
        if self.action == "signup":
            return RegisterSerializer
        if self.action == "change_password":
            return ChangePasswordSerializer
        if self.action == "login":
            return LoginSerializer
        if self.action == "request_otp":
            return SendOTPSerializer
        if self.action == "reset_password":
            return ResetPasswordSerializer
        return super().get_serializer_class()

    @action(methods=["post"], detail=False)
    def signup(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail': 'User created successfully'}, status=201)

    @action(methods=["get"], detail=False, permission_classes=[IsAuthenticated])
    def get_me(self, request):
        user = request.user
        serializer = self.get_serializer(user)
        return Response(serializer.data)
    
    @action(methods=['post'], detail=False, permission_classes=[IsAuthenticated])
    def change_password(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail": "Your password has been updated."}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['post'])
    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)
    
    @action(methods=['post'], detail=False)
    def request_otp(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail":"OTP has been sent to your email."},status=status.HTTP_200_OK)
    
    @action(methods=['post'], detail=False)
    def reset_password(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"detail":"you have reset your password Successfully."},status=status.HTTP_200_OK)
