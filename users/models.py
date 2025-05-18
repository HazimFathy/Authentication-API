from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
# Create your models here.


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    
    def is_otp_expired(self):
        if not self.otp_created_at:
            return True
        return timezone.now() > self.otp_created_at + timedelta(minutes=10)
    
    def request_new_otp(self):
        if not self.otp_created_at :
            return True  
        return timezone.now() < self.otp_created_at + timedelta(minutes=1.5)
    