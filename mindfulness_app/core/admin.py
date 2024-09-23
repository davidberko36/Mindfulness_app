from django.contrib import admin
from .models import User, AudioTrack, ScheduledSession, MoodTrack

# Register your models here.
admin.site.register(User)
admin.site.register(AudioTrack)
admin.site.register(ScheduledSession)
admin.site.register(MoodTrack)