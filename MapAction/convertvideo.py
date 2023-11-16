import glob
import subprocess
from django.conf import settings

mp4List = glob.glob("/var/www/actionmap-django/uploads/*.mp4")
movList = glob.glob("/var/www/actionmap-django/uploads/*.mov")
print("mov list")
print(movList)
print("mp4 list")
for mp in movList:

    print(mp[:-4]+".mov")
    if mp[:-4]+".mp4" not in mp4List:
        subprocess.check_call(['ffmpeg', '-i', mp,  '-vcodec', 'h264' , mp[:-4]+'.mp4'])
    else:
        print("file converted")
subprocess.call(['chmod','777', "-R", settings.MEDIA_ROOT])
