from ctypes import cdll
import time

msvcrt = cdll.msvcrt
counter = 0

while(1):
    msvcrt.wprintf('Loop iteration {} \n'.format(counter))
    time.sleep(2)
    counter += 1
    