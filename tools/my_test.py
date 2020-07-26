# -*- coding: utf-8 -*-
"""
Created on Thu Nov 14 18:21:50 2019

@author: deefunkt
"""
import my_debugger

debugger = my_debugger.debugger()
pid = input('Enter PID of process to debug: ')
debugger.attach(int(pid))
try:
    wprintf_address = debugger.get_function_address('msvcrt.dll', 'wprintf')
    print("Address of wprintf is {}".format(wprintf_address))
    debugger.bp_set(wprintf_address)
    debugger.run()

except Exception as e:
    print(e.message)
finally:
    debugger.detach()

