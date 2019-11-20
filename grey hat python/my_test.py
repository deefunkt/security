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

    thread_list = debugger.enumerate_threads()
    for thread in thread_list:
        thread_context = debugger.get_thread_context(thread)
        if not thread_context:
            # Now let's output the contents of some of the registers
            print("[*] Dumping registers for thread ID: 0x%08x", thread)
            print("[**] RAX: {}".format(thread_context.RAX)) 
            print("[**] RCX: {}".format(thread_context.RCX)) 
            print("[**] RDX: {}".format(thread_context.RDX)) 
            print("[**] R8: {}".format(thread_context.R8)) 
            print("[**] R9: {}".format(thread_context.R9)) 
            print("[**] R10: {}".format(thread_context.R10)) 
            print("[**] R11: {}".format(thread_context.R11))            
            print("[**] RBX: {}".format(thread_context.RBX)) 
            print("[**] RBP: {}".format(thread_context.RBP)) 
            print("[**] RDI: {}".format(thread_context.RDI)) 
            print("[**] RSI: {}".format(thread_context.RSI)) 
            print("[**] RSP: {}".format(thread_context.RSP)) 
            print("[**] R12: {}".format(thread_context.R12)) 
            print("[**] R13: {}".format(thread_context.R13)) 
            print("[**] R14: {}".format(thread_context.R14)) 
            print("[**] R15: {}".format(thread_context.R15))
            print("[*] END DUMP")

finally:
    debugger.detach()

