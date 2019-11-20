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
        if thread_context is not None:
            # Now let's output the contents of some of the registers
            print("[*] Dumping registers for thread ID: ", thread)
            print("[**] RAX: {}".format(thread_context.Rax)) 
            print("[**] RCX: {}".format(thread_context.Rcx)) 
            print("[**] RDX: {}".format(thread_context.Rdx)) 
            print("[**] R8: {}".format(thread_context.R8)) 
            print("[**] R9: {}".format(thread_context.R9)) 
            print("[**] R10: {}".format(thread_context.R10)) 
            print("[**] R11: {}".format(thread_context.R11))            
            print("[**] RBX: {}".format(thread_context.Rbx)) 
            print("[**] RBP: {}".format(thread_context.Rbp)) 
            print("[**] RDI: {}".format(thread_context.Rdi)) 
            print("[**] RSI: {}".format(thread_context.Rsi)) 
            print("[**] RSP: {}".format(thread_context.Rsp)) 
            print("[**] R12: {}".format(thread_context.R12)) 
            print("[**] R13: {}".format(thread_context.R13)) 
            print("[**] R14: {}".format(thread_context.R14)) 
            print("[**] R15: {}".format(thread_context.R15))
            print("[*] END DUMP")

finally:
    debugger.detach()

