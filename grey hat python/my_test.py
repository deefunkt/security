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
        # Now let's output the contents of some of the registers
        print("[*] Dumping registers for thread ID: 0x%08x", thread)
        print("[**] EIP: 0x%08x", thread_context.Eip)
        print("[**] ESP: 0x%08x", thread_context.Esp)
        print("[**] EBP: 0x%08x", thread_context.Ebp)
        print("[**] EAX: 0x%08x", thread_context.Eax)
        print("[**] EBX: 0x%08x", thread_context.Ebx)
        print("[**] ECX: 0x%08x", thread_context.Ecx)
        print("[**] EDX: 0x%08x", thread_context.Edx)
        print("[*] END DUMP")

finally:
    debugger.detach()

