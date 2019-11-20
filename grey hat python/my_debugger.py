# -*- coding: utf-8 -*-
"""
Created on Thu Nov 14 18:17:08 2019

@author: deefunkt
"""
from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32
class debugger():
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False

    def load(self, path_to_exe):
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS
    
        # instantiate the structs
        startupinfo = STARTUPINFO()
        # returned process information stored here
        process_information = PROCESS_INFORMATION()
    
        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        # We then initialize the cb variable in the STARTUPINFO struct
        # which is just the size of the struct itself
        startupinfo.cb = sizeof(startupinfo)
        if kernel32.CreateProcessW(path_to_exe,
                                    None,
                                    None,
                                    None,
                                    None,
                                    creation_flags,
                                    None,
                                    None,
                                    byref(startupinfo),
                                    byref(process_information)):
            print(f"[*] We have successfully launched the process!")
            print(f"[*] PID: {process_information.dwProcessId}")

            # Obtain and store the process handle
            self.h_process = self.open_process(process_information.dwProcessId)
        else:
            print(f"[*] Error: {kernel32.GetLastError()}")

    def open_process(self, pid):
        return kernel32.OpenProcess(PROCESS_ALL_ACCESS, pid, False)

    def release_handles(self):
        if kernel32.CloseHandle(self.h_process):
            print("Error closing han")

    def attach(self, pid):
        self.h_process = self.open_process(pid)
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            self.run()
        else:
            print("[*] Unable to attach to the process.")

    def run(self):
        # Now we poll debuggee for debugging events
        while self.debugger_active:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            # We aren't going to build any event handlers
            # just yet. Let's just resume the process for now.
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status )

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting...")
            if kernel32.CloseHandle(self.h_process):
                print("Error closing han")
            return True
        else:
            print("There was an error.")
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,
                                       None,
                                       thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print("[*] Could not obtain valid thread handle")
            return False

    def enumerate_threads(self):
        thread_entry = THREADENTRY32()
        thread_list = []
        thread_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,
                                                     self.pid)
        if thread_snapshot is not None:
            # You have to set the size of the struct
            # or the call will fail
            thread_entry.dwSize = sizeof(thread_entry)
            # goto top of struct containing snapshot
            success = kernel32.Thread32First(thread_snapshot,
                                             byref(thread_entry))
            while success:
                # enumerate all threads belonging to process
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(thread_snapshot,
                                                byref(thread_entry))
            kernel32.CloseHandle(thread_snapshot)
            return thread_list
        else:
            return False

    def enumerate_processes(self):
        process_entry = PROCESSENTRY32()
        process_list = []
        process_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,
                                                     self.pid)
        if process_snapshot is not None:
            # You have to set the size of the struct
            # or the call will fail
            process_entry.dwSize = sizeof(process_entry)
            # goto top of struct containing snapshot
            success = kernel32.Process32First(process_snapshot,
                                             byref(process_entry))
            while success:
                # enumerate all threads belonging to process
                if process_entry.th32OwnerProcessID == self.pid:
                    process_list.append(process_entry.th32ThreadID)
                success = kernel32.Process32Next(process_snapshot,
                                                byref(process_entry))
            kernel32.CloseHandle(process_snapshot)
            return process_list
        else:
            return False

    def get_thread_context(self, thread_id):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        # Obtain a handle to the thread
        h_thread = self.open_thread(thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            return None








