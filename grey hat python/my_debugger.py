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
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.breakpoints = {}

    def load(self, path_to_exe):
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS
    
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
    
        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        # We then initialize the cb variable in the STARTUPINFO struct
        # Process info stored in struct
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
    
    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting...")
            if kernel32.CloseHandle(self.h_process):
                print("Error closing handle")
            return True
        else:
            print("There was an error.")
            return False
    
    def run(self):
        # Now we poll debuggee for debugging events
        while self.debugger_active:
            self.get_debug_event()

    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(self.h_thread)
            print("Event Code: {},    Thread ID: {}".format(debug_event.dwDebugEventCode, debug_event.dwThreadId))
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print('Access violation exception')
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    # memory breakpoints
                    print('Guard page access exception')
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    # hardware breakpoints
                    print('Single stepping')
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status )

    def exception_handler_breakpoint(self):
        print('[*] Inside the breakpoint handler')
        print('Exception Address: ', self.exception_address)
        return DBG_CONTINUE

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
    
    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,
                                       None,
                                       thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print("[*] Could not obtain valid thread handle")
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

    def dump_thread_context(self, thread_context, thread_id)):
            if thread_context is not None:
                # Now let's output the contents of some of the registers
                print("[*] Dumping registers for thread ID: ", thread_id)
                print("Return (RAX): {}".format(thread_context.Rax))
                print('First 4 integer, pointer args:')
                print("RCX: {},    RDX: {},    R8: {},    R9: {}".format(
                    thread_context.Rcx,
                    thread_context.Rdx,
                    thread_context.R8,
                    thread_context.R9))           
                print("Base Pointer (RBP): {} Stack Pointer (RSP): {}".format(thread_context.Rbp, thread_context.Rsp)) 
                print('Source Index (RSI): {}, Dest Index (RDI): {}'.format(thread_context.Rdi,thread_context.Rsi))
                print("RBX: {}".format(thread_context.Rbx))
                print("R10: {}, R13: {}".format(thread_context.R10, thread_context.R13))
                print("R11: {}, R14: {}".format(thread_context.R11, thread_context.R14)) 
                print("R12: {}, R15: {}".format(thread_context.R12, thread_context.R15)) 
                print("[**] Code Segment (CS): {}".format(thread_context.SegCs)) 
                print("[**] Data Segment (DS): {}".format(thread_context.SegDs)) 
                print("[**] Stack Segment (SS): {}".format(thread_context.SegSs))
                print("[**] Extra Segment (ES): {}".format(thread_context.SegEs))
                # FS contains the Thread Information Block on x86
                print("[**] FS: {}".format(thread_context.SegFs))
                # GS contains the Thread Information Block on x64
                print("[**] GS: {}".format(thread_context.SegGs))
                print("[*] END DUMP")
    
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
    
    def open_process(self, pid):
        return kernel32.OpenProcess(PROCESS_ALL_ACCESS, pid, False)

    def read_process_memory(self, address, length):
        data = ''
        read_buffer = create_string_buffer(length)
        count = c_ulong(0)
        if not kernel32.ReadProcessMemory(self.h_process,
                                            address,
                                            read_buffer,
                                            length,
                                            byref(count)):
            print('Error reading memory address {}'.format(address))
            return False
        else:
            data += read_buffer.raw
            return data
    
    def write_process_memory(self, address, data):
        count = c_ulong(0)
        length = len(data)
        c_data = c_char_p(data[count.value:])
        if not kernel32.WriteProcessMemory(self.h_process,
                                            address,
                                            c_data,
                                            length,
                                            byref(count)):
            print('Error writing to memory address {}'.format(address))
            return False
        else:
            return True

def bp_set(self, address):
    if address not in self.breakpoints:
        try:
            # store original instruction byte and write INT3 opcode
            original_byte = self.read_process_memory(address, 1)
            self.write_process_memory(address, '\xCC')
            # register the breakpoint in internal list
            self.breakpoints[address] = (address, original_byte)
        except:
            print('Error setting breakpoint')
            return False
    print('Breakpoint set at address {}'.format(address))
    return True

def get_function_address(self, dll, function):
    handle = kernel32.GetModuleHandle(dll)
    address = kernel32.GetProcAddress(handle, function)
    kernel32.CloseHandle(handle)
    return address









