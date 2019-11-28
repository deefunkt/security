# -*- coding: utf-8 -*-
"""
Created on Thu Nov 14 18:17:08 2019

@author: deefunkt
"""
from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32
class debugger():
    '''This class implements the logic for the debugger object, to be called from
    other modules.
    '''
    def __init__(self):
        '''Intializes default object attributes
        '''
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.thread_list = []
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.breakpoints = {}
        self.first_breakpoints = True
        self.hardware_breakpoints = {}

    def print_system_error(self):
        '''Calls GetLastError and then formats the error message for display
        '''
        dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
        message = create_unicode_buffer(256)
        error = kernel32.GetLastError()
        kernel32.FormatMessageW(dwFlags,
                                None,
                                error,
                                0,
                                message,
                                sizeof(message), None
                                )
        print("Error {}: {}".format(error, message.value))


    def load(self, path_to_exe):
        '''Creates a given process as a new child of the debugger
        '''
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

    def attach(self, pid):
        '''Attaches the debugger to an already running process
        '''
        self.h_process = self.open_process(pid)
        # We attempt to attach to the process
        # if this fails we exit the call
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
        else:
            print("[*] Unable to attach to the process.")
    
    def detach(self):
        '''Detaches the debugger from a debugged process and releases all opened handles
        '''
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting...")
            self.release_handle(all=True)
            return True
        else:
            print("There was an error.")
            return False
    
    def release_handle(self, handle = None, all = False):
        '''Releases specified handle or all handles using CloseHandle 
        '''
        res = 0
        if all:
            res = kernel32.CloseHandle(self.h_process)
            res += kernel32.CloseHandle(self.h_thread)
        if handle is not None:
            res = kernel32.CloseHandle(handle)
        if res > 0:
            print("Error closing handle")    
    
    def run(self):
        '''Runs the debugger and gets debug events
        '''
        # Now we poll debuggee for debugging events
        while self.debugger_active:
            self.get_debug_event()

    def get_debug_event(self):
        '''Processes debug events for access Violations, memory, hardware and regular breakpoints
        and calls the relevant handlers.
        '''
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(debug_event.dwThreadId, h_thread=self.h_thread)
            # print("Event Code: {},    Thread ID: {}".format(debug_event.dwDebugEventCode, debug_event.dwThreadId))
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
                    self.exception_handler_single_step()
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,
                                        debug_event.dwThreadId,
                                        continue_status )

    def exception_handler_breakpoint(self):
        '''The handler for soft breakpoints
        '''
        print('[*] Inside the breakpoint handler')
        print('Exception Address: ', self.exception_address)
        return DBG_CONTINUE

    def exception_handler_single_step(self):
        '''The handler for hardware breakpoints. Deletes the breakpoint after processing.
        '''
        slot = None
        for i in range(4):
            # check to see which hardware breakpoint fired if any
            if (self.context.Dr6 & 2**i) and i in self.hardware_breakpoints.keys():
                slot = i
        if slot is None:
            continue_status = DBG_EXCEPTION_NOT_HANDLED
            return continue_status
        elif self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
        return continue_status
        
    def bp_del_hw(self, slot):
        '''Deletes and disables hardware breakpoints for all active threads in debuggee
        '''
        # disable the breakpoint for all active threads
        for thread in self.thread_list:
            self.open_thread(thread)
            context = self.get_thread_context(thread, h_thread=self.h_thread, close_handle=False)
            # clear breakpoint address
            setattr(context, 'Dr' + str(slot), 0)
            # clear ENABLE flag
            context.Dr7 &= ~(1 << (slot * 2))
            # Remove (toggle) the condition flag
            context.Dr7 &= ~(3 << ((slot * 4) + 16))
            # Remove (toggle) the length flag
            context.Dr7 &= ~(3 << ((slot * 4) + 18))
            # reset the debug status register
            context.Dr6 = 0
            # Reset the thread's context with the breakpoint removed
            kernel32.SetThreadContext(self.h_thread, byref(context))

    def enumerate_threads(self):
        '''Enumerates threads belonging to debuggee using a Toolhelp32 snapshot across the system
        '''
        thread_entry = THREADENTRY32()
        self.thread_list = []
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
                    self.thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(thread_snapshot,
                                                byref(thread_entry))
            self.release_handle(thread_snapshot)
            return self.thread_list
        else:
            return False
    
    def open_thread(self, thread_id):
        '''Opens a given thread
        '''
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,
                                       None,
                                       thread_id)
        if h_thread is not None:
            self.h_thread = h_thread
            return self.h_thread
        else:
            print("[*] Could not obtain valid thread handle")
            return False
    
    def get_thread_context(self, thread_id, h_thread = None, close_handle = True):
        '''Returns a CONTEXT structure belonging to a thread.
        '''
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        # Obtain a handle to the thread
        if h_thread is None:
            self.open_thread(thread_id)
        if kernel32.GetThreadContext(self.h_thread, byref(context)):
            if close_handle:
                self.release_handle(self.h_thread)
            return context
        else:
            print('Could not obtain thread context for thread id: {}'.format(thread_id))
            return None

    def dump_thread_context(self, thread_context, thread_id, verbose=False):
        '''Pretty prints important registers from a CONTEXT structure
        '''
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
            if verbose:
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
        '''Enumerates running processes on a system through a Toolhelp32 snapshot.
        '''
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
            self.release_handle(process_snapshot)
            return process_list
        else:
            return False
    
    def open_process(self, pid):
        '''Opens a process with a given PID.
        '''
        return kernel32.OpenProcess(PROCESS_ALL_ACCESS, pid, False)

    def read_process_memory(self, address, length):
        '''Reads a process' memory for a given buffer length.
        '''
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
        '''Writes a process' memory with specified data.
        '''
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

    def get_function_address(self, dll, function):
        '''Resolves the address for a specified function in a specified module.
        '''
        kernel32.GetModuleHandleW.restype = c_void_p
        kernel32.GetProcAddress.argtypes = [c_void_p, c_char_p]
        kernel32.GetProcAddress.restype = c_void_p
        kernel32.CloseHandle.argtypes = [c_void_p]
        
        handle = kernel32.GetModuleHandleW(dll)
        address = kernel32.GetProcAddress(handle, function.encode(encoding='ascii'))
        if address == 0:
            self.print_system_error()
        self.release_handle(handle)
        return address

    def bp_set(self, address):
        '''Sets a soft breakpoint at a given address.
        '''
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

    def bp_set_hw(self, address, length, condition):
        '''Sets a hardware breakpoint at a given address.
        '''
        # checking valid length value
        if length not in (1, 2, 4):
            print('Invalid hardware breakpoint length')
            return False
        else:
            length = length - 1

        # check valid condition
        if condition not in (HW_ACCESS, HW_WRITE, HW_EXECUTE):
            print('Invalid hardware breakpoint condition')
            return False
        
        # check for available breakpoint slot
        available = None
        for bpslot in range(4):
            if bpslot not in self.hardware_breakpoints.keys():
                available = bpslot
                break
        if available is None:
            return False
        
        # we set the debug register for every thread
        for thread in self.thread_list():
            self.open_thread(thread)
            context = self.get_thread_context(thread, h_thread=self.h_thread, close_handle=False)
            # enable appropriate flag in DR7 register
            # for setting hw breakpoints for LOCAL TASKS ONLY
            # global task breakpoints would be done with 2, not 1
            context.Dr7 |= 1 << (available * 2)
            # save the address of the breakpoint in the free slot
            setattr(context, 'Dr' + str(available), address)
            # set the breakpoint condition
            context.Dr7 |= condition << ((available * 4) + 16)
            # set the length
            context.Dr7 |= length << ((available * 4) + 18)
            # set thread context with the break set
            kernel32.SetThreadContext(self.h_thread, byref(context))
            self.release_handle(self.h_thread)
        self.hardware_breakpoints[available] = (address, length, condition)
        return True
        






