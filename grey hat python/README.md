# Python 3 debugger

Primarily a usermode debugger written to be used on Windows operating systems, for Windows processes.
It is a customized implementation of the python debugger pydbg originally written by pedramamini, as shown in "Grey Hat Python". Modified to be more properly object oriented than the original code, and written to be compatible with Python 3 on 64 bit systems.

The following functionality is supported:

- attach - Attaches the debugger to an already running process
- bp_del_hw - Deletes and disables hardware breakpoints for all active threads in debuggee
- bp_set - Sets a soft breakpoint at a given address.
- bp_set_hw - Sets a hardware breakpoint at a given address.
- detach - Detaches the debugger from a debugged process and releases all opened handles
- dump_thread_context - Pretty prints important registers from a CONTEXT structure
- enumerate_processes - Enumerates running processes on a system through a Toolhelp32 snapshot.
- enumerate_threads - Enumerates threads belonging to debuggee using a Toolhelp32 snapshot across the system
- exception_handler_breakpoint - The handler for soft breakpoints
- exception_handler_single_step - The handler for hardware breakpoints. Deletes the breakpoint after processing.
- get_debug_event - Processes debug events for access Violations, memory, hardware and regular breakpoints
and calls the relevant handlers.
- get_function_address - Resolves the address for a specified function in a specified module.
- get_thread_context - Returns a CONTEXT structure belonging to a thread.
- load - Creates a given process as a new child of the debugger
- open_process - Opens a process with a given PID.
- open_thread - Opens a given thread
- print_system_error - Calls GetLastError and then formats the error message for display
- read_process_memory - Reads a process' memory for a given buffer length.
- release_handle - Releases specified handle or all handles using CloseHandle 
- run - Runs the debugger and gets debug events
- write_process_memory - Writes a process' memory with specified data.
