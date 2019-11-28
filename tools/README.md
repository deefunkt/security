# Tools

## mailparser.py
### Custom class of mailparser: **EmailParser**
This class defines a way to interact with a raw email stored on disk, and parses
    it for:
        - IP addresses related with the delivery of the message, excluding known
            'good' addresses such as prod.outlook.com, and protection.outlook.com
        - Attachments and embedded files, their filenames, and sha256 hash values
        - URLs embedded in the email
    These artefacts are to be queried against OSINT sources eg. VirusTotal, urlscan.io
    for known malicious activity.
    

The following functionality is supported:


- **get_attachments** - None
- **get_ip_addresses** - None
- **get_urls** - None
## my_debugger.py
### Custom class of my_debugger: **debugger**
Primarily a usermode debugger written to be used on Windows operating systems, 
    for Windows processes. 
    It is a customized implementation of the python debugger pydbg, originally 
    written by pedramamini, as shown in "Grey Hat Python". 
    Modified to be more properly object oriented than the original code, 
    and written to be compatible with Python 3 on 64 bit systems.
    

The following functionality is supported:


- **attach** - Attaches the debugger to an already running process
        
- **bp_del_hw** - Deletes and disables hardware breakpoints for all active threads in debuggee
        
- **bp_set** - Sets a soft breakpoint at a given address.
        
- **bp_set_hw** - Sets a hardware breakpoint at a given address.
        
- **detach** - Detaches the debugger from a debugged process and releases all opened handles
        
- **dump_thread_context** - Pretty prints important registers from a CONTEXT structure
        
- **enumerate_processes** - Enumerates running processes on a system through a Toolhelp32 snapshot.
        
- **enumerate_threads** - Enumerates threads belonging to debuggee using a Toolhelp32 snapshot across the system
        
- **exception_handler_breakpoint** - The handler for soft breakpoints
        
- **exception_handler_single_step** - The handler for hardware breakpoints. Deletes the breakpoint after processing.
        
- **get_debug_event** - Processes debug events for access Violations, memory, hardware and regular breakpoints
and calls the relevant handlers.
- **get_function_address** - Resolves the address for a specified function in a specified module.
        
- **get_thread_context** - Returns a CONTEXT structure belonging to a thread.
        
- **load** - Creates a given process as a new child of the debugger
        
- **open_process** - Opens a process with a given PID.
        
- **open_thread** - Opens a given thread
        
- **print_system_error** - Calls GetLastError and then formats the error message for display
        
- **read_process_memory** - Reads a process' memory for a given buffer length.
        
- **release_handle** - Releases specified handle or all handles using CloseHandle 
        
- **run** - Runs the debugger and gets debug events
        
- **write_process_memory** - Writes a process' memory with specified data.
        
## urlscanio.py
### Custom class of urlscanio: **UrlScanner**
This class contains methods for querying urls against urlscan.io.
    Typical uses:
        scanner = urlScanner()
        submission = scanner.submitUrl(url="http://www.google.com")
        result, isMalicious = scanner.scanResult(scanid = submission["api"])
    'result' contains a dictionary containing various artefacts about the URL.
    'malicious' is 1 for yes and 0 for not.
    You can also supply a list of urls, and will obtain a list of results (dicts) and malicious (list)
        submissions = scanner.submitBulk(urls)
        results, malicious = scanner.scanBulk(submissions)
    

The following functionality is supported:


- **scanBulk** - None
- **scanResult** - None
- **search** - None
- **submitBulk** - None
- **submitURL** - None
## virustotal.py
### Custom class of virustotal: **VirusTotalScanner**
This class contains methods for interacting with the VirusTotal public API.
 - Urls can be checked against the database, and submitted for scanning.
 - IP addresses can be submitted, and associated bad hostnames and file hashes previously identified by
     virustotal are returned as a measure of threat.


The following functionality is supported:


- **getIPReport** - None
- **getUrlReport** - None
- **isError** - None
- **submitURL** - None
## zipcracker.py
