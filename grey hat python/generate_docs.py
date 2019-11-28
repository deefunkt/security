import re
import inspect
import my_debugger

HEADING = 'Python 3 debugger'

INTRO = '''Primarily a usermode debugger written to be used on Windows operating systems, for Windows processes.
It is a customized implementation of the python debugger pydbg originally written by pedramamini, as shown in "Grey Hat Python". Modified to be more properly object oriented than the original code, and written to be compatible with Python 3 on 64 bit systems.

The following functionality is supported:

'''

with open('README.md', 'w+') as readme:
    readme.write('# ' + HEADING)
    readme.write('\n\n')
    readme.write(INTRO) 
    for name, type in inspect.getmembers(my_debugger.debugger):
        if not name.startswith('__'):
            readme.write(f'- {name} - {inspect.getdoc(type)}\n')
