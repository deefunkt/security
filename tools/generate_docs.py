import os
import re
import inspect
import sys
import my_debugger
import mailparser
import urlscanio
import virustotal
import zipcracker

HEADING = 'Tools'

FUNCTIONALITY_INTRO = '''
The following functionality is supported:

'''
files = os.listdir()
not_include = [
    '__pycache__',
    'generate_docs.py',
    'my_debugger_defines.py',
    'my_test.py',
    'printf_loop.py',
    'README.md',]
for names in not_include:
    files.pop(files.index(names))

with open('README.md', 'w+') as readme:
    readme.write('# ' + HEADING)
    readme.write('\n\n')
    for names in files:
        readme.write(f'## {names}\n')
        modname = names.strip('.py')
        class_inspection = inspect.getmembers(
            getattr(sys.modules[__name__], modname), 
            inspect.isclass)
        for class_name, class_type in class_inspection:
            if f'{modname}.' in str(class_type):
                readme.write(f'### Custom class of {modname}: **{class_name}**\n')
                for attribute, type in inspect.getmembers(class_type):
                    if attribute == '__doc__':
                        readme.write(type + '\n')
                        readme.write(FUNCTIONALITY_INTRO + '\n')
                    elif not attribute.startswith('__'):
                        readme.write(f'- **{attribute}** - {inspect.getdoc(type)}\n')
        
