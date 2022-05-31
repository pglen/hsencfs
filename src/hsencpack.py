#!/usr/bin/env python3
"""

OBSOLETE

...This script is going to create a debian package ...


"""
import os, sys

print('This script is going to create a debian package (deactivated)')
sys.exit(0)

###### EDIT THIS SECTION WITH YOUR PACKAGE INFORMATION ######
include_hello_world_script = True # Set to False to manually copy your files and remove helloworld program
package_name = 'helloworld'
major_version = 1
minor_version = 4
package_revision = 0
section = 'base'
priority = ''
architecture = 'amd64' #Change to armhf for Raspberry Pi
depends = 'fuse, fuse3' #For example: libsomethingorrather (>= 1.2.13), anotherDependency (>= 1.2.6)
maintainer = 'Peter Glen <peterglen99@gmail.com>'
#The space before each line in the description is important
package_description = """HsEncFS on the fly encrypting file system
 blahblahblah blahblahblah blahblahblah blahblahblah
"""
###### NO EDITING NEEDED BEYOND THIS LINE ######

version_name = str(major_version) + '.' + str(minor_version) + '-' + str(package_revision)
full_package_name = package_name + '_' + version_name
path = os.getcwd()
package_folder = os.path.join(path, full_package_name)
os.makedirs(package_folder, exist_ok=True)
os.makedirs(os.path.join(package_folder, 'DEBIAN'), exist_ok=True)
with open(os.path.join(package_folder, 'DEBIAN', 'control'), 'w') as file:
    file.write("""Package: """ + package_name + """
Version: """ + version_name + """
Section: """ + section + """
Priority: """ + priority + """
Architecture: """ + architecture + """
Depends: """ + depends + """
Maintainer: """ + maintainer + """
Description: """ + package_description)

if include_hello_world_script:
    script_destination = os.path.join(package_folder, 'usr/local/bin')
    os.makedirs(script_destination, exist_ok=True)
    helloworld_filename = os.path.join(script_destination, 'helloworld')
    with open(helloworld_filename, 'w') as file:
        file.write("""#!/usr/bin/env python3
print('Hello World!')""")
    os.chmod(helloworld_filename, 0o755)

input("Put your files in the package structure and press Enter to continue...")
os.system('dpkg-deb --build ' + full_package_name)


