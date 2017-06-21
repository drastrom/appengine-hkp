import sys
import os
import ptvsd
import getpass
import platform
getpass.getuser = lambda: "debugger"
platform.system = lambda: "Windows"
#Feel free to change the secret and port number
ptvsd.enable_attach(secret = 'gae', address = ('0.0.0.0', 3000))
#The debug server has started and you can now use VS Code to attach to the application for debugging
print("Google App Engine has started, ready to attach the debugger")
