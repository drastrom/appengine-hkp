import ptvsd

import getpass
import platform
#Override methods that die in appengine sandbox
getpass.getuser = lambda: "debugger"
platform.system = lambda: "Windows"

#In visual studio attach dialog, you'll need to select transport python remote,
#and qualifier tcp://gae@localhost:3000
ptvsd.enable_attach(secret = 'gae', address = ('127.0.0.1', 3000))
#The debug server has started and you can now attach to the application for debugging
print("Google App Engine has started, ready to attach the debugger")
