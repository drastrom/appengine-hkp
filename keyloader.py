#!/usr/bin/env python

import cmdline_config

try:
	import dev_appserver
	dev_appserver.fix_sys_path()
except ImportError:
	print('Please make sure the App Engine SDK is in your PYTHONPATH.')
	raise

from google.appengine.ext.remote_api import remote_api_stub

remote_api_stub.ConfigureRemoteApiForOAuth('hkp-test.appspot.com', '/_ah/remote_api')

from appengine_hkp import parser

import sys
for arg in sys.argv[1:]:
	with open(arg, 'rb') as infile:
		parser.load_key(infile.read())

