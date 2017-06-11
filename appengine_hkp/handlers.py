#!/usr/bin/env python

from google.appengine.ext import ndb
import webapp2

import base64
import codecs
import copy
import re
import struct

import pgpdump
import pgpdump.packet
import pgpdump.utils

from . import models
from . import parser

def _incremented_array(ra):
	"""Return an array which is lexically greater than the passed in array
	by one.  The intent is to be able to build a range query such that
	ra <= queried < _incremented_array(ra) will return ra and any array
	that has ra as a prefix.  This relies on the passed in array fulfilling
	the following behaviors:

	* copy.deepcopy(ra) will Do The Right Thing

	* attempting to increment a value beyond its range will result in a
	  ValueError

	* the array can be indexed from the end using negative values

	* attempting to use a negative index beyond -len(ra) will result in an
	  IndexError
	"""

	ra = copy.deepcopy(ra)
	i = 0
	try:
		while True:
			i -= 1
			try:
				ra[i] += 1
				break
			except ValueError, e:
				ra[i] = 0
	except IndexError, e:
		return None

	return ra


class KeyAdd(webapp2.RequestHandler):
	def post(self):
		key_asc = self.request.POST['keytext']
		parser.load_key(key_asc)

	def get(self):
		self.response.write("""<html>
<head>
<title>Upload Key</title>
</head>
<body>
<form action="/pks/add" method="POST">
<label for="keytext">Paste ASCII-armored key here:</label><br/>
<textarea name="keytext" rows="20" cols="65"></textarea><br/>
<input type="submit" name="submit" value="Upload"/>
</form>
</body>
</html>""")


_keyid_regex = re.compile(r'^(?:0[Xx])?([0-9a-fA-F]{8}|[0-9a-fA-F]{16}|[0-9a-fA-F]{40})$')
class KeyLookup(webapp2.RequestHandler):
	def get(self):
		op = self.request.get('op')
		search = self.request.get('search')
		if op == "get":
			match = _keyid_regex.match(search)
			if match:
				q = models.KeyBase.query()
				bin_revkeyid = bytearray(codecs.decode(match.group(1), 'hex')[::-1])
				if len(bin_revkeyid) == 20:
					q.filter(models.KeyBase.reversed_fingerprint == str(bin_revkeyid))
				else:
					q.filter(models.KeyBase.reversed_fingerprint >= str(bin_revkeyid))
					upper_range = _incremented_array(bin_revkeyid)
					if upper_range is not None:
						q.filter(models.KeyBase.reversed_fingerprint < str(upper_range))
				key = q.get()
				if isinstance(key, models.PublicSubkey):
					key = key.key.parent().get()

				if key is None:
					self.response.status = "404 Not Found"
				else:
					#self.response.content_type = 'application/pgp-keys'
					self.response.content_type = 'text/plain'
					self.response.write(key.asciiarmored)

app = webapp2.WSGIApplication([
	('/pks/add', KeyAdd),
	('/pks/lookup', KeyLookup)
], debug=True)

