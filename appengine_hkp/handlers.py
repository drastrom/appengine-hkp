#!/usr/bin/env python

import webapp2

import codecs
import re

from . import models
from . import parser
from . import utils


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
				q = models.KeyBase.query(namespace='hkp')
				bin_revkeyid = bytearray(codecs.decode(match.group(1), 'hex')[::-1])
				if len(bin_revkeyid) == 20:
					q = q.filter(models.KeyBase.reversed_fingerprint == str(bin_revkeyid))
				else:
					q = q.filter(models.KeyBase.reversed_fingerprint >= str(bin_revkeyid))
					upper_range = utils.incremented_array(bin_revkeyid)
					if upper_range is not None:
						q = q.filter(models.KeyBase.reversed_fingerprint < str(upper_range))
				key = q.get()
				if isinstance(key, models.PublicSubkey):
					key = key.key.parent().get()

				if key is None:
					self.response.status = "404 Not Found"
				else:
					#self.response.content_type = 'application/pgp-keys'
					self.response.content_type = 'text/plain'
					self.response.write(key.asciiarmored)
			else:
				self.response.status = "501 Not Implemented"
		else:
			self.response.status = "501 Not Implemented"

app = webapp2.WSGIApplication([
	('/pks/add', KeyAdd),
	('/pks/lookup', KeyLookup)
], debug=True)

