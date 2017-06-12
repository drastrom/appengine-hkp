#!/usr/bin/env python

import webapp2

import codecs
import re

from . import exceptions
from . import models
from . import parser
from . import utils

TEST = True

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

	def _query_by_keyid(self, search, exact=False, fingerprint=False, options=None):
		match = _keyid_regex.match(search)
		if not match:
			raise exceptions.HttpBadRequestException()

		q = models.KeyBase.query(namespace='hkp')
		bin_revkeyid = bytearray(codecs.decode(match.group(1), 'hex')[::-1])
		if len(bin_revkeyid) == 20:
			q = q.filter(models.KeyBase.reversed_fingerprint == str(bin_revkeyid))
		else:
			q = q.filter(models.KeyBase.reversed_fingerprint >= str(bin_revkeyid))
			upper_range = utils.incremented_array(bin_revkeyid)
			if upper_range is not None:
				q = q.filter(models.KeyBase.reversed_fingerprint < str(upper_range))
		return q

	def _query_by_text(self, search, exact=False, fingerprint=False, options=None):
		raise exceptions.HttpNotImplementedException()

	def get_op(self, search, exact=False, fingerprint=False, options=None):
		q = None
		if len(search) > 2 and search[:2].upper() == "0X":
			q = self._query_by_keyid(search, exact, fingerprint, options)
		else:
			q = self._query_by_text(search, exact, fingerprint, options)

		key = q.get()
		if isinstance(key, models.PublicSubkey):
			key = key.key.parent().get()

		if key is None:
			raise exceptions.HttpNotFoundException()
		else:
			self.response.content_type = 'application/pgp-keys' if not TEST else 'text/plain'
			self.response.write(key.asciiarmored)

	def index_op(self, search, exact=False, fingerprint=False, options=None):
		raise exceptions.HttpNotImplementedException()

	def vindex_op(self, search, exact=False, fingerprint=False, options=None):
		raise exceptions.HttpNotImplementedException()

	_operation_mapping = {
			'get': get_op,
			'index': index_op,
			'vindex': vindex_op
	}

	def get(self):
		try:
			op = self.request.get('op')
			search = self.request.get('search')
			options = (self.request.get('options') or "").split(',')
			fingerprint = self.request.get('fingerprint') or "off"
			exact = self.request.get('exact') or "off"

			if fingerprint not in ('on', 'off') or exact not in ('on', 'off'):
				raise exceptions.HttpBadRequestException()

			fingerprint = True if fingerprint == 'on' else False
			exact = True if exact == 'on' else False

			op_func = None
			try:
				op_func = self._operation_mapping[op]
			except KeyError, e:
				raise exceptions.HttpNotImplementedException()

			op_func(self, search, exact, fingerprint, options)

		except exceptions.HttpStatusException, e:
			self.response.status = e.status_line

app = webapp2.WSGIApplication([
	('/pks/add', KeyAdd),
	('/pks/lookup', KeyLookup)
], debug=True)

