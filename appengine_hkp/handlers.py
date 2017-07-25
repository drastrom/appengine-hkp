#!/usr/bin/env python

import webapp2
from google.appengine.ext import ndb

import array
import codecs
import re
import urllib

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
_algo_mapping = {'rsa': 1, 'dsa': 17, 'elg': 16, 'ec': 18, 'ecdsa': 19, 'dh': 21}
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
		q = models.Uid.query(namespace='hkp')
		# XXX are params unicode string, utf-8, ...?
		if type(search) == str:
			search = search.decode('utf-8')

		search = search.lower()

		# really wish they had a field that said what PART of the uid they wanted to query
		# they say 'exact' is implementation interpretation, I'll take that to mean the Uid should be exactly equal
		if exact:
			q = q.filter(models.Uid.uid == search)
		else:
			upper_range = utils.incremented_array(array.array('u', search)).tounicode()
			filters = []
			filters.append(ndb.AND(models.Uid.uid >= search, models.Uid.uid < upper_range))
			filters.append(ndb.AND(models.Uid.name >= search, models.Uid.name < upper_range))
			filters.append(ndb.AND(models.Uid.comment >= search, models.Uid.comment < upper_range))
			filters.append(ndb.AND(models.Uid.email >= search, models.Uid.email < upper_range))

			q = q.filter(ndb.OR(*filters))

		return q

	def get_op(self, search, exact=False, fingerprint=False, options=None):
		q = None
		if len(search) > 2 and search[:2].upper() == "0X":
			q = self._query_by_keyid(search, exact, fingerprint, options)
		else:
			q = self._query_by_text(search, exact, fingerprint, options)

		key_data = bytearray()
		keys_to_get = []
		for entity in q.fetch(20):
			if not isinstance(entity, models.PublicKey):
				keys_to_get.append(entity.key.parent())
			else:
				key_data.extend(entity.key_data)

		if len(keys_to_get):
			for entity in ndb.get_multi(keys_to_get):
				if entity is not None:
					key_data.extend(entity.key_data)

		if len(key_data) == 0:
			raise exceptions.HttpNotFoundException()

		self.response.content_type = 'application/pgp-keys' if not TEST else 'text/plain'
		self.response.write(utils.asciiarmor('PUBLIC KEY BLOCK', key_data))

	def index_op(self, search, exact=False, fingerprint=False, options=None):
		q = None
		if len(search) > 2 and search[:2].upper() == "0X":
			q = self._query_by_keyid(search, exact, fingerprint, options)
		else:
			q = self._query_by_text(search, exact, fingerprint, options)

		keys = []
		keys_to_get = []
		uids_to_get = []
		uids = {}
		for entity in q.fetch(20):
			if isinstance(entity, models.PublicKey):
				keys.append(entity)
				if entity.uids:
					uids_to_get.extend(filter(lambda x: x not in uids and x not in uids_to_get, entity.uids))
			else:
				keys_to_get.append(entity.key.parent())
				if isinstance(entity, models.Uid):
					uids[entity.key] = entity

		if len(keys_to_get):
			for entity in ndb.get_multi(keys_to_get):
				if entity is not None:
					keys.append(entity)
					if entity.uids:
						uids_to_get.extend(filter(lambda x: x not in uids and x not in uids_to_get, entity.uids))

		if len(uids_to_get):
			uids_list = filter(lambda x: x is not None, ndb.get_multi(uids_to_get))
			uids.update(zip(map(lambda x: x.key, uids_list), uids_list))

		self.response.content_type = 'text/plain'
		self.response.write("info:1:{0}\n".format(len(keys)))
		for key in keys:
			# TODO switch algorithm_type to store raw_pub_algorithm_type?
			self.response.write(':'.join(("pub",
								 key.fingerprint,
								 str(_algo_mapping[key.algorithm_type]),
								 str(key.bitlen),
								 str(utils.datetime_to_unix_time(key.creation_time)) if key.creation_time else "",
								 str(utils.datetime_to_unix_time(key.expiration_time)) if key.expiration_time else "",
								 "e" if utils.is_expired(key) else "")) + "\n")
			if key.uids:
				for uid_key in key.uids:
					uid = uids[uid_key]
					uid_str = uid.key.id()
					if type(uid_str) == unicode:
						uid_str = uid_str.encode("utf-8")
					self.response.write(':'.join(("uid",
								   urllib.quote(uid_str),
								   str(utils.datetime_to_unix_time(uid.creation_time)) if uid.creation_time else "",
								   str(utils.datetime_to_unix_time(uid.expiration_time)) if uid.expiration_time else "",
								   "e" if utils.is_expired(uid) else "")) + "\n")

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
			except KeyError as e:
				raise exceptions.HttpNotImplementedException()

			op_func(self, search, exact, fingerprint, options)

		except exceptions.HttpStatusException as e:
			self.response.status = e.status_line

app = webapp2.WSGIApplication([
	('/pks/add', KeyAdd),
	('/pks/lookup', KeyLookup)
], debug=True)

