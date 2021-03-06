#!/usr/bin/env python

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

import base64
import codecs
import hashlib
import re

from . import utils

class Uid(ndb.Model):
	uid = ndb.StringProperty('u', indexed=True, required=True)

	_uid_regex = re.compile(r'^([^<(]+)? ?(?:\(([^\)]*)\))? ?<([^>]*)>?')
	def _parse_uid(self, uid):
		match = self._uid_regex.match(uid)
		if match:
			return (match.group(1).strip() if match.group(1) is not None else None, match.group(2).strip() if match.group(2) is not None else None, match.group(3).strip() if match.group(3) is not None else None)
		else:
			return (None, None, None)
	def _uid_email_localpart(self, uid):
		email = self._parse_uid(uid)[2]
		return utils.zbase32encode(hashlib.sha1(utils.ascii_tolower(email.rpartition('@')[0].encode("utf-8"))).digest()) if email is not None else None
	def _uid_email_domain(self, uid):
		email = self._parse_uid(uid)[2]
		return utils.ascii_tolower(email.rpartition('@')[2].encode("utf-8")) if email is not None else None

	name = ndb.ComputedProperty(lambda self: self._parse_uid(self.uid)[0], 'n', indexed=True)
	comment = ndb.ComputedProperty(lambda self: self._parse_uid(self.uid)[1], 'c', indexed=True)
	email = ndb.ComputedProperty(lambda self: self._parse_uid(self.uid)[2], 'e', indexed=True)
	creation_time = ndb.DateTimeProperty('r', indexed=False)
	expiration_time = ndb.DateTimeProperty('x', indexed=False)
	wkd_id = ndb.ComputedProperty(lambda self: self._uid_email_localpart(self.string_id), 'w', indexed=True)
	wkd_domain = ndb.ComputedProperty(lambda self: self._uid_email_domain(self.string_id), 'd', indexed=True)

	@property
	def string_id(self):
		# XXX ndb.Key encodes unicode string_ids to utf-8, so we need to decode here
		return self.key.string_id().decode("utf-8")

class KeyBase(polymodel.PolyModel):
	reversed_fingerprint = ndb.BlobProperty('rfp', indexed=True, required=True)
	creation_time = ndb.DateTimeProperty('c', indexed=False)
	expiration_time = ndb.DateTimeProperty('e', indexed=False)
	flags = ndb.IntegerProperty('f', indexed=False)
	algorithm_type = ndb.StringProperty('a', indexed=False, required=True)
	bitlen = ndb.IntegerProperty('b', indexed=False)

	@property
	def fingerprint(self):
		return codecs.encode(self.reversed_fingerprint[::-1], 'hex').upper()

	def _fingerprint_suffix(self, bytelen):
		return codecs.encode(self.reversed_fingerprint[bytelen-1::-1], 'hex').upper()

	@property
	def keyid(self):
		return self._fingerprint_suffix(8)

	@property
	def shortkeyid(self):
		return self._fingerprint_suffix(4)

	@property
	def stringid(self):
		return base64.b64encode(self.reversed_fingerprint[::-1])


class PublicSubkey(KeyBase):
	pass

class PublicKey(KeyBase):
	uids = ndb.KeyProperty(Uid, 'u', indexed=False, repeated=True)
	subkeys = ndb.KeyProperty(PublicSubkey, 's', indexed=False, repeated=True)
	key_data = ndb.BlobProperty('d', indexed=False, required=True)

	@property
	def asciiarmored(self):
		return utils.asciiarmor('PUBLIC KEY BLOCK', self.key_data)

