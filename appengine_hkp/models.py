#!/usr/bin/env python

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

import base64
import codecs
import re
import struct

import pgpdump.utils

# see https://stackoverflow.com/a/17511341
def _ceildiv(a, b):
	return -(-a // b)

def _linewrap(string, linelen=64):
	return "\n".join([string[linelen*i:linelen*i+linelen] for i in range(0,_ceildiv(len(string),linelen))])

class Uid(ndb.Model):
	uid = ndb.StringProperty('u', indexed=True, required=True)

	_uid_regex = re.compile(r'^([^<(]+)? ?(?:\(([^\)]*)\))? ?<([^>]*)>?')
	def _parse_uid(self):
		match = self._uid_regex.match(self.uid)
		if match:
			return (match.group(1).strip() if match.group(1) is not None else None, match.group(2).strip() if match.group(2) is not None else None, match.group(3).strip() if match.group(3) is not None else None)
		else:
			return (None, None, None)

	name = ndb.ComputedProperty(lambda self: self._parse_uid()[0], 'n', indexed=True)
	comment = ndb.ComputedProperty(lambda self: self._parse_uid()[1], 'c', indexed=True)
	email = ndb.ComputedProperty(lambda self: self._parse_uid()[2], 'e', indexed=True)

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


class PublicSubkey(KeyBase):
	pass

class PublicKey(KeyBase):
	uids = ndb.KeyProperty(Uid, 'u', indexed=True, repeated=True)
	subkeys = ndb.KeyProperty(PublicSubkey, 's', indexed=True, repeated=True)
	key_data = ndb.BlobProperty('d', indexed=False, required=True)

	@property
	def asciiarmored(self):
		return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{}\n={}\n-----END PGP PUBLIC KEY BLOCK-----".format(_linewrap(base64.b64encode(self.key_data)), base64.b64encode(struct.pack(">I", pgpdump.utils.crc24(self.key_data))[1:]))

