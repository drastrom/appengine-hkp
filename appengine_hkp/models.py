#!/usr/bin/env python

from google.appengine.ext import ndb
from google.appengine.ext.ndb import polymodel

class Uid(ndb.Model):
	name = ndb.StringProperty('n', indexed=True)
	comment = ndb.StringProperty('c', indexed=False)
	email = ndb.StringProperty('e', indexed=True)

class KeyBase(polymodel.PolyModel):
	reversed_fingerprint = ndb.BlobProperty('rfp', indexed=True, required=True)
	creation_time = ndb.DateTimeProperty('c', indexed=False)
	expiration_time = ndb.DateTimeProperty('e', indexed=False)
	flags = ndb.IntegerProperty('f', indexed=False)
	algorithm_type = ndb.StringProperty('a', indexed=False, required=True)
	bitlen = ndb.IntegerProperty('b', indexed=False)

class PublicKey(KeyBase);
	uid = ndb.StructuredProperty(Uid, 'u', indexed=True, repeated=True)
	key_data = ndb.BlobProperty('d', indexed=False, required=True)

class PublicSubkey(KeyBase):
	pass

