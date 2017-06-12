#!/usr/bin/env python
from google.appengine.ext import ndb

import codecs

import pgpdump
import pgpdump.packet

from . import models

def load_key(key_asc):
	data = pgpdump.AsciiData(key_asc)
	entities = []
	pubkey = None
	curkey = None

	for packet in data.packets():
		if isinstance(packet, pgpdump.packet.PublicKeyPacket) and not isinstance(packet, pgpdump.packet.SecretKeyPacket):
			if type(packet) == pgpdump.packet.PublicKeyPacket:
				pubkey = models.PublicKey()
				curkey = pubkey
				# Ugh, BlobProperty wants str, not bytearray
				pubkey.key_data = str(data.data)
			else:
				curkey = models.PublicSubkey()

			entities.append(curkey)

			curkey.reversed_fingerprint = codecs.decode(packet.fingerprint.decode('ascii'), 'hex')[::-1]
			if type(packet) == pgpdump.packet.PublicKeyPacket:
				curkey.key = ndb.Key(models.PublicKey, curkey.integerid)
			else:
				curkey.key = ndb.Key(models.PublicSubkey, curkey.integerid, parent=pubkey.key)
				pubkey.subkeys.append(curkey.key)

			curkey.creation_time = packet.creation_time
			curkey.expiration_time = packet.expiration_time
			curkey.algorithm_type = packet.pub_algorithm_type
			curkey.bitlen = packet.modulus_bitlen
		elif isinstance(packet, pgpdump.packet.UserIDPacket):
			curuid = models.Uid()
			entities.append(curuid)
			curuid.key = ndb.Key(models.Uid, packet.user)
			pubkey.uids.append(curuid.key)

	ndb.put_multi(entities)

