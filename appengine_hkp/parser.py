#!/usr/bin/env python
from google.appengine.ext import ndb

import codecs
import datetime

import pgpdump
import pgpdump.packet
import pgpdump.utils

from . import models

def load_key(key_asc):
	data = pgpdump.AsciiData(key_asc)
	entities = []
	pubkey = None
	curkey = None
	latest_selfsig = datetime.datetime.utcfromtimestamp(0)

	for packet in data.packets():
		if isinstance(packet, pgpdump.packet.PublicKeyPacket) and not isinstance(packet, pgpdump.packet.SecretKeyPacket):
			latest_selfsig = datetime.datetime.utcfromtimestamp(0)
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
				curkey.key = ndb.Key(models.PublicKey, curkey.stringid, namespace='hkp')
			else:
				curkey.key = ndb.Key(models.PublicSubkey, curkey.stringid, parent=pubkey.key, namespace='hkp')
				pubkey.subkeys.append(curkey.key)

			curkey.creation_time = packet.creation_time
			curkey.expiration_time = packet.expiration_time
			curkey.algorithm_type = packet.pub_algorithm_type
			curkey.bitlen = packet.modulus_bitlen
		elif isinstance(packet, pgpdump.packet.UserIDPacket):
			curuid = models.Uid()
			entities.append(curuid)
			curuid.key = ndb.Key(models.Uid, packet.user, parent=pubkey.key, namespace='hkp')
			pubkey.uids.append(curuid.key)
			curuid.uid = packet.user.lower()
		elif isinstance(packet, pgpdump.packet.SignaturePacket):
			# self-sig
			if packet.key_id == pubkey.keyid:
				if packet.creation_time > latest_selfsig:
					latest_selfsig = packet.creation_time
					for subpack in packet.subpackets:
						if subpack.subtype == 9: # Key Expiration Time
							curkey.expiration_time = curkey.creation_time + datetime.timedelta(seconds=pgpdump.utils.get_int4(subpack.data, 0))
						elif subpack.subtype == 27: # Key Flags
							curkey.flags = subpack.data[0]
						elif subpack.subtype == 23: # Key Server Preferences (do we need these?)
							pass

	ndb.put_multi(entities)

