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
	entities = {}
	pubkeys = []
	pubkey = None
	curkey = None
	latest_selfsig = datetime.datetime.utcfromtimestamp(0)

	for packet in data.packets():
		if isinstance(packet, pgpdump.packet.PublicKeyPacket) and not isinstance(packet, pgpdump.packet.SecretKeyPacket):
			latest_selfsig = datetime.datetime.utcfromtimestamp(0)
			if type(packet) == pgpdump.packet.PublicKeyPacket:
				pubkey = models.PublicKey()
				pubkeys.append(pubkey)
				curkey = pubkey
				# Ugh, BlobProperty wants str, not bytearray
				pubkey.key_data = str(data.data)
				curkey.key = ndb.Key(models.PublicKey, packet.fingerprint.decode('ascii'), namespace='hkp')
			else:
				curkey = models.PublicSubkey()
				curkey.key = ndb.Key(models.PublicSubkey, packet.fingerprint.decode('ascii'), parent=pubkey.key, namespace='hkp')
				pubkey.subkeys.append(curkey.key)
			entities[curkey.key] = curkey

			curkey.reversed_fingerprint = codecs.decode(packet.fingerprint.decode('ascii'), 'hex')[::-1]
			curkey.creation_time = packet.creation_time
			curkey.expiration_time = packet.expiration_time
			curkey.algorithm_type = packet.pub_algorithm_type
			curkey.bitlen = packet.modulus_bitlen
		elif isinstance(packet, pgpdump.packet.UserIDPacket):
			curuid = models.Uid()
			curuid.key = ndb.Key(models.Uid, packet.user, parent=pubkey.key, namespace='hkp')
			entities[curuid.key] = curuid
			pubkey.uids.append(curuid.key)
			curuid.uid = packet.user
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

	# allocate integer ids and re-key everything now that we know how many of each there are
	pubkey_id_start, pubkey_id_end = models.PublicKey.allocate_ids(size=len(pubkeys)) # TODO , namespace='hkp'
	for pubkey in pubkeys:
		assert pubkey_id_start <= pubkey_id_end
		pubkey.key = ndb.Key(models.PublicKey, pubkey_id_start, namespace='hkp')
		pubkey_id_start += 1
		subkey_id_start, subkey_id_end = models.PublicSubkey.allocate_ids(size=len(pubkey.subkeys), parent=pubkey.key) # TODO , namespace='hkp'
		new_subkeys = []
		for subkey in pubkey.subkeys:
			assert subkey_id_start <= subkey_id_end
			new_subkeys.append(ndb.Key(models.PublicSubkey, subkey_id_start, parent=pubkey.key, namespace='hkp'))
			entities[subkey].key = new_subkeys[-1]
			subkey_id_start += 1
		pubkey.subkeys = new_subkeys

		uid_id_start, uid_id_end = models.Uid.allocate_ids(size=len(pubkey.uids), parent=pubkey.key) # TODO , namespace='hkp'
		new_uids = []
		for uid in pubkey.uids:
			assert uid_id_start <= uid_id_end
			new_uids.append(ndb.Key(models.Uid, uid_id_start, parent=pubkey.key, namespace='hkp'))
			entities[uid].key = new_uids[-1]
			uid_id_start += 1
		pubkey.uids = new_uids


	ndb.put_multi(entities.values())

