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
	curuid = None
	subkey_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
	pubkey_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
	uid_latest_selfsig = datetime.datetime.utcfromtimestamp(0)

	for packet in data.packets():
		if isinstance(packet, pgpdump.packet.PublicKeyPacket) and not isinstance(packet, pgpdump.packet.SecretKeyPacket):
			if type(packet) == pgpdump.packet.PublicKeyPacket:
				pubkey_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
				pubkey = models.PublicKey()
				curkey = pubkey
				# Ugh, BlobProperty wants str, not bytearray
				pubkey.key_data = str(data.data)
			else:
				subkey_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
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
			uid_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
			curuid = models.Uid()
			entities.append(curuid)
			curuid.key = ndb.Key(models.Uid, packet.user, parent=pubkey.key, namespace='hkp')
			pubkey.uids.append(curuid.key)
			curuid.uid = packet.user.lower()
		elif isinstance(packet, pgpdump.packet.SignaturePacket):
			# self-sig
			if packet.key_id == pubkey.keyid:
				# At this point only interested in UID, subkey, or sig directly on key
				# TODO should record revocation as well
				if packet.raw_sig_type in (0x10, 0x11, 0x12, 0x13, 0x18, 0x1F):
					# From RFC4880:
					#  Subpackets that appear in a certification self-signature
					#  apply to the user name, and subpackets that appear in the subkey
					#  self-signature apply to the subkey.  Lastly, subpackets on the
					#  direct-key signature apply to the entire key.
					#
					# NOTE while the certification subpackets should apply to the user name,
					# not the entire key, gpg seems to put properties of the public key in the
					# certification signature(s).  So, no else here...
					if packet.raw_sig_type >= 0x10 and packet.raw_sig_type <= 0x13 and uid_latest_selfsig < packet.creation_time:
						uid_latest_selfsig = packet.creation_time
						curuid.creation_time = packet.creation_time
						curuid.expiration_time = packet.expiration_time
					if (packet.raw_sig_type == 0x18 and subkey_latest_selfsig < packet.creation_time) or (packet.raw_sig_type != 0x18 and pubkey_latest_selfsig < packet.creation_time):
						# Should modify pubkey even if the direct-key sig packet happens after subkeys
						modkey = curkey if packet.raw_sig_type == 0x18 else pubkey
						for subpack in packet.subpackets:
							if subpack.subtype == 9: # Key Expiration Time
								modkey.expiration_time = modkey.creation_time + datetime.timedelta(seconds=pgpdump.utils.get_int4(subpack.data, 0))
							elif subpack.subtype == 27: # Key Flags
								modkey.flags = subpack.data[0]
							elif subpack.subtype == 23: # Key Server Preferences (do we need these?)
								pass

	ndb.put_multi(entities)

