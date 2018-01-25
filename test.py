#!/usr/bin/env python

if __name__ == "__main__":
	import cmdline_config

import pgpdump
import pgpdump.packet
import pprint

pp = pprint.PrettyPrinter()

import datetime
import re
import codecs
import pgpdump.utils
import struct
import hashlib

from appengine_hkp import utils

s = hashlib.sha1()
s.update(utils.ascii_tolower("Joe.Doe".encode('utf-8')))
print(utils.zbase32encode(s.digest()))
print(utils.zbase32decode("iy9q119eutrkn8s1mk4r39qejnbu3n5q".encode('ascii')) == s.digest())



class Uid(object):
	def __repr__(self):
		return "<%s: %r>" % (self.__class__.__name__, self.__dict__)

	_uid_regex = re.compile(r'^([^<(]+)? ?(?:\(([^\)]*)\))? ?<([^>]*)>?')

	def __init__(self):
		self.uid = ""
		self.creation_time = datetime.datetime.utcfromtimestamp(0)
		self.expiration_time = None

	@property
	def name(self):
		return self._parse_uid()[0]

	@property
	def comment(self):
		return self._parse_uid()[1]

	@property
	def email(self):
		return self._parse_uid()[2]

	@property
	def wkd_id(self):
		return utils.zbase32encode(hashlib.sha1(utils.ascii_tolower(self.email.rpartition('@')[0].encode("utf-8"))).digest()) if self.email is not None else None

	def _parse_uid(self):
		match = self._uid_regex.match(self.uid)
		if match:
			return (match.group(1).strip() if match.group(1) is not None else None, match.group(2).strip() if match.group(2) is not None else None, match.group(3).strip() if match.group(3) is not None else None)
		else:
			return (None, None, None)


class KeyBase(object):
	def __repr__(self):
		return "<%s: %r>" % (self.__class__.__name__, self.__dict__)

	def __init__(self):
		self.reversed_fingerprint = bytearray()
		self.creation_time = datetime.datetime.utcfromtimestamp(0)
		self.expiration_time = None
		self.flags = 0
		algorithm_type = ""
		bitlen = 0

	@property
	def fingerprint(self):
		return codecs.encode(self.reversed_fingerprint[::-1], 'hex').upper()

	def fingerprint_suffix(self, bytelen):
		return codecs.encode(self.reversed_fingerprint[bytelen-1::-1], 'hex').upper()

	@property
	def keyid(self):
		return self.fingerprint_suffix(8)

	@property
	def shortkeyid(self):
		return self.fingerprint_suffix(4)

class PublicSubkey(KeyBase):
	pass


class PublicKey(KeyBase):
	def __init__(self):
		super(PublicKey, self).__init__()
		self.uids = []
		self.subkeys = []
		self.key_data = bytearray()

	@property
	def asciiarmored(self):
		return utils.asciiarmor('PUBLIC KEY BLOCK', self.key_data)


with open('mykey.asc', 'rb') as infile:
	data = pgpdump.AsciiData(infile.read())

pubkeys = []
pubkey = None
curkey = None
curuid = None
subkey_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
pubkey_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
uid_latest_selfsig = datetime.datetime.utcfromtimestamp(0)

for packet in data.packets():
	print(str(type(packet)))
	pp.pprint(packet.__dict__)
	if isinstance(packet, pgpdump.packet.PublicKeyPacket) and not isinstance(packet, pgpdump.packet.SecretKeyPacket):
		if type(packet) == pgpdump.packet.PublicKeyPacket:
			pubkey_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
			pubkey = PublicKey()
			pubkeys.append(pubkey)
			curkey = pubkey
			pubkey.key_data = data.data
		else:
			subkey_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
			curkey = PublicSubkey()
			pubkey.subkeys.append(curkey)

		curkey.reversed_fingerprint = codecs.decode(packet.fingerprint.decode('ascii'), 'hex')[::-1]
		curkey.creation_time = packet.creation_time
		curkey.expiration_time = packet.expiration_time
		curkey.algorithm_type = packet.pub_algorithm_type
		curkey.bitlen = packet.modulus_bitlen
	elif isinstance(packet, pgpdump.packet.UserIDPacket):
		uid_latest_selfsig = datetime.datetime.utcfromtimestamp(0)
		curuid = Uid()
		pubkey.uids.append(curuid)
		curuid.uid = packet.user
	elif isinstance(packet, pgpdump.packet.SignaturePacket):
		pp.pprint([subpack.__dict__ for subpack in packet.subpackets])
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

pp.pprint([pubkey.__dict__ for pubkey in pubkeys])
print("Real fingerprints")
pp.pprint([pubkey.fingerprint for pubkey in pubkeys])
pp.pprint([pubkey.keyid for pubkey in pubkeys])
pp.pprint([pubkey.shortkeyid for pubkey in pubkeys])
print("Uid parts")
pp.pprint([uid._parse_uid() for uid in pubkey.uids for pubkey in pubkeys])
print(pubkeys[0].asciiarmored)
print("WKD ids")
pp.pprint([uid.wkd_id for uid in pubkey.uids for pubkey in pubkeys])
