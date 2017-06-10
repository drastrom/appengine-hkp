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

class Uid(object):
	def __repr__(self):
		return "<%s: %r>" % (self.__class__.__name__, self.__dict__)

	_uid_regex = re.compile(r'^([^<(]+)? ?(?:\(([^\)]*)\))? ?<([^>]*)>?')

	def __init__(self):
		self.uid = ""

	@property
	def name(self):
		return self._parse_uid()[0]

	@property
	def comment(self):
		return self._parse_uid()[1]

	@property
	def email(self):
		return self._parse_uid()[2]

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
		return codecs.encode(self.reversed_fingerprint[::-1], 'hex').upper().encode('ascii')

	def fingerprint_suffix(self, bytelen):
		return codecs.encode(self.reversed_fingerprint[bytelen-1::-1], 'hex').upper().encode('ascii')

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


with open('mykey.asc', 'rb') as infile:
	data = pgpdump.AsciiData(infile.read())

pubkeys = []
pubkey = None
curkey = None

for packet in data.packets():
	if isinstance(packet, pgpdump.packet.PublicKeyPacket) and not isinstance(packet, pgpdump.packet.SecretKeyPacket):
		if packet.name == "Public Key Packet":
			pubkey = PublicKey()
			pubkeys.append(pubkey)
			curkey = pubkey
			pubkey.key_data = data.data
		else:
			curkey = PublicSubkey()
			pubkey.subkeys.append(curkey)

		curkey.reversed_fingerprint = codecs.decode(packet.fingerprint.decode('ascii'), 'hex')[::-1]
		curkey.creation_time = packet.creation_time
		curkey.expiration_time = packet.expiration_time
		curkey.algorithm_type = packet.pub_algorithm_type
		curkey.bitlen = packet.modulus_bitlen
	elif isinstance(packet, pgpdump.packet.UserIDPacket):
		curuid = Uid()
		pubkey.uids.append(curuid)
		curuid.uid = packet.user

pp.pprint([pubkey.__dict__ for pubkey in pubkeys])
print "Real fingerprints"
pp.pprint([pubkey.fingerprint for pubkey in pubkeys])
pp.pprint([pubkey.keyid for pubkey in pubkeys])
pp.pprint([pubkey.shortkeyid for pubkey in pubkeys])
print "Uid parts"
pp.pprint([uid._parse_uid() for uid in pubkey.uids for pubkey in pubkeys])
