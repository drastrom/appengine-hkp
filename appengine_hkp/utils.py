#!/usr/bin/env python

import base64
import copy
import datetime
import pgpdump.utils
import string
import struct
import threading

def incremented_array(ra):
	"""Return an array which is lexically greater than the passed in array
	by one.  The intent is to be able to build a range query such that
	ra <= queried < _incremented_array(ra) will return ra and any array
	that has ra as a prefix.  This relies on the passed in array fulfilling
	the following behaviors:

	* copy.deepcopy(ra) will Do The Right Thing

	* attempting to increment a value beyond its range will result in a
	  ValueError

	* the array can be indexed from the end using negative values

	* attempting to use a negative index beyond -len(ra) will result in an
	  IndexError
	"""

	ra = copy.deepcopy(ra)
	i = 0
	to_element = lambda x: x
	from_element = lambda e: e

	if len(ra) > 0:
		if type(ra[0]) == unicode:
			to_element = lambda x: unichr(x)
			from_element = lambda e: ord(e)
		elif type(ra[0]) == str:
			to_element = lambda x: chr(x)
			from_element = lambda e: ord(e)

	try:
		while True:
			i -= 1
			try:
				ra[i] = to_element(from_element(ra[i]) + 1)
				break
			except ValueError as e:
				ra[i] = to_element(0)
	except IndexError as e:
		return None

	return ra

# see https://stackoverflow.com/a/17511341
def ceildiv(a, b):
	"""see https://stackoverflow.com/a/17511341"""
	return -(-a // b)

def linewrap(string, linelen=64):
	return "\n".join([string[linelen*i:linelen*(i+1)] for i in range(0,ceildiv(len(string),linelen))])

def asciiarmor(armor_header_type, data):
	return "-----BEGIN PGP {0}-----\n\n{1}\n={2}\n-----END PGP {0}-----".format(armor_header_type, linewrap(base64.b64encode(data).decode('ascii')), base64.b64encode(struct.pack(">I", pgpdump.utils.crc24(bytearray(data)))[1:]).decode('ascii'))

_ascii_tolower = None
_ascii_tolower_lock = threading.Lock()
def ascii_tolower(s):
	global _ascii_tolower, _ascii_tolower_lock
	if _ascii_tolower is None:
		with _ascii_tolower_lock:
			if _ascii_tolower is None:
				try:
					_ascii_tolower = string.maketrans(string.ascii_uppercase, string.ascii_lowercase)
				except AttributeError:
					_ascii_tolower = bytes.maketrans(string.ascii_uppercase.encode('ascii'), string.ascii_lowercase.encode('ascii'))
	return s.translate(_ascii_tolower)

_zbase32encode = None
_zbase32decode = None
_zbase32_lock = threading.Lock()
def _zbase32init():
	global _zbase32encode, _zbase32decode, _zbase32_lock
	with _zbase32_lock:
		if _zbase32encode is None or _zbase32decode is None:
			base32alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
			zbase32alpha = "ybndrfg8ejkmcpqxot1uwisza345h769"
			try:
				_zbase32encode = string.maketrans(base32alpha, zbase32alpha)
				_zbase32decode = string.maketrans(zbase32alpha, base32alpha)
			except AttributeError:
				base32alpha = base32alpha.encode('ascii')
				zbase32alpha = zbase32alpha.encode('ascii')
				_zbase32encode = bytes.maketrans(base32alpha, zbase32alpha)
				_zbase32decode = bytes.maketrans(zbase32alpha, base32alpha)

def zbase32encode(s):
	global _zbase32encode
	if _zbase32encode is None:
		_zbase32init()
	return base64.b32encode(s).rstrip('='.encode('ascii')).translate(_zbase32encode)

def zbase32decode(s):
	global _zbase32decode
	if _zbase32decode is None:
		_zbase32init()
	return base64.b32decode(s.translate(_zbase32decode).ljust(ceildiv(len(s),8)*8,'='.encode('ascii')))

epoch = datetime.datetime.utcfromtimestamp(0)

def datetime_to_unix_time(dt):
	return int((dt - epoch).total_seconds())

def is_expired(obj, now):
	return obj.expiration_time and obj.expiration_time <= now
