#!/usr/bin/env python

import base64
import copy
import pgpdump.utils
import struct

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

