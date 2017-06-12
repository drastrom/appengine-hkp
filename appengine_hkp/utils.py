#!/usr/bin/env python

import copy

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
	try:
		while True:
			i -= 1
			try:
				ra[i] += 1
				break
			except ValueError, e:
				ra[i] = 0
	except IndexError, e:
		return None

	return ra

# see https://stackoverflow.com/a/17511341
def ceildiv(a, b):
	"""see https://stackoverflow.com/a/17511341"""
	return -(-a // b)

def linewrap(string, linelen=64):
	return "\n".join([string[linelen*i:linelen*(i+1)] for i in range(0,ceildiv(len(string),linelen))])
