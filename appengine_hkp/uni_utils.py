#!/usr/bin/env python

import unicodedata
import py2casefold

# see Unicode 3.13
# http://www.unicode.org/versions/Unicode9.0.0/ch03.pdf
_toCasefold = py2casefold.casefold
_NFKD = lambda x: unicodedata.normalize('NFKD', x)
_NFD = lambda x: unicodedata.normalize('NFD', x)

def canonical_casefold(x):
	return _NFD(_toCasefold(_NFD(x)))

def compatibility_casefold(x):
	return _NFKD(_toCasefold(_NFKD(_toCasefold(_NFD(x)))))

