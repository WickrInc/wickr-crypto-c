#!/usr/bin/env python
#
# Copyright 2017 John-Mark Gurney.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#

'''This is a wrapper around Ed448-Goldilocks.

This module does not follow the standard Crypto modular method
of signing due to the complexity of integration w/ the library, and
that things should be more simple to use.'''

__author__ = 'John-Mark Gurney'
__copyright__ = 'Copyright 2017 John-Mark Gurney'''
__license__ = 'BSD'
__version__ = '0.1'
__status__ = 'alpha'

import array
import os
import os.path
import sys
import unittest
import warnings

from ctypes import *

try:
	_dname = os.path.dirname(__file__)
	if not _dname:
		_dname = '.'
	_path = os.path.join(_dname, 'libdecaf.so')
	decaf = CDLL(_path)
except OSError as e: # pragma: no cover
	import warnings
	warnings.warn('libdecaf.so not installed.')
	raise ImportError(str(e))

DECAF_EDDSA_448_PUBLIC_BYTES = 57
DECAF_EDDSA_448_PRIVATE_BYTES = DECAF_EDDSA_448_PUBLIC_BYTES
DECAF_EDDSA_448_SIGNATURE_BYTES = DECAF_EDDSA_448_PUBLIC_BYTES + DECAF_EDDSA_448_PRIVATE_BYTES

# Types

ed448_pubkey_t = c_uint8 * DECAF_EDDSA_448_PUBLIC_BYTES
ed448_privkey_t = c_uint8 * DECAF_EDDSA_448_PRIVATE_BYTES
ed448_sig_t = c_uint8 * DECAF_EDDSA_448_SIGNATURE_BYTES

c_uint8_p = POINTER(c_uint8)

decaf_error_t = c_int

# Data
try:
	DECAF_ED448_NO_CONTEXT = POINTER(c_uint8).in_dll(decaf, 'DECAF_ED448_NO_CONTEXT')
except ValueError:
	DECAF_ED448_NO_CONTEXT = None

funs = {
	'decaf_ed448_derive_public_key': (None, [ ed448_pubkey_t, ed448_privkey_t]),
	'decaf_ed448_sign': (None, [ ed448_sig_t, ed448_privkey_t, ed448_pubkey_t, c_uint8_p, c_size_t, c_uint8, c_uint8_p, c_uint8 ]),
	'decaf_ed448_verify': (decaf_error_t, [ ed448_sig_t, ed448_pubkey_t, c_uint8_p, c_size_t, c_uint8, c_uint8_p, c_uint8 ]),
}

for i in funs:
	f = getattr(decaf, i)
	f.restype, f.argtypes = funs[i]

def _makeba(s):
	r = (c_ubyte * len(s))()
	r[:] = array.array('B', s)
	return r

def _makestr(a):
	# XXX - because python3 sucks, and unittest doesn't offer
	# ability to silence stupid warnings, hide the tostring
	# DeprecationWarning.
	with warnings.catch_warnings():
		warnings.simplefilter('ignore')
		return array.array('B', a).tostring()


def _ed448_privkey():
	return _makeba(os.urandom(DECAF_EDDSA_448_PRIVATE_BYTES))

class EDDSA448(object):
	_PUBLIC_SIZE = DECAF_EDDSA_448_PUBLIC_BYTES
	_PRIVATE_SIZE = DECAF_EDDSA_448_PRIVATE_BYTES
	_SIG_SIZE = DECAF_EDDSA_448_SIGNATURE_BYTES

	def __init__(self, priv=None, pub=None):
		'''Generate a new sign or verify object.  At least one
		of priv or pub MUST be specified.

		If pub is not specified, it will be generated from priv.
		If both are specified, there is no verification that pub
		is the public key for priv.

		It is recommended that you use the generate method to
		generate a new key.'''

		if priv is None and pub is None:
			raise ValueError('at least one of priv or pub must be specified.')

		if priv is not None:
			try:
				priv = _makeba(priv)
			except Exception as e:
				raise ValueError('priv must be a byte string', e)

		self._priv = priv

		if self._priv is not None and pub is None:
			self._pub = ed448_pubkey_t()
			decaf.decaf_ed448_derive_public_key(self._pub, self._priv)
		else:
			self._pub = _makeba(pub)

	@classmethod
	def generate(cls):
		'''Generate a signing object w/ a newly generated key.'''

		return cls(priv=_ed448_privkey())

	def has_private(self):
		'''Returns True if object has private key.'''

		return self._priv is not None

	def public_key(self):
		'''Returns a new object w/o the private key.  This new
		object will have the public part and can be used for
		verifying messages'''

		return self.__class__(pub=self._pub)

	def export_key(self, format):
		'''Export the key.  The only format supported is 'raw'.

		If has_private is True, then the private part will be
		exported.  If it is False, then the public part will be.
		There is no indication on the output if the key is
		public or private.  It must be tracked independantly
		of the data.'''

		if format == 'raw':
			if self._priv is None:
				return _makestr(self._pub)
			else:
				return _makestr(self._priv)
		else:
			raise ValueError('unsupported format: %s' % repr(format))

	@staticmethod
	def _makectxargs(ctx):
		if ctx is None:
			ctxargs = (DECAF_ED448_NO_CONTEXT, 0)
		else:
			ctxargs = (_makeba(ctx), len(ctx))

		return ctxargs

	def sign(self, msg, ctx=None):
		'''Returns a signature over the message.  Requires that has_private returns True.'''

		sig = ed448_sig_t()
		ctxargs = self._makectxargs(ctx)
		decaf.decaf_ed448_sign(sig, self._priv, self._pub, _makeba(msg), len(msg), 0, *ctxargs)

		return _makestr(sig)

	def verify(self, sig, msg, ctx=None):
		'''Raises an error if sig is not valid for msg.'''

		_sig = ed448_sig_t()
		_sig[:] = array.array('B', sig)
		ctxargs = self._makectxargs(ctx)
		if not decaf.decaf_ed448_verify(_sig, self._pub, _makeba(msg), len(msg), 0, *ctxargs):
			raise ValueError('signature is not valid')

def generate(curve='ed448'):
	return EDDSA448.generate()

class TestEd448(unittest.TestCase):
	def test_init(self):
		self.assertRaises(ValueError, EDDSA448)

	def test_gen(self):
		key = generate(curve='ed448')
		self.assertIsInstance(key, EDDSA448)

		self.assertTrue(key.has_private())

		pubkey = key.public_key()
		self.assertFalse(pubkey.has_private())

	def test_keyexport(self):
		# Generate key and export
		key = generate(curve='ed448')
		privkey = key.export_key('raw')

		# Generate signature
		message = b'sdlkfjsdf'
		sig = key.sign(message)

		# Verify that the key can be imported and verifies
		key2 = EDDSA448(privkey)
		key2.verify(sig, message)

		# Export the public key
		keypub = key.public_key()
		pubkey = keypub.export_key('raw')

		# Verify that the public key can be imported and verifies
		key3 = EDDSA448(pub=pubkey)
		key3.verify(sig, message)

		self.assertRaises(ValueError, key.export_key, 'PEM')

	def test_keyimportexport(self):
		privkey = b'1' * DECAF_EDDSA_448_PRIVATE_BYTES
		key = EDDSA448(privkey)

		self.assertEqual(key.export_key(format='raw'), privkey)

		key = EDDSA448(pub=b'1' * DECAF_EDDSA_448_PUBLIC_BYTES)

		self.assertRaises(ValueError, EDDSA448, priv=u'1' * DECAF_EDDSA_448_PRIVATE_BYTES)

	def test_sig(self):
		key = generate()

		message = b'this is a test message for signing'
		sig = key.sign(message)

		# Make sure sig is a string of bytes
		self.assertIsInstance(sig, bytes)
		self.assertEqual(len(sig), EDDSA448._SIG_SIZE)

		# Make sure sig is valid
		key.verify(sig, message)

		# Make sure sig is valid for public only version
		pubkey = key.public_key()
		pubkey.verify(sig, message)

		# Ensure that the wrong message fails
		message = b'this is the wrong message'
		self.assertRaises(ValueError, pubkey.verify, sig, message)

	def test_ctx(self):
		key = generate()

		message = b'foobar'
		ctx = b'contexta'
		sig = key.sign(message, ctx)

		# Make sure it verifies correctly
		key.verify(sig, message, ctx)

		# Make sure it fails w/o context
		self.assertRaises(ValueError, key.verify, sig, message)

		# Make sure it fails w/ invalid/different context
		self.assertRaises(ValueError, key.verify, sig, message, ctx + b'a')

class TestBasicLib(unittest.TestCase):
	def test_basic(self):
		priv = _ed448_privkey()
		pub = ed448_pubkey_t()

		decaf.decaf_ed448_derive_public_key(pub, priv)

		message = b'this is a test message'

		sig = ed448_sig_t()
		decaf.decaf_ed448_sign(sig, priv, pub, _makeba(message), len(message), 0, None, 0)

		r = decaf.decaf_ed448_verify(sig, pub, _makeba(message), len(message), 0, None, 0)
		self.assertTrue(r)

		message = b'aofeijseflj'
		r = decaf.decaf_ed448_verify(sig, pub, _makeba(message), len(message), 0, None, 0)
		self.assertFalse(r)
