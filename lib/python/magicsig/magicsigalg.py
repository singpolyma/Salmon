#!/usr/bin/python2.4
#
# Copyright 2009 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Implementation of Magic Signatures low level operations.

See Magic Signatures RFC for specification.  This implements
the cryptographic layer of the spec, essentially signing and
verifying byte buffers using a public key algorithm.
"""

__author__ = 'jpanzer@google.com (John Panzer)'


import base64
import re
import logging

# PyCrypto: Note that this is not available in the
# downloadable GAE SDK, must be installed separately.
# See http://code.google.com/p/googleappengine/issues/detail?id=2493
# for why this is most easily installed under the
# project's path rather than somewhere more sane.
import Crypto.PublicKey
import Crypto.PublicKey.RSA
from Crypto.Util import number

import hashlib


# Note that PyCrypto is a very low level library and its documentation
# leaves something to be desired.  As a cheat sheet, for the RSA
# algorithm, here's a decoding of terminology:
#     n - modulus (public)
#     e - public exponent
#     d - private exponent
#     (n, e) - public key
#     (n, d) - private key
#     (p, q) - the (private) primes from which the keypair is derived.

# Thus a public key is a tuple (n,e) and a public/private key pair
# is a tuple (n,e,d).  Often the exponent is 65537 so for convenience
# we default e=65537 in this code.


def GenSampleSignature(text):
  """Demo using a hard coded, test public/private keypair."""
  demo_keypair = ('RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1'
                  'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww=='
                  '.AQAB'
                  '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5'
                  'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==')

  signer = SignatureAlgRsaSha256(demo_keypair)
  return signer.Sign(text)


# Utilities
def _NumToB64(num):
  """Turns a bignum into a urlsafe base64 encoded string."""
  return base64.urlsafe_b64encode(number.long_to_bytes(num))


def _B64ToNum(b64):
  """Turns a urlsafe base64 encoded string into a bignum."""
  return number.bytes_to_long(base64.urlsafe_b64decode(b64))

# Patterns for parsing serialized keys
_WHITESPACE_RE = re.compile(r'\s+')
_KEY_RE = re.compile(
    r"""RSA\.
      (?P<mod>[^\.]+)
      \.
      (?P<exp>[^\.]+)
      (?:\.
        (?P<private_exp>[^\.]+)
      )?""",
    re.VERBOSE)


def RSAToString(keypair, full_key_pair=True):
  """Serializes key to a safe string storage format.

  Args:
    keypair: An RSAobj
    full_key_pair: Whether to save the private key portion as well.
  Returns:
    The string representation of the key in the format:

      RSA.mod.exp[.optional_private_exp]

    Each component is a urlsafe-base64 encoded representation of
    the corresponding RSA key field.
  """
  mod = _NumToB64(keypair.n)
  exp = '.' + _NumToB64(keypair.e)
  private_exp = ''
  if full_key_pair and keypair.d:
    private_exp = '.' + _NumToB64(keypair.d)
  return 'RSA.' + mod + exp + private_exp

def RSAFromString(text):
  """Parses key from a standard string storage format.

  Args:
    text: The key in text form.  See ToString for description
      of expected format.
  Raises:
    ValueError: The input format was incorrect.
  """
  # First, remove all whitespace:
  text = re.sub(_WHITESPACE_RE, '', text)

  # Parse out the period-separated components
  match = _KEY_RE.match(text)
  if not match:
    raise ValueError('Badly formatted key string: "%s"', text)

  private_exp = match.group('private_exp')
  if private_exp:
    private_exp = _B64ToNum(private_exp)
  else:
    private_exp = None
  return Crypto.PublicKey.RSA.construct(
      (_B64ToNum(match.group('mod')),
       _B64ToNum(match.group('exp')),
        private_exp))
