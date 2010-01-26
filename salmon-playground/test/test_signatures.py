#!/usr/bin/python
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

"""Tests for signatures.py."""

__author__ = 'jpanzer@google.com (John Panzer)'

import re
import unittest
import signatures


def _StripWS(s):
  """Strips all whitespace from a string."""
  return re.sub('\s+', '', s)


class TestSignature(unittest.TestCase):
  """Tests signatures module."""

  _test_publickey = ('RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1'
                     'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww==.AQAB')

  _test_keypair = ('RSA.mVgY8RN6URBTstndvmUUPb4UZTdwvwmddSKE5z_jvKUEK6yk1'
                   'u3rrC9yN8k6FilGj9K0eeUPe2hf4Pj-5CmHww=='
                   '.AQAB'
                   '.Lgy_yL3hsLBngkFdDw1Jy9TmSRMiH6yihYetQ8jy-jZXdsZXd8V5'
                   'ub3kuBHHk4M39i3TduIkcrjcsiWQb77D8Q==')

  def setUp(self):
    # Well known keys to use for testing:
    self.signer = signatures.SignatureAlgRsaSha1(self._test_keypair)
    self.verifier = signatures.SignatureAlgRsaSha1(self._test_publickey)

  def testNumberSerialization(self):
    # Just for extra paranoia, as the underlying libraries don't have tests:
    self.assertEquals(signatures._NumToB64(1), 'AQ==')

    # This will fail if someone swaps to little endian by accident:
    self.assertEquals(signatures._NumToB64(65537), 'AQAB')

    # Test round tripping of a realistically large number:
    n = pow(2, 2048) + 42
    b64 = signatures._NumToB64(n)
    self.assertEquals(signatures._B64ToNum(b64), n)

  def testBadKey(self):
    # Bad input should raise appropriate exceptions
    self.assertRaises(ValueError,
                      signatures.SignatureAlgRsaSha1, 'Barney the dinosaur')
    self.assertRaises(TypeError,
                      signatures.SignatureAlgRsaSha1, 42)

  def testRsaSignature(self):
    text = unicode('One small splash for a salmon, one giant '
                   'leap for salmonkind!', 'utf-8').encode('utf-8')
    sig = self.signer.Sign(text)

    # The just-signed (text,sig) tuple should validate:
    self.assertTrue(self.verifier.Verify(text, sig))

    # Even tiny modifications to the text should not validate:
    self.assertFalse(self.verifier.Verify(text+'a', sig))

  def testSerialization(self):
    # Round tripping should produce equal strings, modulo whitespace.
    self.assertEquals(_StripWS(self.signer.ToString()),
                      _StripWS(self._test_keypair))
    self.assertEquals(_StripWS(self.verifier.ToString()),
                      _StripWS(self._test_publickey))
    self.assertNotEquals(_StripWS(self.signer.ToString()),
                         _StripWS(self.verifier.ToString()))

