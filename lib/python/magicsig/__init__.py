#!/usr/bin/python2.4
#
# Copyright 2009 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Implementation of Magic Signatures protocol.

See Magic Signatures RFC for specification.  This module
implements the Magic Signature API on top of the crypto
layer in magicsigalg.py, hiding the low level crypto details.
"""

__author__ = 'jpanzer@google.com (John Panzer)'


import base64
import re
import sys
import time
import urllib
import OpenPGP
import OpenPGP.Crypto
from Crypto.Util import number

# ElementTree is standard with Python >=2.5, needs
# environment support for 2.4 and lower.
try:
  import xml.etree.ElementTree as et  # Python >=2.5
except ImportError:
  try:
    import elementtree as et  # Allow local path override
  except ImportError:
    raise

_WHITESPACE_RE = re.compile(r'\s+')


class Error(Exception):
  """Error thrown for generic magic envelope failures."""

  def __init__(self):
    Exception.__init__(self)


def NormalizeUserIdToUri(userid):
  """Normalizes a user-provided user id to a reasonable guess at a URI."""
  userid = userid.strip()

  # If already in a URI form, we're done:
  if (userid.startswith('http:') or
      userid.startswith('https:') or
      userid.startswith('acct:')):
    return userid

  if userid.find('@') > 0:
    return 'acct:'+userid

  # Catchall:  Guess at http: if nothing else works.
  return 'http://'+userid


def _GetElementByTagName(e, ns, tag_name):
  """Retrieves a unique element from a DOM subtree by name.

  Convenience wrapper for the case where the format
  dictates exactly-once semantics.

  Args:
    e: Root element of DOM subtree.
    ns: Namespace of desired element.
    tag_name: Name of desired element.
  Raises:
    ValueError: If the element was not unique or not found.
  Returns:
    The desired element.
  """
  seq = e.getElementsByTagNameNS(unicode(ns), unicode(tag_name))
  if seq.length == 0: raise ValueError('Element %s not found' % tag_name)
  if seq.length > 1: raise ValueError('Element %s appears multiple times' %
                                      tag_name)
  return seq.item(0)


class KeyRetriever(object):
  """Retrieves public or private keys for a signer identifier (URI)."""

  def LookupPublicKey(self, signer_uri):
    # TODO(jpanzer): Really look this up with Webfinger.
    if not signer_uri:
      return None
    return (8031283789075196565022891546563591368344944062154100509645398892293433370859891943306439907454883747534493461257620351548796452092307094036643522661681091, 65537, 2411823798049787808355822337426462024816467706597110824882602127030945300698688657448540895366210592380576050280953899102635751538748696981555132000814065)

  def LookupPrivateKey(self, signer_uri):
    """Look up signing key for a given signer URI."""
    # TODO(jpanzer): Fix this up to really work, or eliminate.
    return self.LookupPublicKey(signer_uri)

_ATOM_NS_URL = 'http://www.w3.org/2005/Atom'
_ME_NS_URL = 'http://salmon-protocol.org/ns/magic-env'
_ATOM_NS='{%s}' % _ATOM_NS_URL
_ME_NS='{%s}' % _ME_NS_URL

# Set up default namespace mappings for things we care about:
try:
  __register_namespace = et.register_namespace
except AttributeError:
  def __register_namespace(prefix, uri):
    et._namespace_map[uri] = prefix
__register_namespace('atom', _ATOM_NS_URL)
__register_namespace('me', _ME_NS_URL)
__register_namespace('thr', 'http://purl.org/syndication/thread/1.0')

class MagicEnvelopeProtocol(object):
  """Implementation of Magic Envelope protocol."""

  ENCODING = 'rfc2397'  # This is a constant for now.
  key_retriever = KeyRetriever()

  def GetPrivateKey(self, signer_uri):
    """Retrieves private signing key to be used."""
    return self.key_retriever.LookupPrivateKey(signer_uri)

  def GetPublicKey(self, signer_uri):
    """Retrieves public key to be used to verify signatures for signer."""
    return self.key_retriever.LookupPublicKey(signer_uri)

  def GetSignerURI(self, data):
    """Grabs signer == first author from given message.

    Currently we're assuming most messages are single author
    and punting on what it means to sign a multi-author
    message.  We only look at the first (lexical) author
    in the input and act as if that is the only author.

    Args:
      data: The message, either pre-parsed or a string.
    Returns:
      The URI of the author of the message.
    """
    if isinstance(data, et.ElementTree):
      d = data
    else:
      d = et.ElementTree()
      d._setroot(et.XML(data))

    auth_uris = d.getroot().findall(_ATOM_NS+'author/'+_ATOM_NS+'uri')
    for u in auth_uris:
      return NormalizeUserIdToUri(u.text)

  def IsAllowedSigner(self, data, userid_uri):
    """Checks that userid_uri is identified as an allowed signer.

    Note that this does not do a signature check.

    Args:
      data: The message, either pre-parsed or a string.
      userid_uri: The URI of the author to be checked.
    Returns:
      True iff userid_uri is identified as the first author.
    """
    return self.GetSignerURI(data) == userid_uri

  def Verify(self, env):
    """Verifies magic envelope data.

    Checks that its signature matches the contents and that the
    author's public key generated the signature.

    Args:
      env: The magic envelope data in dict form (section 3.1 of spec)
    Returns:
      True iff the signature is verified.
    """
    assert env['alg'].split('-')[0] == 'RSA'
    assert env['encoding'] == self.ENCODING

    # Decode data to text and grab the author:
    text = self.DecodeData(env['data'].encode('utf-8'), env['encoding'])
    signer_uri = self.GetSignerURI(text)

    verifier = OpenPGP.Crypto.RSA(self.GetKeypair(signer_uri))

    return verifier.verify(env)

  def GetSigningAlg(self, signing_key):
    """Returns algorithm to use for signing messages.

    Args:
      signing_key: Keypair to use to construct the algorithm.
    Returns:
      An algorithm object that can be used to sign byte sequences.
    """
    # TODO(jpanzer): Massage signing_key into appropriate format if needed.

    # Use standard test key if testing:
    if signing_key == 'TEST':
      signing_key = (8031283789075196565022891546563591368344944062154100509645398892293433370859891943306439907454883747534493461257620351548796452092307094036643522661681091, 65537, 2411823798049787808355822337426462024816467706597110824882602127030945300698688657448540895366210592380576050280953899102635751538748696981555132000814065)

    return OpenPGP.Crypto.RSA(signing_key)

  def GetVerifierAlg(self, public_key):
    """Returns algorithm to use for verifying messages.

    Args:
      public_key: Public key to use to construct the algorithm.
    Returns:
      An algorithm object that can be used to sign byte sequences.
    """
    # TODO(jpanzer): Massage public_key into appropriate format if needed.
    return OpenPGP.Crypto.RSA(public_key)

  def EncodeData(self, raw_text_data, encoding, mime_type=None):
    """Encodes raw data into an armored form.

    Args:
      raw_text_data: Textual data to be encoded; should be in utf-8 form.
      encoding: Encoding to use
    Raises:
      ValueError: The encoding is unknown or missing.
    Returns:
      The encoded data in the specified format.
    """
    if not mime_type:
        mime_type = 'application/octet-stream'
    if isinstance(raw_text_data, long):
        raw_text_data = number.long_to_bytes(raw_text_data)

    if encoding == 'base64url':
        return base64.urlsafe_b64encode(raw_text_data).encode('utf-8')
    elif encoding == 'rfc2397':
        return ('data:' + mime_type + ';base64,' + \
            base64.standard_b64encode(raw_text_data)).encode('utf-8')
    elif encoding == 'raw':
        if isinstance(raw_text_data, unicode):
            return raw_text_data.encode('utf-8')
        return raw_text_data
    else:
      raise ValueError('Unknown encoding %s' % encoding)

  def DecodeData(self, encoded_text_data, encoding):
    """Decodes armored data into raw text form.

    Args:
      encoded_text_data: Armored data to be decoded.
      encoding: Encoding to use.
    Raises:
      ValueError: If the encoding is unknown.
    Returns:
      The raw decoded text as a string.
    """
    if encoding == 'base64url':
        return base64.urlsafe_b64decode(encoded_text_data.encode('utf-8'))
    elif encoding == 'rfc2397':
        parts = encoded_text_data.encode('utf-8').split(',', 1)
        if parts[0].split(';')[-1:][0] == 'base64':
            return base64.standard_b64decode(parts[1])
        else:
            return urllib.unquote(parts[1])
    elif encoding == 'raw':
        return encoded_text_data
    else:
      raise ValueError('Unknown encoding %s' % encoding)

  def ParseData(self, raw_text_data, mime_type):
    """Parses the payload of a magic envelope's data field.

    Args:
      raw_text_data: Data in given MIME type.
      mime_type: Type of the textual data.  application/atom+xml supported
    Raises:
      ValueError: The input format was unrecognized or badly formed.
    Returns:
      Parsed data suitable for passing in to other methods of this object.
    """
    if mime_type != 'application/atom+xml':
      raise ValueError('Unknown MIME type %s' % mime_type)

    d = et.ElementTree()
    d._setroot(et.XML(raw_text_data))

    return d

  def Parse(self, textinput, mime_type='application/atom+xml'):
    """Parses a magic envelope.

    Args:
      textinput: Input message in either application/pgp-encrypted
        or application/atom format.
      mime_type: MIME type of textinput data.
    Raises:
      ValueError: The input format was unrecognized or badly formed.
    Returns:
      Magic envelope fields in dict format per section 3.1 of spec.
    """
    encoding = None
    if mime_type == 'application/atom+xml':
        d = et.ElementTree()
        d._setroot(et.XML(textinput.strip()))

        if d.getroot().tag == _ATOM_NS+'feed':
            d._setroot(d.find(_ATOM_NS+'entry'))

        data_el = None
        if d.getroot().tag == _ATOM_NS+'entry':
          for el in d.findall(_ATOM_NS+'link'):
              if el.get('rel').split(' ').count('alternate') > 0 \
                 and el.get('type') == 'application/pgp-encrypted':
                  data_el = el
                  break
        else:
          raise ValueError('Unrecognized input format')

        encoding = 'rfc2397'
        data = data_el.get('href')
    elif mime_type == 'application/pgp-encrypted': # Raw binary OpenPGP
        encoding = 'raw'
        data = textinput
    else:
        raise ValueError('Unrecognized input format')

    m = OpenPGP.Message.parse(self.DecodeData(data, encoding))
    logging.error(m._packets)
    signature_packet, data_packet = m.signature_and_data()
    return ({'encoding': encoding,
            'algorithm': signature_packet.key_algorithm_name() \
            + '-' + signature_packet.hash_algorithm_name(),
            'data_type': data_packet.filename,
            'sig': data,
            'data': data_packet.data})

class EnvelopeError(Error):
  """Error thrown on failure to initialize an Envelope."""
  invalid_envelope = None  # The failed envelope
  error_text = None  # Human readable error text
  context = None  # Tuple of type,value from chained exception if any

  def __init__(self, envelope, err, context=None):
    self.invalid_envelope = envelope
    self.error_text = err
    self.context = context
    Error.__init__(self)

  def __str__(self):
    return '<magicsig.Error "%s" for envelope %s (prior exception: %s)>' % (
        self.error_text, self.invalid_envelope, self.context)


class Envelope(object):
  """Represents a Magic Envelope."""

  # Envelope contents (verified)
  _data = None  # The payload data as a string
  _data_type = None  # The MIME type of the payload
  _encoding = None  # The encoding to use ("base64url")
  _alg = None  # The algorithm used ("RSA")
  _sig = None  # The signature string

  _parsed_data = None  # The data as a parsed object
  _signer_uri = None  # URI of signer
  _signer_key = None  # Key(pair) associated w/signature

  _init_timestamp = None  # Timestamp when signed or verified

  def __init__(self,
               protocol=MagicEnvelopeProtocol(),
               **kwargs):
    """Initializes an envelope from arbitrary input."""
    try:
      self._protocol = protocol
      self._Initialize(kwargs)

      if self._sig:  # Verify signature if provided
        self._PerformVerification()
      elif self._signer_key:  # Sign w/signer key if provided
        self._Sign()
      else:
        raise EnvelopeError(self, 'Can neither verify nor sign envelope')
    except EnvelopeError:
      raise
    #except:
    #  raise EnvelopeError(self, 'Unknown envelope failure %s' %
    #                      sys.exc_info()[:1],
    #                      sys.exc_info()[:2])

    # Record when object successfully initialized.  This
    # also serves as a validity flag.
    self._init_timestamp = time.time()

  def _Initialize(self, kwargs):
    """Initializes envelope data from input."""
    # Input from serialized text document if provided:
    self._mime_type = kwargs.get('mime_type', 'application/atom+xml')
    self._document = kwargs.get('document', None)

    if self._document:
      # If document provided, use it to parse out fields:
      fields = self._protocol.Parse(self._document, self._mime_type)
      kwargs.update(fields)

    # Pull structured data from kwargs and sanity check:
    self._data = kwargs.get('data', None)
    self._data_type = kwargs.get('data_type', None)
    self._encoding = kwargs.get('encoding', 'rfc2397')
    self._alg = kwargs.get('alg', 'RSA-SHA256')
    self._sig = kwargs.get('sig', None)
    if self._sig and not isinstance(self._sig, long):
        self._sig = self._protocol.DecodeData(self._sig, self._encoding)

    # Sanity checks:
    if not self._data_type:
      raise EnvelopeError(self, 'Missing data_type')
    if self._alg != 'RSA-SHA256':
      raise EnvelopeError(self, 'Unknown alg %s; must be RSA-SHA256' %
                          self._alg)
    if self._encoding != 'base64url' and self._encoding != 'rfc2397' \
       and self._encoding != 'raw':
      raise EnvelopeError(self, 'Unknown encoding %s; must be base64url' %
                          self._encoding)

    raw_data = kwargs.get('raw_data_to_sign', None)
    if raw_data:
      # If passed raw data to sign, the envelope goes into signing mode.
      assert self._data_type
      assert not self._sig
      assert not self._data
      assert 'signer_uri' in kwargs
      assert 'signer_key' in kwargs  # And it better be a keypair too!

      self._parsed_data = self._protocol.ParseData(raw_data,
                                                   self._data_type)
      self._data = raw_data
      self._signer_uri = kwargs['signer_uri']
      self._signer_key = kwargs['signer_key']
    elif self._sig:
      # If passed a signature, the envelope goes into verify mode.
      if not self._data:
        raise EnvelopeError(self, 'No data to verify')
      raw_data = self._data # data with signatures is not encoded
    else:
      # No raw data and no signature, give up.
      raise EnvelopeError(self, 'Insufficient data to initialize envelope.')

    # Cache a parsed representation of the raw data:
    self._parsed_data = self._protocol.ParseData(raw_data, self._data_type)

    # At this point the envelope is initialized but is not yet valid.
    # (It needs to be either verified or signed.)
    self._init_timestamp = None

  def Age(self):
    """Age of object since successful verification."""
    assert self._init_timestamp

    return self._init_timestamp - time.time()

  def _Sign(self):
    """Signs an envelope given appropriate key inputs."""
    assert self._signer_uri
    assert self._signer_key
    assert self._protocol.IsAllowedSigner(self._parsed_data, self._signer_uri)

    alg = self._protocol.GetSigningAlg(self._signer_key)
    packet = OpenPGP.LiteralDataPacket(self._data, 'u', self._data_type)
    self._sig = self._protocol.EncodeData(alg.sign(packet).to_bytes(),
                    self._encoding, 'application/pgp-encrypted')

    # Hmm.  This seems like a no-brainer assert but what if you're
    # signing something with a not-yet-published public key?
    assert alg.verify(self._protocol.DecodeData(self._sig, self._encoding))

    # TODO(jpanzer): Clear private key data from object?

  def _PerformVerification(self):
    """Performs signature verification on parsed data."""
    # Decode data to text, cache parsed representation,
    # and find the key to use:
    self._parsed_data = self._protocol.ParseData(self._data, self._data_type)
    self._signer_uri = self._protocol.GetSignerURI(self._parsed_data)
    self._signer_public_key = self._protocol.GetPublicKey(self._signer_uri)

    # Get a verifier for that key:
    verifier = self._protocol.GetVerifierAlg(self._signer_public_key)

    # Check whether the signature verifies; if not, abandon
    # this envelope.
    if not verifier.verify(self._sig):
      raise EnvelopeError(self, 'Signature verification failed.')

  def ToBytes(self):
    """Outputs raw serialization of envelope"""
    assert self._init_timestamp  # Object must be successfully initialized
    return self._protocol.DecodeData(self._sig, self._encoding)

  def ToXML(self, fulldoc=True, indentation=0):
    """Turns envelope into serialized XML suitable for transmission.

    Args:
      fulldoc: Return a full XML document with <?xml...
      indentation: Indent each line this number of spaces.
    Returns:
      An XML document or fragment in string form.
    """
    assert self._init_timestamp  # Object must be successfully initialized
    # TODO(jpanzer): Determine leeway period before requiring another
    # verification
    # (we can't keep an object sitting around in memory for a month without
    # rechecking the signature).

    # Template for a Magic Envelope:
    if fulldoc:
      template = '<?xml version=\'1.0\' encoding=\'UTF-8\'?>'
    else:
      template = ''
    template += """
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <link type="application/pgp-encrypted" rel="alternate" href="%s" />
  </entry>
</feed>
"""
    text = template % self._sig
    indented_text = ''
    for line in text.strip().split('\n'):
      indented_text += ' '*indentation + line + '\n'

    return indented_text

  def ToAtom(self, fulldoc=True, indentation=0):
    """Turns envelope into serialized Atom entry.

    Args:
      fulldoc: Return a full XML document with <?xml...
      indentation: Indent each line this number of spaces.
    Returns:
      An Atom entry XML document with a link element
      containing the original magic signature data.
    """
    if not self._parsed_data:
      self._parsed_data = self._protocol.ParseData(text, self._data_type)

    d = self._parsed_data
    assert d.getroot().tag == _ATOM_NS+'entry'

    # Create a provenance and add it in.
    data_el = et.Element(_ATOM_NS+'link')
    data_el.set('type', 'application/pgp-encrypted')
    data_el.set('rel', 'alternate')
    data_el.set('href', self._protocol.EncodeData(self._sig, 'rfc2397', \
                'application/pgp-encrypted'))

    # Add in the provenance element:
    d.getroot().append(data_el)

    # Prettify:
    self._PrettyIndent(d.getroot(), indentation/2)

    # Turn it back into text for consumption:
    text = et.tostring(d.getroot(),encoding='utf-8')

    indented_text = ''
    for line in text.strip().split('\n'):
      if line.strip() != '':
        indented_text += ' '*indentation + line + '\n'

    if fulldoc:
      indented_text = ('<?xml version=\'1.0\' encoding=\'UTF-8\'?>\n' +
                       indented_text)
    return indented_text

  def GetData(self):
    """Returns envelope's verified data."""
    return self._protocol.Decode(self._data, self._encoding)

  def GetParsedData(self):
    """Returns envelope's verified data in parsed form."""
    if not self._parsed_data:
      self._parsed_data = self._protocol.ParseData(
          self._protocol.Decode(self._data),
          self._data_type)
    return self._parsed_data

  def GetDataWithProvenance(self):
    """Returns envelope's data as a string with provenance attached."""
    # TODO(jpanzer): Implement.

  def GetParsedDataWithProvenance(self):
    """Returns data with provenance in parsed form."""
    # TODO(jpanzer): Implement.


  def _PrettyIndent(self, elem, level=0):
    """Prettifies an element tree in-place"""
    # TODO(jpanzer): Avoid munging text nodes where it matters?
    i = "\n" + level*"  "
    if len(elem):
      if not elem.text or not elem.text.strip():
         elem.text = i + "  "
      if not elem.tail or not elem.tail.strip():
        elem.tail = i
      for elem in elem:
        self._PrettyIndent(elem, level+1)
      if not elem.tail or not elem.tail.strip():
        elem.tail = i
    else:
      if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = i

def _ToPretty(text, indent, linelength):
  """Makes huge text lines pretty, or at least printable."""
  tl = linelength - indent
  output = ''
  for i in range(0, len(text), tl):
    if output:
      output += '\n'
    output += ' ' * indent + text[i:i+tl]
  return output
