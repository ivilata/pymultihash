# pymultihash: Python implementation of the multihash specification
#
# Initial author: Ivan Vilata-i-Balaguer
# License: MIT

"""Python implementation of the multihash specification

This is an implementation of the `multihash`_ specification in Python.
The main component in the module is the `Multihash` class, a named tuple that
represents a hash function and a digest created with it, with extended
abilities to work with hashlib-compatible hash functions, verify the integrity
of data, and encode itself to a byte string in the binary format described in
the specification (possibly ASCII-encoded).  The `decode()` function can be
used for the inverse operation, i.e. converting a (possibly ASCII-encoded)
byte string into a `Multihash` object.

.. _multihash: https://github.com/jbenet/multihash

Basic usage
===========

Decoding
--------

One of the basic cases happens when you have a multihash-encoded digest like:

>>> mhash = b'EiAsJrRraP/Gj/mbRTwdMEE0E0ItcGSDv6D5il6IYmbnrg=='

You know beforehand that the multihash is Base64-encoded.  You also have some
data and you want to check if it matches that digest:

>>> data = b'foo'

To perform this check, you may first *decode* the multihash (i.e. parse it)
into a `Multihash` object, which provides the ``verify()`` method to validate
the given byte string against the encoded digest:

>>> import multihash
>>> mh = multihash.decode(mhash, 'base64')
>>> mh.verify(data)
True

Please note that you needed to specify that the multihash is Base64-encoded,
otherwise binary encoding is assumed (and the decoding will probably fail).
The verification internally uses a hashlib-compatible implementation of the
function indicated by the encoded multihash to check the data.  Read more
about codecs and hash functions further below.

The function in a `Multihash` object is stored as a member of the `Func`
enumeration, which contains one member per function listed in the `multihash`_
specification.  The name of a `Func` member is the name of that function in
the specification (with hyphens replaced by underscores), and its value is the
function code.  The `Multihash` object also contains the binary string with
the raw hash digest.  Application-specific hash functions are also supported,
but their numeric code is used instead of a `Func` member.

>>> mh  # doctest: +ELLIPSIS
Multihash(func=<Func.sha2_256: 18>, digest=b'...')
>>> hex(mh.func.value)
'0x12'
>>> len(mh.digest)
32

The short representation of a `Multihash` object only shows the function name
(or its code if application-specific), and the Base64-encoded version of the
raw hash digest:

>>> print(mh)
Multihash(sha2_256, b64:LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=)

If you need a shorter multihash, you may truncate it while keeping the initial
bytes of the raw hash digest.  A byte string validates against a truncated
multihash if its digest bytes match the initial bytes of the string's hash:

>>> mh_trunc = mh.truncate(16)
>>> print(mh_trunc)
Multihash(sha2_256, b64:LCa0a2j/xo/5m0U8HTBBNA==)
>>> mh_trunc.verify(data)
True

Encoding
--------

Now imagine that you have some data and you want to create a multihash out of
it.  First you must create a `Multihash` instance with the desired function
and the computed binary digest.  If you already know them, you may create the
`Multihash` instance directly:

>>> mh = multihash.Multihash(multihash.Func.sha2_512, b'...')
>>> print(mh)  # doctest: +ELLIPSIS
Multihash(sha2_512, b64:...)

Instead of the `Func` member, you may find more comfortable to use the
function name (e.g. ``'sha2-512'`` or ``'sha2_512'``) or its code (e.g. ``19``
or ``0x13``).  Or you may create `Multihash` instances straight from
hashlib-compatible objects:

>>> import hashlib
>>> hash = hashlib.sha1(data)
>>> mh = Multihash.from_hash(hash)
>>> print(mh)
Multihash(sha1, b64:C+7Hteo/D9vJXQ3UfzxbwnXaijM=)

However the easiest way to get a `Multihash` instance is with the `digest()`
function, which internally uses a hashlib-compatible implementation of the
indicated function to do the job for you:

>>> mh = multihash.digest(data, 'sha1')
>>> print(mh)
Multihash(sha1, b64:C+7Hteo/D9vJXQ3UfzxbwnXaijM=)

In any case, getting the multihash-encoded digest is very simple:

>>> mh.encode('base64')
b'ERQL7se16j8P28ldDdR/PFvCddqKMw=='

As before, an encoding (Base64) was specified to avoid getting the binary
version of the multihash.

The hash function registry
==========================

As the multihash specification indicates, you may use hash function codes in
the range 0x00-0x0f to specify application-specific hash functions.
The `decode()` function allows such multihashes, and the `Multihash`
constructor allows specifying such hash functions by their integer code:

>>> import multihash
>>> import hashlib
>>> data = b'foo'
>>> mh = multihash.Multihash(0x05, hashlib.md5(data).digest())
>>> print(mh)  # doctest: +ELLIPSIS
Multihash(0x5, b64:rL0Y20zC+Fzt72VPzMSk2A==)

However this does not allow using more intuitive strings instead of numbers
for application-specific functions, and digesting or verifying with such a
function is not possible:

>>> multihash.digest(data, 'md5')
Traceback (most recent call last):
    ...
KeyError: ('unknown hash function', 'md5')
>>> mh.verify(data)
Traceback (most recent call last):
    ...
KeyError: ('unknown hash function', 5)

The `FuncReg` class helps work around these problems by providing a registry
of hash functions.  You may add your application-specific hash functions there
with a code, a name, and optionally a name and a callable object for
hashlib-compatible operations:

>>> multihash.FuncReg.register(0x05, 'md-5', 'md5', hashlib.md5)
>>> multihash.digest(data, 'md-5')  # doctest: +ELLIPSIS
Multihash(func=5, digest=b'...')
>>> mh.verify(data)
True

You may remove your application-specific functions from the registry as well:

>>> multihash.FuncReg.unregister(0x05)

`FuncReg` also allows you to iterate over registered functions (as `Func`
members or function codes), and check if it contains a given function
(i.e. whether the `Func` or code is registered or not).

>>> [f.name for f in multihash.FuncReg if f == multihash.Func.sha3]
['sha3_512']
>>> 0x05 in multihash.FuncReg
False

The codec registry
==================

Although a multihash is properly a binary packing format for a hash digest, it
is not normally exchanged in binary form, but in some ASCII-encoded
representation of it.  As seen above, multihash decoding and encoding calls
support an ``encoding`` argument to allow ASCII decoding or encoding for
your convenience.

The encodings mentioned in the multihash standard are already enabled and
available by using their name (a string) as the ``encoding`` argument.
The ``base58`` encoding needs that the ``base58`` package is
installed, though.

The ``CodecReg`` class allows you to access the available codecs and register
your own ones (or replace existing ones) with a name and encoding and decoding
callables that get and return byte strings.  For instance, to add the uuencode
codec:

>>> import multihash
>>> import binascii
>>> multihash.CodecReg.register('uu', binascii.b2a_uu, binascii.a2b_uu)

To use it:

>>> mhash = b'6$10+[L>UZC\\\\/V\\\\E=#=1_/%O"==J*,P  \\n'
>>> mh = multihash.decode(mhash, 'uu')
>>> print(mh)
Multihash(sha1, b64:C+7Hteo/D9vJXQ3UfzxbwnXaijM=)
>>> mh.encode('uu') == mhash
True

You may remove any codec from the registry as well:

>>> multihash.CodecReg.unregister('uu')

`CodecReg` also allows you to iterate over registered codec names, and check
if it contains a given codec (i.e. whether it is registered or not).

>>> {'hex', 'base64'}.issubset(multihash.CodecReg)
True
>>> 'base32' in multihash.CodecReg
True
"""

from collections import namedtuple
from enum import Enum
from numbers import Integral

# Import standard hashlib-compatible modules.
import hashlib
# Import codecs mentioned in the multihash spec.
import binascii
import base64

# Try to import known optional hashlib-compatible modules.
try:
    import sha3
except ImportError:
    sha3 = None
try:
    import pyblake2 as blake2
except ImportError:
    blake2 = None
# Try to import external codecs mentioned in the multihash spec.
try:
    import base58
except ImportError:
    base58 = None


def _is_app_specific_func(code):
    """Is the given hash function integer `code` application-specific?"""
    return isinstance(code, Integral) and (0x00 <= code <= 0x0f)


class Func(Enum):
    """An enumeration of hash functions supported by multihash.

    The name of each member has its hyphens replaced by underscores.
    The value of each member corresponds to its integer code.

    >>> Func.sha2_512.value == 0x13
    True
    """
    sha1 = 0x11
    sha2_256 = 0x12
    sha2_512 = 0x13
    # See jbenet/multihash#11 for new SHA-3 function names and codes.
    sha3_512 = 0x14
    sha3 = sha3_512  # deprecated, for backwards compatibility
    sha3_384 = 0x15
    sha3_256 = 0x16
    sha3_224 = 0x17
    shake_128 = 0x18
    shake_256 = 0x19
    blake2b = 0x40
    blake2s = 0x41


class _FuncRegMeta(type):
    def __contains__(self, func):
        """Return whether `func` is a registered function.

        >>> FuncReg.reset()
        >>> Func.sha2_256 in FuncReg
        True
        """
        return func in self._func_hash

    def __iter__(self):
        """Iterate over registered functions.

        Standard multihash functions are represented as members of `Func`,
        while application-specific functions are integers.

        >>> FuncReg.reset()
        >>> set(FuncReg) == set(Func)
        True
        """
        return iter(self._func_hash)


class FuncReg(metaclass=_FuncRegMeta):
    """Registry of hash supported functions."""

    # Standard hash function data.
    _std_func_data = [  # (func, hash name, hash new)
        (Func.sha1, 'sha1', hashlib.sha1),

        (Func.sha2_256, 'sha256', hashlib.sha256),
        (Func.sha2_512, 'sha512', hashlib.sha512),

        (Func.sha3_512, 'sha3_512', sha3.sha3_512 if sha3 else None),
        (Func.sha3_384, 'sha3_384', sha3.sha3_384 if sha3 else None),
        (Func.sha3_256, 'sha3_256', sha3.sha3_256 if sha3 else None),
        (Func.sha3_224, 'sha3_224', sha3.sha3_224 if sha3 else None),

        (Func.shake_128, 'shake_128', None),
        (Func.shake_256, 'shake_256', None),

        (Func.blake2b, 'blake2b', blake2.blake2b if blake2 else None),
        (Func.blake2s, 'blake2s', blake2.blake2s if blake2 else None)]

    # Hashlib compatibility data for a hash: hash name (e.g. ``sha256`` for
    # SHA-256, ``sha2-256`` in multihash), and the corresponding constructor.
    _hash = namedtuple('hash', 'name new')

    @classmethod
    def reset(cls):
        """Reset the registry to the standard multihash functions."""
        # Maps function names (hyphens or underscores) to registered functions.
        cls._func_from_name = {}

        # Maps hashlib names to registered functions.
        cls._func_from_hash = {}

        # Hashlib compatibility data by function.
        cls._func_hash = {}

        register = cls._do_register
        for (func, hash_name, hash_new) in cls._std_func_data:
            register(func, func.name, hash_name, hash_new)
        assert set(cls._func_hash) == set(Func)

    @classmethod
    def get(cls, func_hint):
        """Return a registered hash function matching the given hint.

        The hint may be a `Func` member, a function name (with hyphens or
        underscores), or its code.  A `Func` member is returned for standard
        multihash functions and an integer code for application-specific ones.
        If no matching function is registered, a `KeyError` is raised.

        >>> fm = FuncReg.get(Func.sha2_256)
        >>> fnu = FuncReg.get('sha2_256')
        >>> fnh = FuncReg.get('sha2-256')
        >>> fc = FuncReg.get(0x12)
        >>> fm == fnu == fnh == fc
        True
        """
        # Different possibilities of `func_hint`, most to least probable.
        try:  # `Func` member (or its value)
            return Func(func_hint)
        except ValueError:
            pass
        if func_hint in cls._func_from_name:  # `Func` member name, extended
            return cls._func_from_name[func_hint]
        if func_hint in cls._func_hash:  # registered app-specific code
            return func_hint
        raise KeyError("unknown hash function", func_hint)

    @classmethod
    def _do_register(cls, code, name, hash_name=None, hash_new=None):
        """Add hash function data to the registry without checks."""
        cls._func_from_name[name.replace('-', '_')] = code
        cls._func_from_name[name.replace('_', '-')] = code
        if hash_name:
            cls._func_from_hash[hash_name] = code
        cls._func_hash[code] = cls._hash(hash_name, hash_new)

    @classmethod
    def register(cls, code, name, hash_name=None, hash_new=None):
        """Add an application-specific function to the registry.

        Registers a function with the given `code` (an integer) and `name` (a
        string, which is added both with only hyphens and only underscores),
        as well as an optional `hash_name` and `hash_new` constructor for
        hashlib compatibility.  If the application-specific function is
        already registered, the related data is replaced.  Registering a
        function with a `code` not in the application-specific range
        (0x00-0xff) or with names already registered for a different function
        raises a `ValueError`.

        >>> import hashlib
        >>> FuncReg.register(0x05, 'md-5', 'md5', hashlib.md5)
        >>> FuncReg.get('md-5') == FuncReg.get('md_5') == 0x05
        True
        >>> hashobj = FuncReg.hash_from_func(0x05)
        >>> hashobj.name == 'md5'
        True
        >>> FuncReg.func_from_hash(hashobj) == 0x05
        True
        >>> FuncReg.reset()
        >>> 0x05 in FuncReg
        False
        """
        if not _is_app_specific_func(code):
            raise ValueError(
                "only application-specific functions can be registered")
        # Check already registered name in different mappings.
        name_mapping_data = [  # (mapping, name in mapping, error if existing)
            (cls._func_from_name, name,
             "function name is already registered for a different function"),
            (cls._func_from_hash, hash_name,
             "hashlib name is already registered for a different function")]
        for (mapping, nameinmap, errmsg) in name_mapping_data:
            existing_func = mapping.get(nameinmap, code)
            if existing_func != code:
                raise ValueError(errmsg, existing_func)
        # Unregister if existing to ensure no orphan entries.
        if code in cls._func_hash:
            cls.unregister(code)
        # Proceed to registration.
        cls._do_register(code, name, hash_name, hash_new)

    @classmethod
    def unregister(cls, code):
        """Remove an application-specific function from the registry.

        Unregisters the function with the given `code` (an integer).  If the
        function is not registered, a `KeyError` is raised.  Unregistering a
        function with a `code` not in the application-specific range
        (0x00-0xff) raises a `ValueError`.

        >>> import hashlib
        >>> FuncReg.register(0x05, 'md-5', 'md5', hashlib.md5)
        >>> FuncReg.get('md-5')
        5
        >>> FuncReg.unregister(0x05)
        >>> FuncReg.get('md-5')
        Traceback (most recent call last):
            ...
        KeyError: ('unknown hash function', 'md-5')
        """
        if code in Func:
            raise ValueError(
                "only application-specific functions can be unregistered")
        # Remove mapping to function by name.
        func_names = {n for (n, f) in cls._func_from_name.items() if f == code}
        for func_name in func_names:
            del cls._func_from_name[func_name]
        # Remove hashlib data and mapping to hash.
        hash = cls._func_hash.pop(code)
        if hash.name:
            del cls._func_from_hash[hash.name]

    @classmethod
    def func_from_hash(cls, hash):
        """Return the multihash `Func` for the hashlib-compatible `hash` object.

        If no `Func` is registered for the given hash, a `KeyError` is raised.

        >>> import hashlib
        >>> h = hashlib.sha256()
        >>> f = FuncReg.func_from_hash(h)
        >>> f is Func.sha2_256
        True
        """
        return cls._func_from_hash[hash.name]

    @classmethod
    def hash_from_func(cls, func):
        """Return a hashlib-compatible object for the multihash `func`.

        If the `func` is registered but no hashlib-compatible constructor is
        available for it, `None` is returned.  If the `func` is not
        registered, a `KeyError` is raised.

        >>> h = FuncReg.hash_from_func(Func.sha2_256)
        >>> h.name
        'sha256'
        """
        new = cls._func_hash[func].new
        return new() if new else None

# Initialize the function hash registry.
FuncReg.reset()


def _do_digest(data, func):
    """Return the binary digest of `data` with the given `func`."""
    func = FuncReg.get(func)
    hash = FuncReg.hash_from_func(func)
    if not hash:
        raise ValueError("no available hash function for hash", func)
    hash.update(data)
    return bytes(hash.digest())


class _CodecRegMeta(type):
    def __contains__(self, encoding):
        """Return whether `encoding` is a registered codec.

        >>> CodecReg.reset()
        >>> 'base64' in CodecReg
        True
        """
        return encoding in self._codecs

    def __iter__(self):
        """Iterate over registered codec names.

        >>> CodecReg.reset()
        >>> {'hex', 'base32', 'base64'}.issubset(CodecReg)
        True
        """
        return iter(self._codecs)


class CodecReg(metaclass=_CodecRegMeta):
    """Registry of supported codecs."""

    # Common codec data.
    _common_codec_data = [  # (name, encode, decode)
        ('hex', binascii.b2a_hex, binascii.a2b_hex),
        ('base32', base64.b32encode, base64.b32decode),
        ('base64', base64.b64encode, base64.b64decode)]
    if base58:
        _common_codec_data.append(
            ('base58', lambda s: bytes(base58.b58encode(s)), base58.b58decode))

    # Codec data: encoding and decoding functions (both from bytes to bytes).
    _codec = namedtuple('codec', 'encode decode')

    @classmethod
    def reset(cls):
        """Reset the registry to the standard codecs."""
        cls._codecs = {}
        c = cls._codec
        for (name, encode, decode) in cls._common_codec_data:
            cls._codecs[name] = c(encode, decode)

    @classmethod
    def register(cls, name, encode, decode):
        """Add a codec to the registry.

        Registers a codec with the given `name` (a string) to be used with the
        given `encode` and `decode` functions, which take a `bytes` object and
        return another one.  An existing codec is replaced.

        >>> import binascii
        >>> CodecReg.register('uu', binascii.b2a_uu, binascii.a2b_uu)
        >>> CodecReg.get_decoder('uu') is binascii.a2b_uu
        True
        >>> CodecReg.reset()
        >>> 'uu' in CodecReg
        False
        """
        cls._codecs[name] = cls._codec(encode, decode)

    @classmethod
    def unregister(cls, name):
        """Remove a codec from the registry.

        Unregisters the codec with the given `name` (a string).  If the codec
        is not registered, a `KeyError` is raised.

        >>> import binascii
        >>> CodecReg.register('uu', binascii.b2a_uu, binascii.a2b_uu)
        >>> 'uu' in CodecReg
        True
        >>> CodecReg.unregister('uu')
        >>> 'uu' in CodecReg
        False
        """
        del cls._codecs[name]

    @classmethod
    def get_encoder(cls, encoding):
        r"""Return an encoder for the given `encoding`.

        The encoder gets a `bytes` object as argument and returns another
        encoded `bytes` object.  If the `encoding` is not registered, a
        `KeyError` is raised.

        >>> encode = CodecReg.get_encoder('hex')
        >>> encode(b'FOO\x00')
        b'464f4f00'
        """
        return cls._codecs[encoding].encode

    @classmethod
    def get_decoder(cls, encoding):
        r"""Return a decoder for the given `encoding`.

        The decoder gets a `bytes` object as argument and returns another
        decoded `bytes` object.  If the `encoding` is not registered, a
        `KeyError` is raised.

        >>> decode = CodecReg.get_decoder('hex')
        >>> decode(b'464f4f00')
        b'FOO\x00'
        """
        return cls._codecs[encoding].decode

# Initialize the codec registry.
CodecReg.reset()


class Multihash(namedtuple('Multihash', 'func digest')):
    """A named tuple representing a multihash function and digest.

    The hash function is usually a `Func` member.

    >>> mh = Multihash(Func.sha1, b'BINARY_DIGEST')
    >>> mh == (Func.sha1, b'BINARY_DIGEST')
    True
    >>> mh == (mh.func, mh.digest)
    True

    However it can also be its integer value (the function code) or its string
    name (the function name, with either underscore or hyphen).

    >>> mhfc = Multihash(Func.sha1.value, mh.digest)
    >>> mhfc == mh
    True
    >>> mhfn = Multihash('sha2-256', b'...')
    >>> mhfn.func is Func.sha2_256
    True

    Application-specific codes (0x00-0x0f) are also accepted.  Other codes
    raise a `KeyError`.

    >>> mhfc = Multihash(0x01, b'...')
    >>> mhfc.func
    1
    >>> mhfc = Multihash(1234, b'...')
    Traceback (most recent call last):
        ...
    KeyError: ('unknown hash function', 1234)
    """
    __slots__ = ()

    def __new__(cls, func, digest):
        try:
            func = FuncReg.get(func)
        except KeyError:
            if _is_app_specific_func(func):
                # Application-specific function codes
                # are allowed even if not registered.
                func = int(func)
            else:
                raise
        digest = bytes(digest)
        return super(cls, Multihash).__new__(cls, func, digest)

    @classmethod
    def from_hash(self, hash):
        """Create a `Multihash` from a hashlib-compatible `hash` object.

        >>> import hashlib
        >>> data = b'foo'
        >>> hash = hashlib.sha1(data)
        >>> digest = hash.digest()
        >>> mh = Multihash.from_hash(hash)
        >>> mh == (Func.sha1, digest)
        True

        Application-specific hash functions are also supported (see
        `FuncReg`).

        If there is no matching multihash hash function for the given `hash`,
        a `ValueError` is raised.
        """
        try:
            func = FuncReg.func_from_hash(hash)
        except KeyError as ke:
            raise ValueError(
                "no matching multihash function", hash.name) from ke
        digest = hash.digest()
        return Multihash(func, digest)

    def __str__(self):
        """Return a compact string representation of the multihash.

        The representation includes the name of the standard multihash
        function or the hexadecimal code of the application-specific one, and
        a Base64-encoded version of the raw digest.  This is *not* the
        complete multihash-encoded digest that can be obtained with
        `Multihash.encode()`.

        >>> mh = Multihash(Func.sha1, b'TEST')
        >>> print(mh)
        Multihash(sha1, b64:VEVTVA==)
        >>> mh = Multihash(0x01, b'TEST')
        >>> print(mh)
        Multihash(0x1, b64:VEVTVA==)
        """
        return 'Multihash({func}, b64:{digest})'.format(
            func=self.func.name if self.func in Func else hex(self.func),
            digest=base64.b64encode(self.digest).decode()
        )

    def encode(self, encoding=None):
        r"""Encode into a multihash-encoded digest.

        If `encoding` is `None`, a binary digest is produced:

        >>> mh = Multihash(0x01, b'TEST')
        >>> mh.encode()
        b'\x01\x04TEST'

        If the name of an `encoding` is specified, it is used to encode the
        binary digest before returning it (see `CodecReg` for supported
        codecs).

        >>> mh.encode('base64')
        b'AQRURVNU'

        If the `encoding` is not available, a `KeyError` is raised.
        """
        try:
            fc = self.func.value
        except AttributeError:  # application-specific function code
            fc = self.func
        mhash = bytes([fc, len(self.digest)]) + self.digest
        if encoding:
            mhash = CodecReg.get_encoder(encoding)(mhash)
        return mhash

    def verify(self, data):
        r"""Does the given `data` hash to the digest in this `Multihash`?

        >>> import hashlib
        >>> data = b'foo'
        >>> hash = hashlib.sha1(data)
        >>> mh = Multihash.from_hash(hash)
        >>> mh.verify(data)
        True
        >>> mh.verify(b'foobar')
        False

        Application-specific hash functions are also supported (see
        `FuncReg`).
        """
        digest = _do_digest(data, self.func)
        return digest[:len(self.digest)] == self.digest

    def truncate(self, length):
        """Return a new `Multihash` with a shorter digest `length`.

        If the given `length` is greater than the original, a `ValueError`
        is raised.

        >>> mh1 = Multihash(0x01, b'FOOBAR')
        >>> mh2 = mh1.truncate(3)
        >>> mh2 == (0x01, b'FOO')
        True
        >>> mh3 = mh1.truncate(10)
        Traceback (most recent call last):
            ...
        ValueError: cannot enlarge the original digest by 4 bytes
        """
        if length > len(self.digest):
            raise ValueError("cannot enlarge the original digest by %d bytes"
                             % (length - len(self.digest)))
        return self.__class__(self.func, self.digest[:length])


def digest(data, func):
    """Hash the given `data` into a new `Multihash`.

    The given hash function `func` is used to perform the hashing.  It must be
    a registered hash function (see `FuncReg`).

    >>> data = b'foo'
    >>> mh = digest(data, Func.sha1)
    >>> mh.encode('base64')
    b'ERQL7se16j8P28ldDdR/PFvCddqKMw=='
    """
    digest = _do_digest(data, func)
    return Multihash(func, digest)


def decode(mhash, encoding=None):
    r"""Decode a multihash-encoded digest into a `Multihash`.

    If `encoding` is `None`, a binary digest is assumed.

    >>> mhash = b'\x11\x0a\x0b\xee\xc7\xb5\xea?\x0f\xdb\xc9]'
    >>> mh = decode(mhash)
    >>> mh == (Func.sha1, mhash[2:])
    True

    If the name of an `encoding` is specified, it is used to decode the digest
    before parsing it (see `CodecReg` for supported codecs).

    >>> import base64
    >>> emhash = base64.b64encode(mhash)
    >>> emh = decode(emhash, 'base64')
    >>> emh == mh
    True

    If the `encoding` is not available, a `KeyError` is raised.  If the digest
    has an invalid format or contains invalid data, a `ValueError` is raised.
    """
    mhash = bytes(mhash)
    if encoding:
        mhash = CodecReg.get_decoder(encoding)(mhash)
    try:
        func = mhash[0]
        length = mhash[1]
        digest = mhash[2:]
    except IndexError as ie:
        raise ValueError("multihash is too short") from ie
    if length != len(digest):
        raise ValueError(
            "multihash length field does not match digest field length")
    return Multihash(func, digest)
