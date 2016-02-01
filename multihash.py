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
the specification.  The `decode()` function can be used for the inverse
operation, i.e. converting a byte string into a `Multihash` object.

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

Please note that we needed to specify that the multihash is Base64-encoded,
otherwise binary encoding is assumed.  The verification internally uses a
hashlib-compatible implementation of the function indicated by the encoded
multihash to check the data.  Read about codecs and hash functions
further below.

The function in a `Multihash` object is stored as a member of the `Func`
enumeration, which contains one member per function listed in the `multihash`_
specification.  The name of a `Func` member is the name of that function in
the specification (with hyphens replaced by underscores), and its value is the
function code.  The `Multihash` object also contains the binary string with
the raw hash digest.

>>> mh  # doctest: +ELLIPSIS
Multihash(func=<Func.sha2_256: 18>, digest=b'...')
>>> hex(mh.func.value)
'0x12'
>>> len(mh.digest)
32

The short representation of a `Multihash` object only shows the function name
(or its code), and the Base64-encoded version of the raw hash digest:

>>> print(mh)
Multihash(sha2_256, b64:LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=)

Encoding
--------

Now imagine that you have some data and you want to create a multihash out of
it.  First you must create a `Multihash` instance with the desired function
and the computed binary digest.  If you already know them, you may create the
`Multihash` instance directly:

>>> mh = multihash.Multihash(multihash.Func.sha2_512, b'...')
>>> print(mh)  # doctest: +ELLIPSIS
Multihash(sha2_512, b64:...)

Instead of the `Func` member, you may use the function name (``'sha2-512'`` or
``'sha2_512'``) or its code (``19`` or ``0x13``).  You may also create
`Multihash` instances from hashlib-compatible objects:

>>> import hashlib
>>> hash = hashlib.sha1(data)
>>> mh = Multihash.from_hash(hash)
>>> print(mh)  # doctest: +ELLIPSIS
Multihash(sha1, b64:...)

Or you may get a `Multihash` instance with the `digest()` function, which
internally uses a hashlib-compatible implementation of the indicated function
to do the job for you:

>>> mh = multihash.digest(data, multihash.Func.sha1)
>>> print(mh)  # doctest: +ELLIPSIS
Multihash(sha1, b64:...)

In any case, getting the multihash-encoded digest is very simple:

>>> mh.encode('base64')
b'ERQL7se16j8P28ldDdR/PFvCddqKMw=='

As before, an encoding (Base64) was specified to avoid getting the binary
version of the multihash.

.. functions

.. codecs

"""

from base64 import b64encode
from collections import namedtuple
from enum import Enum
from numbers import Integral


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


class FuncReg:
    """Registry of hash supported functions."""

    # Hashlib compatibility data for a hash: hash name (e.g. ``sha256`` for
    # SHA-256, ``sha2-256`` in multihash), and the corresponding constructor.
    _hash = namedtuple('hash', 'name new')

    @classmethod
    def reset(cls):
        """Reset the registry to the standard multihash functions."""
        # Try to import known hashlib-compatible modules.
        import hashlib as hl
        try:
            import sha3 as s3
        except ImportError:
            s3 = None
        try:
            import pyblake2 as b2
        except ImportError:
            b2 = None

        h = cls._hash
        cls._func_hash = {
            Func.sha1: h('sha1', hl.sha1),
            Func.sha2_256: h('sha256', hl.sha256),
            Func.sha2_512: h('sha512', hl.sha512),
            Func.sha3_512: h('sha3_512', s3.sha3_512 if s3 else None),
            Func.sha3_384: h('sha3_384', s3.sha3_384 if s3 else None),
            Func.sha3_256: h('sha3_256', s3.sha3_256 if s3 else None),
            Func.sha3_224: h('sha3_224', s3.sha3_224 if s3 else None),
            Func.shake_128: h('shake_128', None),
            Func.shake_256: h('shake_256', None),
            Func.blake2b: h('blake2b', b2.blake2b if b2 else None),
            Func.blake2s: h('blake2s', b2.blake2s if b2 else None),
        }
        assert set(cls._func_hash) == set(Func)

        # Allows lookup by `Func` member name or CSV table name.
        cls._func_from_name = dict(Func.__members__)
        cls._func_from_name.update({f.name.replace('_', '-'): f for f in Func})

        # Maps hashlib names to multihash-supported functions.
        cls._func_from_hash = {h.name: f for (f, h) in cls._func_hash.items()}

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
    def get_funcs(cls):
        """Return a set of registered functions.

        Standard multihash functions are represented as members of `Func`,
        while application-specific functions are integers.

        >>> FuncReg.reset()
        >>> FuncReg.get_funcs() == set(Func)
        True
        """
        return {func for func in cls._func_hash}

    @classmethod
    def register(cls, code, name, hash_name, hash_new):
        """Add an application-specific function to the registry.

        Registers a function with the given `code` (an integer) and `name` (a
        string), as well as a `hash_name` and `hash_new` constructor for
        hashlib compatibility.  If the application-specific function is
        already registered, the related data is replaced.  Registering a
        function with a `code` not in the application-specific range
        (0x00-0xff) or with names already registered for a different function
        raises a `ValueError`.

        >>> import hashlib
        >>> FuncReg.register(0x03, 'md5', 'md5', hashlib.md5)
        >>> FuncReg.hash_from_func(0x03).name == 'md5'
        True
        >>> FuncReg.reset()
        >>> 0x03 in FuncReg.get_funcs()
        False
        """
        if not _is_app_specific_func(code):
            raise ValueError(
                "only application-specific functions can be registered")
        name_mapping_data = [  # (mapping, name in mapping, error if existing)
            (cls._func_from_name, name,
             "function name is already registered for a different function"),
            (cls._func_from_hash, hash_name,
             "hashlib name is already registered for a different function")]
        # Check already registered name in different mappings.
        for (mapping, nameinmap, errmsg) in name_mapping_data:
            existing_func = mapping.get(nameinmap, code)
            if existing_func != code:
                raise ValueError(errmsg, existing_func)
        # Unregister if existing to ensure no orphan entries.
        if code in cls._func_hash:
            cls.unregister(code)
        # Proceed to registration.
        cls._func_hash[code] = cls._hash(hash_name, hash_new)
        for (mapping, nameinmap, _) in name_mapping_data:
            mapping[nameinmap] = code
            mapping[nameinmap.replace('_', '-')] = code

    @classmethod
    def unregister(cls, code):
        """Remove an application-specific function from the registry.

        Unregisters the function with the given `code` (an integer).  If the
        function is not registered, a `KeyError` is raised.  Unregistering a
        function with a `code` not in the application-specific range
        (0x00-0xff) raises a `ValueError`.

        >>> import hashlib
        >>> FuncReg.register(0x03, 'md5', 'md5', hashlib.md5)
        >>> 0x03 in FuncReg.get_funcs()
        True
        >>> FuncReg.unregister(0x03)
        >>> 0x03 in FuncReg.get_funcs()
        False
        """
        if code in Func:
            raise ValueError(
                "only application-specific functions can be unregistered")
        hash = cls._func_hash.pop(code)
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


class CodecReg:
    """Registry of supported codecs."""

    # Codec data: encoding and decoding functions (both from bytes to bytes).
    _codec = namedtuple('codec', 'encode decode')

    @classmethod
    def reset(cls):
        """Reset the registry to the standard codecs."""
        # Try to import codecs mentioned in the hashlib spec.
        import binascii
        import base64

        c = cls._codec
        cls._codecs = {
            'hex': c(binascii.b2a_hex, binascii.a2b_hex),
            'base32': c(base64.b32encode, base64.b32decode),
            'base64': c(base64.b64encode, base64.b64decode)
        }

        # The spec doesn't have compulsory codes, though.
        try:
            import base58
            cls._codecs['base58'] = c(
                lambda s: bytes(base58.b58encode(s)), base58.b58decode)
        except ImportError:
            pass

    @classmethod
    def get_codecs(cls):
        """Return a set of registered codec names.

        >>> CodecReg.reset()
        >>> 'base64' in CodecReg.get_codecs()
        True
        """
        return {codec for codec in cls._codecs}

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
        >>> 'uu' in CodecReg.get_codecs()
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
        >>> 'uu' in CodecReg.get_codecs()
        True
        >>> CodecReg.unregister('uu')
        >>> 'uu' in CodecReg.get_codecs()
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
            digest=b64encode(self.digest).decode()
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


def _test():
    import doctest
    doctest.testmod()

if __name__ == '__main__':
    _test()
