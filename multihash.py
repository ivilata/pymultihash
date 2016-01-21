# pymultihash: Python implementation of the multihash specification
#
# Initial author: Ivan Vilata-i-Balaguer
# License: MIT

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
    sha3_384 = 0x15
    sha3_256 = 0x16
    sha3_224 = 0x17
    shake_128 = 0x18
    shake_256 = 0x19
    blake2b = 0x40
    blake2s = 0x41

# Allows lookup by `Func` member name or CSV table name.
_func_from_name = dict(Func.__members__)
_func_from_name.update({f.name.replace('_', '-'): f for f in Func})


class FuncHash:
    """Registry of supported hashlib-compatible hashes."""
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

        # Maps hashlib names to multihash-supported functions.
        cls._func_from_hash = {h.name: f for (f, h) in cls._func_hash.items()}

    @classmethod
    def get_funcs(cls):
        """Return a set of registered functions.

        Standard multihash functions are represented as members of `Func`,
        while application-specific functions are integers.

        >>> FuncHash.reset()
        >>> FuncHash.get_funcs() == set(Func)
        True
        """
        return {func for func in cls._func_hash}

    @classmethod
    def register(cls, code, name, new):
        """Add an application-specific function to the registry.

        Registers a function with the given `code` (an integer) and `name` (a
        string) to be used with the given hashlib-compatible `new`
        constructor.  Existing functions are replaced.  Registering a function
        with a `code` not in the application-specific range (0x00-0xff) raises
        a `ValueError`.

        >>> import hashlib
        >>> FuncHash.register(0x03, 'md5', hashlib.md5)
        >>> FuncHash.hash_from_func(0x03).name == 'md5'
        True
        >>> FuncHash.reset()
        >>> 0x03 in FuncHash.get_funcs()
        False
        """
        if not _is_app_specific_func(code):
            raise ValueError(
                "only application-specific functions can be registered")
        cls._func_hash[code] = cls._hash(name, new)
        cls._func_from_hash[name] = code

    @classmethod
    def unregister(cls, code):
        """Remove an application-specific function from the registry.

        Unregisters the function with the given `code` (an integer).  If the
        function is not registered, a `KeyError` is raised.  Unregistering a
        function with a `code` not in the application-specific range
        (0x00-0xff) raises a `ValueError`.

        >>> import hashlib
        >>> FuncHash.register(0x03, 'md5', hashlib.md5)
        >>> 0x03 in FuncHash.get_funcs()
        True
        >>> FuncHash.unregister(0x03)
        >>> 0x03 in FuncHash.get_funcs()
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
        >>> f = FuncHash.func_from_hash(h)
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

        >>> h = FuncHash.hash_from_func(Func.sha2_256)
        >>> h.name
        'sha256'
        """
        new = cls._func_hash[func].new
        return new() if new else None

# Initialize the function hash registry.
FuncHash.reset()


class Codecs:
    """Registry of supported codecs."""
    _codec = namedtuple('codec', 'encode decode')

    @classmethod
    def reset(cls):
        """Reset the registry to the standard codecs."""
        # Try to import codecs mentioned in the hashlib spec.
        import binascii as ba
        import base64 as b64
        try:
            import base58 as b58
        except ImportError:
            b58 = None

        c = cls._codec
        cls._codecs = {
            'hex': c(ba.b2a_hex, ba.a2b_hex),
            'base32': c(b64.b32encode, b64.b32decode),
            'base64': c(b64.b64encode, b64.b64decode)
        }
        if b58:
            cls._codecs['base58'] = c(
                lambda s: bytes(b58.b58encode(s)), b58.b58decode)

    @classmethod
    def get_encoder(cls, encoding):
        r"""Return an encoder for the given `encoding`.

        The encoder gets a `bytes` object as argument and returns another
        encoded `bytes` object.  If the `encoding` is not registered, a
        `KeyError` is raised.

        >>> encode = Codecs.get_encoder('hex')
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

        >>> decode = Codecs.get_decoder('hex')
        >>> decode(b'464f4f00')
        b'FOO\x00'
        """
        return cls._codecs[encoding].decode

# Initialize the codec registry.
Codecs.reset()


class Multihash(namedtuple('Multihash', 'func digest')):
    """A named tuple representing a multihash function and digest.

    The hash function is a `Func` member:

    >>> mh = Multihash(Func.sha1, b'BINARY_DIGEST')
    >>> mh == (Func.sha1, b'BINARY_DIGEST')
    True
    >>> mh == (mh.func, mh.digest)
    True

    Although it can also be its integer value (the function code) or its
    string name (the function name, with either underscore or hyphen):

    >>> mhfc = Multihash(Func.sha1.value, mh.digest)
    >>> mhfc == mh
    True
    >>> mhfn = Multihash('sha2-256', b'...')
    >>> mhfn.func is Func.sha2_256
    True

    Application-specific codes (0x00-0x0f) are also accepted.  Other codes
    raise a `ValueError`:

    >>> mhfc = Multihash(0x01, b'...')
    >>> mhfc.func
    1
    >>> mhfc = Multihash(1234, b'...')
    Traceback (most recent call last):
        ...
    ValueError: ('invalid hash function code', 1234)
    """
    __slots__ = ()

    def __new__(cls, func, digest):
        try:
            f = Func(func)  # function or function code
        except ValueError as ve:
            if _is_app_specific_func(func):
                f = int(func)  # application-specific function code
            elif func in _func_from_name:
                f = _func_from_name[func]  # function name
            else:
                raise ValueError("invalid hash function code", func) from ve
        return super(cls, Multihash).__new__(cls, f, bytes(digest))

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
        `FuncHash`).

        If there is no matching multihash hash function for the given `hash`,
        a `ValueError` is raised.
        """
        try:
            func = FuncHash.func_from_hash(hash)
        except KeyError as ke:
            raise ValueError(
                "no matching multihash function", hash.name) from ke
        digest = hash.digest()
        return Multihash(func, digest)

    def encode(self, encoding=None):
        r"""Encode into a multihash-encoded digest.

        If `encoding` is `None`, a binary digest is produced:

        >>> mh = Multihash(0x01, b'TEST')
        >>> mh.encode()
        b'\x01\x04TEST'

        If the name of an `encoding` is specified, it is used to encode the
        binary digest before returning it (see `Codecs` for supported codecs):

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
            mhash = Codecs.get_encoder(encoding)(mhash)
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
        `FuncHash`).
        """
        hash = FuncHash.hash_from_func(self.func)
        if not hash:
            raise ValueError("no available hash function for hash", self.func)
        hash.update(data)
        digest = bytes(hash.digest())
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


def decode(mhash, encoding=None):
    r"""Decode a multihash-encoded digest into a `Multihash`.

    If `encoding` is `None`, a binary digest is assumed:

    >>> mhash = b'\x11\x0a\x0b\xee\xc7\xb5\xea?\x0f\xdb\xc9]'
    >>> mh = decode(mhash)
    >>> mh == (Func.sha1, mhash[2:])
    True

    If the name of an `encoding` is specified, it is used to decode the digest
    before parsing it (see `Codecs` for supported codecs):

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
        mhash = Codecs.get_decoder(encoding)(mhash)
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
