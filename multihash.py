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

    The value of each member corresponds to its integer code.

    >>> Func.sha1.value == 0x11
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

# Maps hashlib names to multihash-supported functions.
_func_from_hash = {
    'sha1': Func.sha1,
    'sha256': Func.sha2_256,
    'sha512': Func.sha2_512,
    # See jbenet/multihash#11 for new SHA-3 function names and codes.
    'sha3_512': Func.sha3_512,  # as used by pysha3
    'sha3_384': Func.sha3_384,  # as used by pysha3
    'sha3_256': Func.sha3_256,  # as used by pysha3
    'sha3_224': Func.sha3_224,  # as used by pysha3
    'shake_128': Func.shake_128,  # as used by pysha3
    'shake_256': Func.shake_256,  # as used by pysha3
    'blake2b': Func.blake2b,  # as used by pyblake2
    'blake3s': Func.blake2s  # as used by pyblake2
}


class Multihash(namedtuple('Multihash', 'func length digest')):
    """A named tuple representing multihash function, length and digest.

    The hash function is a `Func` member:

    >>> mh = Multihash(Func.sha1, 20, b'BINARY_DIGEST')
    >>> mh == (Func.sha1, 20, b'BINARY_DIGEST')
    True
    >>> mh == (mh.func, mh.length, mh.digest)
    True

    Although it can also be its integer value (the function code) or its
    string name (the function name, with either underscore or hyphen):

    >>> mhfc = Multihash(Func.sha1.value, mh.length, mh.digest)
    >>> mhfc == mh
    True
    >>> mhfn = Multihash('sha2-256', 32, b'...')
    >>> mhfn.func is Func.sha2_256
    True

    Application-specific codes (0x00-0x0f) are also accepted.  Other codes
    raise `ValueError`:

    >>> mhfc = Multihash(0x01, 4, b'...')
    >>> mhfc.func
    1
    >>> mhfc = Multihash(1234, 4, b'...')
    Traceback (most recent call last):
        ...
    ValueError: ('invalid hash function code', 1234)
    """
    __slots__ = ()

    def __new__(cls, func, length, digest):
        try:
            f = Func(func)  # function or function code
        except ValueError as ve:
            if _is_app_specific_func(func):
                f = int(func)  # application-specific function code
            elif func in _func_from_name:
                f = _func_from_name[func]  # function name
            else:
                raise ValueError("invalid hash function code", func)
        return super(cls, Multihash).__new__(cls, f, length, digest)

    @classmethod
    def from_hash(self, hash):
        """Create a `Multihash` from a hashlib-compatible `hash` object.

        >>> import hashlib
        >>> hash = hashlib.sha1(b'foo')
        >>> digest = hash.digest()
        >>> mh = Multihash.from_hash(hash)
        >>> mh == (Func.sha1, len(digest), digest)
        True

        If there is no matching multihash hash function for the given `hash`,
        `KeyError` is raised.

        >>> hash = hashlib.sha224(b'foo')
        >>> mh = Multihash.from_hash(hash)
        Traceback (most recent call last):
            ...
        ValueError: ('no matching multihash function', 'sha224')
        """
        try:
            func = _func_from_hash[hash.name]
        except KeyError:
            raise ValueError("no matching multihash function", hash.name)
        digest = hash.digest()
        return Multihash(func, len(digest), digest)


def decode(digest):
    r"""Decode a multihash-encoded binary digest into a `Multihash`.

    >>> digest = b'\x11\x0a\x0b\xee\xc7\xb5\xea?\x0f\xdb\xc9]'
    >>> decode(digest) == (Func.sha1, 10, digest[2:])
    True
    """
    return Multihash(int(digest[0]), int(digest[1]), digest[2:])


def _test():
    import doctest
    doctest.testmod()

if __name__ == '__main__':
    _test()
