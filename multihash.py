# pymultihash: Python implementation of the multihash specification
#
# Initial author: Ivan Vilata-i-Balaguer
# License: MIT

from collections import namedtuple
from enum import Enum


class Func(Enum):
    """An enumeration of hash functions supported by multihash.

    The value of each member corresponds to its integer code.

    >>> Func.sha1.value == 0x11
    True
    """
    sha1 = 0x11
    sha2_256 = 0x12
    sha2_512 = 0x13
    sha3 = 0x14
    blake2b = 0x40
    blake2s = 0x41


class Multihash(namedtuple('Multihash', 'func length digest')):
    """A named tuple representing multihash function, length and digest.

    The function may be a `Func` member or its integer value (the function
    code).

    >>> mh = Multihash(Func.sha1, 20, b'BINARY_DIGEST')
    >>> mh == (Func.sha1, 20, b'BINARY_DIGEST')
    True
    >>> mh == (mh.func, mh.length, mh.digest)
    True

    >>> mhfc = Multihash(Func.sha1.value, mh.length, mh.digest)
    >>> mhfc == mh
    True
    """
    __slots__ = ()

    def __new__(cls, func, length, digest):
        try:
            f = Func(func)
        except ValueError as ve:
            raise ValueError("invalid hash function code", f)
        return super(cls, Multihash).__new__(cls, f, length, digest)


def _test():
    import doctest
    doctest.testmod()

if __name__ == '__main__':
    _test()
