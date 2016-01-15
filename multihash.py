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

    >>> mh = Multihash(Func.sha1, 20, b'BINARY_DIGEST')
    >>> mh == (Func.sha1, 20, b'BINARY_DIGEST')
    True
    >>> mh == (mh.func, mh.length, mh.digest)
    True
    """
    __slots__ = ()


def _test():
    import doctest
    doctest.testmod()

if __name__ == '__main__':
    _test()
