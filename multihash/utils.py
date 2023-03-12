# pymultihash: Python implementation of the multihash specification
#
# Initial author: Ivan Vilata-i-Balaguer
# License: MIT

"""Assorted utilities"""

import codecs


class IdentityHash:
    """hashlib-compatible algorithm where the input is the digest.

    Please note that the digest size of an identity hash instance varies as
    the hash is updated with new data.

    >>> h = IdentityHash()
    >>> h.digest(), h.digest_size
    (b'', 0)
    >>> h.update(b'foo')
    >>> h.digest(), h.digest_size
    (b'foo', 3)
    >>> h.update(b'bar')
    >>> h.digest(), h.digest_size
    (b'foobar', 6)
    """

    @property
    def name(self):
        return 'identity'

    @property
    def digest_size(self):
        return len(self._data)

    @property
    def block_size(self):
        return 1  # hopefully irrelevant

    def __init__(self):
        self._data = b''

    def update(self, data):
        self._data += data

    def digest(self):
        return self._data

    def hexdigest(self):
        return codecs.encode(self._data, 'hex').decode('ascii')

    def copy(self):
        c = self.__class__()
        c._data = self._data
        return c
