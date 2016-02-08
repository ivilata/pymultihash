import doctest
import unittest

import multihash


def suite():
    return doctest.DocTestSuite(multihash)

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
