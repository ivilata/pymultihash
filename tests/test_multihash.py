import doctest
import unittest

import multihash
import multihash.func


def suite():
    tests = unittest.TestSuite()
    for module in [multihash.func, multihash]:
        tests.addTests(doctest.DocTestSuite(module))
    return tests

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
