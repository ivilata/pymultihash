# SPDX-FileCopyrightText: 2016, 2023 Ivan Vilata-i-Balaguer <ivan@selidor.net>
#
# SPDX-License-Identifier: MIT

import doctest
import unittest

import multihash
import multihash.funcs
import multihash.codecs
import multihash.multihash
import multihash.utils


def suite():
    tests = unittest.TestSuite()
    for module in [
            multihash.funcs, multihash.codecs, multihash.multihash,
            multihash.utils,
            multihash]:
        tests.addTests(doctest.DocTestSuite(module))
    return tests

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
