======================================================
 Python implementation of the multihash specification
======================================================

This is an implementation of the `multihash`_ specification in Python.
The main component in the module is the `Multihash` class, a named tuple that
represents a hash function and a digest created with it, with extended
abilities to work with hashlib-compatible hash functions, verify the integrity
of data, and encode itself to a byte string in the binary format described in
the specification.  The `decode()` function can be used for the inverse
operation, i.e. converting a byte string into a `Multihash` object.

.. _multihash: https://github.com/jbenet/multihash

Please see the docstring in the ``multihash`` module for more information.
