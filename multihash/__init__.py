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
the specification (possibly ASCII-encoded).  The `decode()` function can be
used for the inverse operation, i.e. converting a (possibly ASCII-encoded)
byte string into a `Multihash` object.

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

Please note that you needed to specify that the multihash is Base64-encoded,
otherwise binary encoding is assumed (and the decoding will probably fail).
The verification internally uses a hashlib-compatible implementation of the
function indicated by the encoded multihash to check the data.  Read more
about codecs and hash functions further below.

The function in a `Multihash` object is stored as a member of the `Func`
enumeration, which contains one member per function listed in the `multihash`_
specification.  The name of a `Func` member is the name of that function in
the specification (with hyphens replaced by underscores), and its value is the
function code.  The `Multihash` object also contains the binary string with
the raw hash digest.  Application-specific hash functions are also supported,
but their numeric code is used instead of a `Func` member.

>>> mh  # doctest: +ELLIPSIS
Multihash(func=<Func.sha2_256: 18>, digest=b'...')
>>> hex(mh.func.value)
'0x12'
>>> len(mh.digest)
32

The short representation of a `Multihash` object only shows the function name
(or its code if application-specific), and the Base64-encoded version of the
raw hash digest:

>>> print(mh)
Multihash(sha2_256, b64:LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=)

If you need a shorter multihash, you may truncate it while keeping the initial
bytes of the raw hash digest.  A byte string validates against a truncated
multihash if its digest bytes match the initial bytes of the string's hash:

>>> mh_trunc = mh.truncate(16)
>>> print(mh_trunc)
Multihash(sha2_256, b64:LCa0a2j/xo/5m0U8HTBBNA==)
>>> mh_trunc.verify(data)
True

Encoding
--------

Now imagine that you have some data and you want to create a multihash out of
it.  First you must create a `Multihash` instance with the desired function
and the computed binary digest.  If you already know them, you may create the
`Multihash` instance directly:

>>> mh = multihash.Multihash(multihash.Func.sha2_512, b'...')
>>> print(mh)  # doctest: +ELLIPSIS
Multihash(sha2_512, b64:...)

Instead of the `Func` member, you may find more comfortable to use the
function name (e.g. ``'sha2-512'`` or ``'sha2_512'``) or its code (e.g. ``19``
or ``0x13``).  Or you may create `Multihash` instances straight from
hashlib-compatible objects:

>>> import hashlib
>>> hash = hashlib.sha1(data)
>>> mh = Multihash.from_hash(hash)
>>> print(mh)
Multihash(sha1, b64:C+7Hteo/D9vJXQ3UfzxbwnXaijM=)

However the easiest way to get a `Multihash` instance is with the `digest()`
function, which internally uses a hashlib-compatible implementation of the
indicated function to do the job for you:

>>> mh = multihash.digest(data, 'sha1')
>>> print(mh)
Multihash(sha1, b64:C+7Hteo/D9vJXQ3UfzxbwnXaijM=)

In any case, getting the multihash-encoded digest is very simple:

>>> mh.encode('base64')
b'ERQL7se16j8P28ldDdR/PFvCddqKMw=='

As before, an encoding (Base64) was specified to avoid getting the binary
version of the multihash.

The hash function registry
==========================

As the multihash specification indicates, you may use hash function codes in
the range 0x00-0x0f to specify application-specific hash functions.
The `decode()` function allows such multihashes, and the `Multihash`
constructor allows specifying such hash functions by their integer code:

>>> import multihash
>>> import hashlib
>>> data = b'foo'
>>> mh = multihash.Multihash(0x05, hashlib.md5(data).digest())
>>> print(mh)  # doctest: +ELLIPSIS
Multihash(0x5, b64:rL0Y20zC+Fzt72VPzMSk2A==)

However this does not allow using more intuitive strings instead of numbers
for application-specific functions, and digesting or verifying with such a
function is not possible:

>>> multihash.digest(data, 'md5')
Traceback (most recent call last):
    ...
KeyError: ('unknown hash function', 'md5')
>>> mh.verify(data)
Traceback (most recent call last):
    ...
KeyError: ('unknown hash function', 5)

The `FuncReg` class helps work around these problems by providing a registry
of hash functions.  You may add your application-specific hash functions there
with a code, a name, and optionally a name and a callable object for
hashlib-compatible operations:

>>> multihash.FuncReg.register(0x05, 'md-5', 'md5', hashlib.md5)
>>> multihash.digest(data, 'md-5')  # doctest: +ELLIPSIS
Multihash(func=5, digest=b'...')
>>> mh.verify(data)
True

You may remove your application-specific functions from the registry as well:

>>> multihash.FuncReg.unregister(0x05)

`FuncReg` also allows you to iterate over registered functions (as `Func`
members or function codes), and check if it contains a given function
(i.e. whether the `Func` or code is registered or not).

>>> [f.name for f in multihash.FuncReg if f == multihash.Func.sha3]
['sha3_512']
>>> 0x05 in multihash.FuncReg
False

The codec registry
==================

Although a multihash is properly a binary packing format for a hash digest, it
is not normally exchanged in binary form, but in some ASCII-encoded
representation of it.  As seen above, multihash decoding and encoding calls
support an ``encoding`` argument to allow ASCII decoding or encoding for
your convenience.

The encodings mentioned in the multihash standard are already enabled and
available by using their name (a string) as the ``encoding`` argument.
The ``base58`` encoding needs that the ``base58`` package is
installed, though.

The ``CodecReg`` class allows you to access the available codecs and register
your own ones (or replace existing ones) with a name and encoding and decoding
callables that get and return byte strings.  For instance, to add the uuencode
codec:

>>> import multihash
>>> import binascii
>>> multihash.CodecReg.register('uu', binascii.b2a_uu, binascii.a2b_uu)

To use it:

>>> mhash = b'6$10+[L>UZC\\\\/V\\\\E=#=1_/%O"==J*,P  \\n'
>>> mh = multihash.decode(mhash, 'uu')
>>> print(mh)
Multihash(sha1, b64:C+7Hteo/D9vJXQ3UfzxbwnXaijM=)
>>> mh.encode('uu') == mhash
True

You may remove any codec from the registry as well:

>>> multihash.CodecReg.unregister('uu')

`CodecReg` also allows you to iterate over registered codec names, and check
if it contains a given codec (i.e. whether it is registered or not).

>>> {'hex', 'base64'}.issubset(multihash.CodecReg)
True
>>> 'base32' in multihash.CodecReg
True
"""

from multihash.version import __version__  # noqa
from multihash.funcs import Func, FuncReg  # noqa
from multihash.codecs import CodecReg  # noqa
from multihash.multihash import Multihash, digest, decode  # noqa

__all__ = [
    '__version__',
    'Func', 'FuncReg',
    'CodecReg',
    'Multihash', 'digest', 'decode',
]
