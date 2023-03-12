# pymultihash: Python implementation of the multihash specification
#
# Initial author: Ivan Vilata-i-Balaguer
# License: MIT

"""Codec registry"""

from collections import namedtuple

# Import codecs mentioned in the multihash spec.
import binascii
import base64

# Try to import external codecs mentioned in the multihash spec.
try:
    import base58
except ImportError:
    base58 = None


class _CodecRegMeta(type):
    def __contains__(self, encoding):
        """Return whether `encoding` is a registered codec.

        >>> CodecReg.reset()
        >>> 'base64' in CodecReg
        True
        """
        return encoding in self._codecs

    def __iter__(self):
        """Iterate over registered codec names.

        >>> CodecReg.reset()
        >>> {'hex', 'base32', 'base64'}.issubset(CodecReg)
        True
        """
        return iter(self._codecs)


class CodecReg(metaclass=_CodecRegMeta):
    """Registry of supported codecs."""

    # Common codec data.
    _common_codec_data = [  # (name, encode, decode)
        ('hex', binascii.b2a_hex, binascii.a2b_hex),
        ('base32', base64.b32encode, base64.b32decode),
        ('base64', base64.b64encode, base64.b64decode)]
    if base58:
        _common_codec_data.append(
            ('base58', base58.b58encode, base58.b58decode))

    # Codec data: encoding and decoding functions (both from bytes to bytes).
    _codec = namedtuple('codec', 'encode decode')

    @classmethod
    def reset(cls):
        """Reset the registry to the standard codecs."""
        cls._codecs = {}
        c = cls._codec
        for (name, encode, decode) in cls._common_codec_data:
            cls._codecs[name] = c(encode, decode)

    @classmethod
    def register(cls, name, encode, decode):
        """Add a codec to the registry.

        Registers a codec with the given `name` (a string) to be used with the
        given `encode` and `decode` functions, which take a `bytes` object and
        return another one.  An existing codec is replaced.

        >>> import binascii
        >>> CodecReg.register('uu', binascii.b2a_uu, binascii.a2b_uu)
        >>> CodecReg.get_decoder('uu') is binascii.a2b_uu
        True
        >>> CodecReg.reset()
        >>> 'uu' in CodecReg
        False
        """
        cls._codecs[name] = cls._codec(encode, decode)

    @classmethod
    def unregister(cls, name):
        """Remove a codec from the registry.

        Unregisters the codec with the given `name` (a string).  If the codec
        is not registered, a `KeyError` is raised.

        >>> import binascii
        >>> CodecReg.register('uu', binascii.b2a_uu, binascii.a2b_uu)
        >>> 'uu' in CodecReg
        True
        >>> CodecReg.unregister('uu')
        >>> 'uu' in CodecReg
        False
        """
        del cls._codecs[name]

    @classmethod
    def get_encoder(cls, encoding):
        r"""Return an encoder for the given `encoding`.

        The encoder gets a `bytes` object as argument and returns another
        encoded `bytes` object.  If the `encoding` is not registered, a
        `KeyError` is raised.

        >>> encode = CodecReg.get_encoder('hex')
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

        >>> decode = CodecReg.get_decoder('hex')
        >>> decode(b'464f4f00')
        b'FOO\x00'
        """
        return cls._codecs[encoding].decode


# Initialize the codec registry.
CodecReg.reset()
