# Based on PyPA sample project's setup script.

"""Pymultihash installation script."""

import os.path
from setuptools import setup, find_packages

# Load readme file into long description.
thisdir = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(thisdir, 'README.rst')) as readme:
    long_description = readme.read()

setup(
    name='pymultihash',
    version='0.5.0a1',

    description="Python implementation of the multihash specification",
    long_description=long_description,

    url='https://github.com/ivilata/pymultihash',
    author="Ivan Vilata-i-Balaguer",
    author_email='ivan@selidor.net',

    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security :: Cryptography',
    ],
    keywords="multihash hash digest format ASCII encoding",

    packages=find_packages(),
    install_requires=[],
    extras_require={
        'sha3': ['pysha3'],
        'blake2': ['pyblake2'],
    },
)
