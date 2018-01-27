simple-bcrypt
=============

.. module:: simple_bcrypt

simple-bcrypt package provides bcrypt hashing utilities for `Flask/Sanic/Quart/Eve` application.
Python 3.3+ is required to use this package.

Due to the recent increased prevelance of powerful hardware, such as modern
GPUs, hashes have become increasingly easy to crack. A proactive solution to
this is to use a hash that was designed to be "de-optimized". Bcrypt is such
a hashing facility; unlike hashing algorithms such as MD5 and SHA1, which are
optimized for speed, bcrypt is intentionally structured to be slow.

For sensitive data that must be protected, such as passwords, bcrypt is an
advisable choice.

Installation
------------

Install the extension with one of the following commands:

.. code-block:: bash

    $ pip install simple-bcrypt

.. note::
    You need Python Development Headers to install py-bcrypt package, needed
    as a dependency. If you are on Mac OS or Windows, you probably have it
    already installed. Otherwise look for python-dev package for Debian-based
    distributives and for python-devel package for RedHat-based.

Usage
-----

To use the extension simply import the class wrapper and pass the `Flask/Sanic/Quart/Eve` app
object back to here. Do so like this::

Flask:

.. code-block:: python

    from flask import Flask
    from simple_bcrypt import Bcrypt

    app = Flask(__name__)
    bcrypt = Bcrypt(app)


Sanic:

.. code-block:: python

    from sanic import Sanic
    from simple_bcrypt import Bcrypt

    app = Sanic(__name__)
    bcrypt = Bcrypt(app)


Quart:

.. code-block:: python

    from quart import Quart
    from simple_bcrypt import Bcrypt

    app = Quart(__name__)
    bcrypt = Bcrypt(app)


Eve:

.. code-block:: python

    from eve import Eve
    from simple_bcrypt import Bcrypt

    app = Eve()
    bcrypt = Bcrypt(app)


Available Config with default:

.. code-block:: python

    app.config['BCRYPT_LOG_ROUNDS'] = 6
    app.config['BCRYPT_HASH_IDENT'] = '2b'
    app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = False

Two primary hashing methods are now exposed by way of the bcrypt object. You need to use decode('utf-8') on generate_password_hash(), like below:

.. code-block:: python

    pw_hash = bcrypt.generate_password_hash('hunter2').decode('utf-8')
    bcrypt.check_password_hash(pw_hash, 'hunter2') # returns True

API
___
.. autoclass:: simple_bcrypt.Bcrypt
    :members:

.. autofunction:: simple_bcrypt.generate_password_hash

.. autofunction:: simple_bcrypt.check_password_hash

