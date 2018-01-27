# simple-bcrypt

simple-bcrypt package provides bcrypt hashing utilities for
`Flask/Sanic/Quart/Eve` application. Python 3.3+ is required to use this package.

Due to the recent increased prevelance of powerful hardware, such as modern
GPUs, hashes have become increasingly easy to crack. A proactive solution to
this is to use a hash that was designed to be "de-optimized". Bcrypt is such
a hashing facility; unlike hashing algorithms such as MD5 and SHA1, which are
optimized for speed, bcrypt is intentionally structured to be slow.

For sensitive data that must be protected, such as passwords, bcrypt is an
advisable choice.

## Installation

Install the extension with one of the following commands:
    
    $ pip install simple-bcrypt

## Usage

To use the package simply import the class wrapper and pass the app
object back to here. Do so like this:

### Flask
    
    from flask import Flask
    from simple_bcrypt import Bcrypt
    
    app = Flask(__name__)
    bcrypt = Bcrypt(app)


### Sanic

    from sanic import Sanic
    from simple_bcrypt import Bcrypt

    app = Sanic(__name__)
    bcrypt = Bcrypt(app)


### Quart

    from quart import Quart
    from simple_bcrypt import Bcrypt

    app = Quart(__name__)
    bcrypt = Bcrypt(app)


### Eve

    from eve import Eve
    from simple_bcrypt import Bcrypt

    app = Eve()
    bcrypt = Bcrypt(app)


Two primary hashing methods are now exposed by way of the bcrypt object.
You need to use decode('utf-8') on generate_password_hash(), like below:

    pw_hash = bcrypt.generate_password_hash('hunter2').decode('utf-8')
    bcrypt.check_password_hash(pw_hash, 'hunter2') # returns True

## Documentation

[simple-bcrypt docs](https://shopnilsazal.github.io/simple-bcrypt/)


## Credits

simple-bcrypt is ported from [Flask-Bcrypt](https://github.com/maxcountryman/flask-bcrypt)
