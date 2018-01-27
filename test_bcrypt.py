# coding:utf-8
import unittest
from sanic import Sanic
from quart import Quart
from flask import Flask
from eve import Eve
from simple_bcrypt import Bcrypt, check_password_hash, generate_password_hash


class FlaskBasicTestCase(unittest.TestCase):

    def setUp(self):
        flask_app = Flask(__name__)
        flask_app.config['BCRYPT_LOG_ROUNDS'] = 6
        flask_app.config['BCRYPT_HASH_IDENT'] = '2b'
        flask_app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = False
        self.flask_bcrypt = Bcrypt(flask_app)

    def test_is_string(self):
        pw_hash = self.flask_bcrypt.generate_password_hash('secret')
        self.assertTrue(isinstance(pw_hash, bytes))

    def test_custom_rounds(self):
        password = 'secret'
        pw_hash1 = self.flask_bcrypt.generate_password_hash(password, 5)
        self.assertNotEqual(password, pw_hash1)

    def test_check_hash(self):
        pw_hash = self.flask_bcrypt.generate_password_hash('secret')
        # check a correct password
        self.assertTrue(self.flask_bcrypt.check_password_hash(pw_hash, 'secret'))
        # check an incorrect password
        self.assertFalse(self.flask_bcrypt.check_password_hash(pw_hash, 'hunter2'))
        # check unicode
        pw_hash = self.flask_bcrypt.generate_password_hash('\u2603')
        self.assertTrue(self.flask_bcrypt.check_password_hash(pw_hash, '\u2603'))
        # check helpers
        pw_hash = generate_password_hash('hunter2')
        self.assertTrue(check_password_hash(pw_hash, 'hunter2'))

    def test_check_hash_unicode_is_utf8(self):
        password = '\u2603'
        pw_hash = self.flask_bcrypt.generate_password_hash(password)
        # check a correct password
        self.assertTrue(self.flask_bcrypt.check_password_hash(pw_hash, b'\xe2\x98\x83'))

    def test_rounds_set(self):
        self.assertEqual(self.flask_bcrypt._log_rounds, 6)

    def test_unicode_hash(self):
        password = '東京'
        h = generate_password_hash(password).decode('utf-8')
        self.assertTrue(check_password_hash(h, password))

    def test_long_password(self):
        """Test bcrypt maximum password length.

        The bcrypt algorithm has a maximum password length of 72 bytes, and
        ignores any bytes beyond that."""

        # Create a password with a 72 bytes length
        password = 'A' * 72
        pw_hash = self.flask_bcrypt.generate_password_hash(password)
        # Ensure that a longer password yields the same hash
        self.assertTrue(self.flask_bcrypt.check_password_hash(pw_hash, 'A' * 80))


class SanicBasicTestCase(unittest.TestCase):

    def setUp(self):
        sanic_app = Sanic(__name__)
        sanic_app.config['BCRYPT_LOG_ROUNDS'] = 6
        sanic_app.config['BCRYPT_HASH_IDENT'] = '2b'
        sanic_app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = False
        self.sanic_bcrypt = Bcrypt(sanic_app)

    def test_is_string(self):
        pw_hash = self.sanic_bcrypt.generate_password_hash('secret')
        self.assertTrue(isinstance(pw_hash, bytes))

    def test_custom_rounds(self):
        password = 'secret'
        pw_hash1 = self.sanic_bcrypt.generate_password_hash(password, 5)
        self.assertNotEqual(password, pw_hash1)

    def test_check_hash(self):
        pw_hash = self.sanic_bcrypt.generate_password_hash('secret')
        # check a correct password
        self.assertTrue(self.sanic_bcrypt.check_password_hash(pw_hash, 'secret'))
        # check an incorrect password
        self.assertFalse(self.sanic_bcrypt.check_password_hash(pw_hash, 'hunter2'))
        # check unicode
        pw_hash = self.sanic_bcrypt.generate_password_hash('\u2603')
        self.assertTrue(self.sanic_bcrypt.check_password_hash(pw_hash, '\u2603'))
        # check helpers
        pw_hash = generate_password_hash('hunter2')
        self.assertTrue(check_password_hash(pw_hash, 'hunter2'))

    def test_check_hash_unicode_is_utf8(self):
        password = '\u2603'
        pw_hash = self.sanic_bcrypt.generate_password_hash(password)
        # check a correct password
        self.assertTrue(self.sanic_bcrypt.check_password_hash(pw_hash, b'\xe2\x98\x83'))

    def test_rounds_set(self):
        self.assertEqual(self.sanic_bcrypt._log_rounds, 6)

    def test_unicode_hash(self):
        password = '東京'
        h = generate_password_hash(password).decode('utf-8')
        self.assertTrue(check_password_hash(h, password))

    def test_long_password(self):
        """Test bcrypt maximum password length.

        The bcrypt algorithm has a maximum password length of 72 bytes, and
        ignores any bytes beyond that."""

        # Create a password with a 72 bytes length
        password = 'A' * 72
        pw_hash = self.sanic_bcrypt.generate_password_hash(password)
        # Ensure that a longer password yields the same hash
        self.assertTrue(self.sanic_bcrypt.check_password_hash(pw_hash, 'A' * 80))


class QuartBasicTestCase(unittest.TestCase):

    def setUp(self):
        quart_app = Quart(__name__)
        quart_app.config['BCRYPT_LOG_ROUNDS'] = 6
        quart_app.config['BCRYPT_HASH_IDENT'] = '2b'
        quart_app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = False
        self.quart_bcrypt = Bcrypt(quart_app)

    def test_is_string(self):
        pw_hash = self.quart_bcrypt.generate_password_hash('secret')
        self.assertTrue(isinstance(pw_hash, bytes))

    def test_custom_rounds(self):
        password = 'secret'
        pw_hash1 = self.quart_bcrypt.generate_password_hash(password, 5)
        self.assertNotEqual(password, pw_hash1)

    def test_check_hash(self):
        pw_hash = self.quart_bcrypt.generate_password_hash('secret')
        # check a correct password
        self.assertTrue(self.quart_bcrypt.check_password_hash(pw_hash, 'secret'))
        # check an incorrect password
        self.assertFalse(self.quart_bcrypt.check_password_hash(pw_hash, 'hunter2'))
        # check unicode
        pw_hash = self.quart_bcrypt.generate_password_hash('\u2603')
        self.assertTrue(self.quart_bcrypt.check_password_hash(pw_hash, '\u2603'))
        # check helpers
        pw_hash = generate_password_hash('hunter2')
        self.assertTrue(check_password_hash(pw_hash, 'hunter2'))

    def test_check_hash_unicode_is_utf8(self):
        password = '\u2603'
        pw_hash = self.quart_bcrypt.generate_password_hash(password)
        # check a correct password
        self.assertTrue(self.quart_bcrypt.check_password_hash(pw_hash, b'\xe2\x98\x83'))

    def test_rounds_set(self):
        self.assertEqual(self.quart_bcrypt._log_rounds, 6)

    def test_unicode_hash(self):
        password = '東京'
        h = generate_password_hash(password).decode('utf-8')
        self.assertTrue(check_password_hash(h, password))

    def test_long_password(self):
        """Test bcrypt maximum password length.

        The bcrypt algorithm has a maximum password length of 72 bytes, and
        ignores any bytes beyond that."""

        # Create a password with a 72 bytes length
        password = 'A' * 72
        pw_hash = self.quart_bcrypt.generate_password_hash(password)
        # Ensure that a longer password yields the same hash
        self.assertTrue(self.quart_bcrypt.check_password_hash(pw_hash, 'A' * 80))


class EveBasicTestCase(unittest.TestCase):

    def setUp(self):
        eve_settings = {
            'BCRYPT_LOG_ROUNDS': 6,
            'BCRYPT_HASH_IDENT': '2b',
            'BCRYPT_HANDLE_LONG_PASSWORDS': False,
            'DOMAIN': {}
        }
        eve_app = Eve(settings=eve_settings)
        self.eve_bcrypt = Bcrypt(eve_app)

    def test_is_string(self):
        pw_hash = self.eve_bcrypt.generate_password_hash('secret')
        self.assertTrue(isinstance(pw_hash, bytes))

    def test_custom_rounds(self):
        password = 'secret'
        pw_hash1 = self.eve_bcrypt.generate_password_hash(password, 5)
        self.assertNotEqual(password, pw_hash1)

    def test_check_hash(self):
        pw_hash = self.eve_bcrypt.generate_password_hash('secret')
        # check a correct password
        self.assertTrue(self.eve_bcrypt.check_password_hash(pw_hash, 'secret'))
        # check an incorrect password
        self.assertFalse(self.eve_bcrypt.check_password_hash(pw_hash, 'hunter2'))
        # check unicode
        pw_hash = self.eve_bcrypt.generate_password_hash('\u2603')
        self.assertTrue(self.eve_bcrypt.check_password_hash(pw_hash, '\u2603'))
        # check helpers
        pw_hash = generate_password_hash('hunter2')
        self.assertTrue(check_password_hash(pw_hash, 'hunter2'))

    def test_check_hash_unicode_is_utf8(self):
        password = '\u2603'
        pw_hash = self.eve_bcrypt.generate_password_hash(password)
        # check a correct password
        self.assertTrue(self.eve_bcrypt.check_password_hash(pw_hash, b'\xe2\x98\x83'))

    def test_rounds_set(self):
        self.assertEqual(self.eve_bcrypt._log_rounds, 6)

    def test_unicode_hash(self):
        password = '東京'
        h = generate_password_hash(password).decode('utf-8')
        self.assertTrue(check_password_hash(h, password))

    def test_long_password(self):
        """Test bcrypt maximum password length.

        The bcrypt algorithm has a maximum password length of 72 bytes, and
        ignores any bytes beyond that."""

        # Create a password with a 72 bytes length
        password = 'A' * 72
        pw_hash = self.eve_bcrypt.generate_password_hash(password)
        # Ensure that a longer password yields the same hash
        self.assertTrue(self.eve_bcrypt.check_password_hash(pw_hash, 'A' * 80))


class FlaskLongPasswordsTestCase(FlaskBasicTestCase):

    def setUp(self):
        flask_app = Flask(__name__)
        flask_app.config['BCRYPT_LOG_ROUNDS'] = 6
        flask_app.config['BCRYPT_HASH_IDENT'] = '2b'
        flask_app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = True
        self.flask_bcrypt = Bcrypt(flask_app)

    def test_long_password(self):
        """Test the work around bcrypt maximum password length."""

        # Create a password with a 72 bytes length
        password = 'A' * 72
        pw_hash = self.flask_bcrypt.generate_password_hash(password)
        # Ensure that a longer password **do not** yield the same hash
        self.assertFalse(self.flask_bcrypt.check_password_hash(pw_hash, 'A' * 80))


class SanicLongPasswordsTestCase(SanicBasicTestCase):

    def setUp(self):
        sanic_app = Sanic(__name__)
        sanic_app.config['BCRYPT_LOG_ROUNDS'] = 6
        sanic_app.config['BCRYPT_HASH_IDENT'] = '2b'
        sanic_app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = True
        self.sanic_bcrypt = Bcrypt(sanic_app)

    def test_long_password(self):
        """Test the work around bcrypt maximum password length."""

        # Create a password with a 72 bytes length
        password = 'A' * 72
        pw_hash = self.sanic_bcrypt.generate_password_hash(password)
        # Ensure that a longer password **do not** yield the same hash
        self.assertFalse(self.sanic_bcrypt.check_password_hash(pw_hash, 'A' * 80))


class QuartLongPasswordsTestCase(QuartBasicTestCase):

    def setUp(self):
        quart_app = Quart(__name__)
        quart_app.config['BCRYPT_LOG_ROUNDS'] = 6
        quart_app.config['BCRYPT_HASH_IDENT'] = '2b'
        quart_app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = True
        self.quart_bcrypt = Bcrypt(quart_app)

    def test_long_password(self):
        """Test the work around bcrypt maximum password length."""

        # Create a password with a 72 bytes length
        password = 'A' * 72
        pw_hash = self.quart_bcrypt.generate_password_hash(password)
        # Ensure that a longer password **do not** yield the same hash
        self.assertFalse(self.quart_bcrypt.check_password_hash(pw_hash, 'A' * 80))


class EveLongPasswordsTestCase(EveBasicTestCase):

    def setUp(self):
        eve_app = Quart(__name__)
        eve_app.config['BCRYPT_LOG_ROUNDS'] = 6
        eve_app.config['BCRYPT_HASH_IDENT'] = '2b'
        eve_app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = True
        self.eve_bcrypt = Bcrypt(eve_app)

    def test_long_password(self):
        """Test the work around bcrypt maximum password length."""

        # Create a password with a 72 bytes length
        password = 'A' * 72
        pw_hash = self.eve_bcrypt.generate_password_hash(password)
        # Ensure that a longer password **do not** yield the same hash
        self.assertFalse(self.eve_bcrypt.check_password_hash(pw_hash, 'A' * 80))


if __name__ == '__main__':
    unittest.main()
