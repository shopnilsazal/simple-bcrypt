'''
    simple-bcrypt
    ------------

    Bcrypt hashing for your App.
'''

import os

from setuptools import setup

module_path = os.path.join(os.path.dirname(__file__), 'simple_bcrypt.py')
with open(module_path) as module:
    for line in module:
        if line.startswith('__version_info__'):
            version_line = line
            break

__version__ = '.'.join(eval(version_line.split('__version_info__ = ')[-1]))

setup(
    name='simple-bcrypt',
    version=__version__,
    url='https://github.com/shopnilsazal/simple-bcrypt',
    license='BSD',
    author='Rafiqul Haasan',
    author_email='shopnilsazal@gmail.com',
    description='Bcrypt hashing for Flask, Sanic, Quart and Eve.',
    long_description=__doc__,
    py_modules=['simple_bcrypt'],
    zip_safe=False,
    platforms='any',
    install_requires=['bcrypt>=3.1.1'],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    test_suite='test_bcrypt'
)
