__author__ = 'Robert Cope'
__version__ = '0.0.1.dev1'

from setuptools import setup
from pip.req import parse_requirements
import os

requirements = parse_requirements(os.path.join(os.path.realpath(__file__), 'requirements.txt'))

setup(name='PyDNS',
      author=__author__,
      author_email='robert.cope@pushrodtechnology.com',
      version=__version__,
      packages='PyDNS',
      install_requires=requirements)
