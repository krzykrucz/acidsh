#!/usr/bin/env python

from setuptools import setup

setup(name='acidsh',
      version='1.0',
      description='Transactional shell',
      packages=['acidsh', 'acidsh.builtins'],
      entry_points="""
      [console_scripts]
      acidsh = acidsh.shell:main
      """,
      )
