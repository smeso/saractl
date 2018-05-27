"""
    saractl - S.A.R.A.'s userspace utilities.
    Copyright (C) 2017  Salvatore Mesoraca <s.mesoraca16@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from setuptools import setup

with open('README.rst') as f:
    long_description = f.read()

setup(name='saractl',
      version='0.2',
      description='S.A.R.A.\'s userspace utilities.',
      author='Salvatore Mesoraca',
      author_email='s.mesoraca16@gmail.com',
      url='https://smeso.it/sara',
      license='GPLv3+',
      test_suite='tests',
      entry_points={'console_scripts': ['saractl = sara.main:main',
                                        'sara-xattr = sara.main:main [xattr]']},
      long_description=long_description,
      platforms='Linux',
      keywords='linux lsm linux-security-module sara security w^x',
      packages=['sara', 'sara.submodules'],
      extras_require={'elfcheck':  ["pyelftools"],
                      'capabilities': ["pythonprctl"],
                      'xattr': ["pyxattr"]},
      data_files=[('/etc/sara/', ['config/main.conf']),
                  ('/etc/sara/wxprot.conf.d/', ['config/99_wxprot.conf']),
                  ('/usr/share/man/man8/', ['man/saractl.8',
                                            'man/sara-xattr.8']),
                  ('/usr/share/man/man7/', ['man/sara.7']),
                  ('/usr/share/man/man5/', ['man/wxprot.conf.5'])],
      classifiers=['Development Status :: 3 - Alpha',
                   'Environment :: Console',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'Intended Audience :: End Users/Desktop',
                   'Natural Language :: English',
                   'Operating System :: POSIX :: Linux',
                   'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
                   'Programming Language :: Python :: 3',
                   'Programming Language :: Python :: 3.4',
                   'Programming Language :: Python :: 3 :: Only',
                   'Topic :: Security',
                   'Topic :: System :: Monitoring',
                   'Topic :: System :: Operating System Kernels :: Linux',
                   'Topic :: Utilities']
      )
