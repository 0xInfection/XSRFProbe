#!/usr/bin/env python

import io
from setuptools import setup, find_packages
from os import path
this_directory = path.abspath(path.dirname(__file__))
with io.open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    desc = f.read()

setup(
    name='xsrfprobe',
    version=__import__('xsrfprobe').__version__,
    long_description=desc,
    long_description_content_type='text/markdown',
    author='Pinaki Mondal',
    author_email='theinfecteddrake@gmail.com',
    license=__import__('xsrfprobe').__license__,
    url='https://github.com/0xInfection/XSRFProbe',
    download_url='https://github.com/0xInfection/XSRFProbe/archive/v2.1.zip',
    packages=find_packages(),
    scripts=['xsrfprobe/bin/xsrfprobe'],
    install_requires=[
        'requests',
        'bs4',
        'stringdist',
        'tld',
        'yattag'
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
    ],
    keywords=['csrf', 'xsrf', 'appsec', 'vulnerability scanner', 'webapps'],
)
