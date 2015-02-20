#!/usr/bin/env python

# chardet's setup.py
from distutils.core import setup
setup(
    name = "pro_vision",
    packages = [""],
    version = "0.2.0",
    description = "Ansible Pro Vision Library",
    author = "Patrick Galbraith",
    author_email = "patg@hp.com",
    url = "http://patg.net/",
    download_url = "http://tbd.tgz",
    keywords = ["pro-vision", "hp switches", "ansible"],
    classifiers = [
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Development Status :: 4 - Beta",
        "Environment :: Other Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Text Processing :: Linguistic",
        ],
    long_description = """\

Provision Switch Library for Ansible
-------------------------------------

Contains routines to talk manage a Pro Vision-based switch using Ansible

This version requires Python 2.7 or later
"""
)
