#!/usr/bin/env python3

from setuptools import setup

setup(
    name="targetedKerberoast",
    version="0.1.0",
    description=(
        "TargetedKerberoast by Shutdown (@_nwodtuhs). "
    ),
    author="Shutdown",
    author_email="",
    url="https://github.com/ShutdownRepo/targetedKerberoast",
    license="MIT",
    py_modules=["targetedKerberoast"],
    scripts=["targetedKerberoast.py"],
    install_requires=[
        "ldap3>=2.9.1",
        "pyasn1>=0.4.8",
        "impacket>=0.9.24",
        "rich>=13.3.4",
    ],
    python_requires=">=3.6",
)
