# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):

    user_options = [("pytest-args=", "a", "Args to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        sys.exit(pytest.main(self.pytest_args))


setup(
    name="tabi",
    version="1.0.2",
    description="Detect hijacks from BGP logs",
    url="https://github.com/ANSSI-FR/tabi",
    author="ANSSI/SDE",
    author_email="sde.lrp@ssi.gouv.fr",
    license="mit",
    packages=find_packages(exclude=["tests*", "examples*"]),
    entry_points={
        "console_scripts": ["tabi=tabi.parallel.__main__:main"]
    },
    install_requires=[
        "py-radix",
        "python-dateutil",
    ],
    tests_require=["pytest>=2.7.1"],
    cmdclass={"test": PyTest}
)
