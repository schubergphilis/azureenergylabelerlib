#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
try:
    from pipenv.project import Project
    from pipenv.utils import convert_deps_to_pip

    pfile = Project().parsed_pipfile
    requirements = convert_deps_to_pip(pfile['packages'], r=False)
    test_requirements = convert_deps_to_pip(pfile['dev-packages'], r=False)
except ImportError:
    # get the requirements from the requirements.txt
    requirements = [line.strip()
                    for line in open('requirements.txt').readlines()
                    if line.strip() and not line.startswith('#')]
    # get the test requirements from the test_requirements.txt
    test_requirements = [line.strip()
                         for line in
                         open('dev-requirements.txt').readlines()
                         if line.strip() and not line.startswith('#')]

readme = open('README.rst').read()
history = open('HISTORY.rst').read().replace('.. :changelog:', '')
version = open('.VERSION').read()


setup(
    name='''azureenergylabelerlib''',
    version=version,
    description='''A python library that generates energy labels based on findings in Azure subscriptions''',
    long_description=readme + '\n\n' + history,
    author='''Sayantan Khanra''',
    author_email='''skhanra@schubergphilis.com''',
    url='''https://github.com/schubergphilis/azureenergylabelerlib''',
    packages=find_packages(where='.', exclude=('tests', 'hooks', '_CI*')),
    package_dir={'''azureenergylabelerlib''':
                 '''azureenergylabelerlib'''},
    include_package_data=True,
    install_requires=requirements,
    license='MIT',
    zip_safe=False,
    keywords='''azureenergylabelerlib ''',
    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.7',
        ],
    test_suite='tests',
    tests_require=test_requirements
)
