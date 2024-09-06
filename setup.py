from setuptools import setup
import os


setup(
    name='peautodumper',
    version=1.0,
    url='https://github.com/kptis/PEAutoDumper.git',
    author="n33r9",
    description="PE dump and Import address table rebuild.",
    install_requires=['winappdbg','distorm3','elfesteem'],
    py_modules=['pyiatrebuild'],
    entry_points={'console_scripts': ['pyiatrebuild=pyiatrebuild:main']}
)

