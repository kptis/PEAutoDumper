from setuptools import setup
import os


setup(
    name='peautodumper',
    version=1.0,
    url='https://github.com/kptis/PEAutoDumper.git',
    author="n33r9",
    description="PE dump and Import address table rebuild.",
    install_requires=['winappdbg','distorm3','elfesteem'],
    py_modules=['MTA_dump_rebuild'],
    entry_points={'console_scripts': ['MTA_dump_rebuild=MTA_dump_rebuild:main']}
)

