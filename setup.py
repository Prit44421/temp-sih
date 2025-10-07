from setuptools import setup, find_packages

setup(
    name='kavach',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click',
        'fastapi',
        'uvicorn[standard]',
        'distro',
        'cryptography',
        'textual',
    ],
    entry_points={
        'console_scripts': [
            'kavach = kavach.cli.kavach_cli:cli',
        ],
    },
)
