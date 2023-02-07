import setuptools
from powerhub._version import __version__

setuptools.setup(
    name='PowerHub',
    version=__version__,
    author='Adrian Vollmer',
    url='https://github.com/AdrianVollmer/PowerHub',
    description='A post exploitation tool based on a web application, '
        'focusing on bypassing endpoint protection and '
        'application whitelisting',
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'powerhub=powerhub.__main__:main'
        ],
    },
    install_requires=[
        'cheroot',
        'cryptography',
        'eventlet>=0.33.3',
        'Flask>=1.0.2',
        'Flask-SocketIO>=3.1.2',
        'flask-sqlalchemy>=3.0',
        'Jinja2>=3.0',
        'pyOpenSSL',
        'pypykatz>=0.2.2',
        'python-magic',
        'service_identity',
        'twisted>=18.9.0',
        'watchdog',
        'werkzeug>=0.15',
        'wsgidav>=3.0.0',
    ],
    python_requires='>=3',
    extras_require={
        'tests': ['pytest', 'beautifulsoup4', 'lxml', 'requests']
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
