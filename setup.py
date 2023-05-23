""" Setup script """
import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="revproxy_auth",
    version="0.1.3",
    author="Ismael Raya",
    author_email="phornee@gmail.com",
    description="Reverse proxy with synology authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Phornee/revproxy_auth",
    packages=setuptools.find_packages(),
    include_package_data=True,
    data_files=[
        ('tests/data', ['tests/data/config.yml'])
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Home Automation"
    ],
    install_requires=[
        'Flask>=1.1.2',
        'config_yml>=0.3.0',
        'beautifulsoup4>=4.10.0'
    ],
    python_requires='>=3.6',
)
