""" Setup script """
import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="revproxy_auth",
    version="0.1.16",
    author="Ismael Raya",
    author_email="phornee@gmail.com",
    description="Reverse proxy with synology authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Phornee/revproxy_auth",
    packages=setuptools.find_packages(),
    include_package_data=True,
    # data_files=[
    #     ('tests/data', ['tests/data/config.yml'])
    # ],
    # package_data={
    #     'revproxy_auth/css': ['view.css'],
    #     'templates': ['form.html']
    # },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Home Automation"
    ],
    install_requires=[
        'Flask>=3.1.0',
        'config_yml>=0.3.0',
        'beautifulsoup4>=4.13.3',
        'requests>=2.32.3'
    ],
    python_requires='>=3.11',
)
