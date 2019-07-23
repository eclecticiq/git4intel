from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="git4intel",
    description="elasticsearch threat intel client library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/eclecticiq/inc-mission-control-git4intel/",
    author="EclecticIQ",
    author_email="chris@eclecticiq.com",
    version='0.0.1',
    license="GNU General Public License v3.0",
    packages=find_packages(),
    install_requires=[
        'elasticsearch',
        'stix2',
        'taxii2-client',
        'python-slugify',
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Topic :: Internet",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
