import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="jmvolume",
    version="0.0.1",
    author="Jorge Monforte González",
    author_email="yo@llou.net",
    description="A cryptsetup, Linux encrypted volumes, wrapper",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/llou/jmvolume",
    py_modules=["jmvolume"],
    platforms="linux",
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    python_requires='>=2.7',
)
