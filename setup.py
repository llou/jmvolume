import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="localo",
    version="0.0.1",
    author="Jorge Monforte González",
    author_email="yo@llou.net",
    description="A cryptsetup, Linux encrypted volumes, wrapper",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/llou/localo",
    py_modules=["gnupg"],
    platforms="linux",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='==2.7',
)
