=====================
Welcome to Bluepass!!
=====================

Bluepass is a secure password manager with peer-to-peer sync built in.
Currently it is an early beta version, and needs to be installed from source.

Generic installation instructions
=================================

The instructions below are generic installation instructions. You can find
specific instructions for Ubuntu and Fedora further down. Bluepass should work
on any recent Linux distribution. It should also work on Mac OSX and Windows,
but on these platforms P2P sync is not yet available. 

* Make sure you have a supported version of Python installed. The preferred
  version is Python 3.3, but 2.7 and 2.6 also work.
* Make sure you can compile and install C extensions for Python. This means
  that you need Python development files, a C compiler, make and pip. You
  also need git to check out the Bluepass source code.
* Install dependencies: PyQt4, libffi including development files and openssl
  including development files.
* If you want to install in a virtualenv, set one up and activate it.
* Clone the sources from Github: ``git clone https://github.com/geertj/bluepass``
* ``pip install -r requirements.txt`` from the bluepass directory.
* ``python setup.py install``

Installing on Ubuntu and Fedora
===============================

Ubuntu 13.04 and later, and Fedora 19 and later provide Python 3.3. On these
distributions it is recommended to use Python3 for running Bluepass.

First you need to install dependencies. Apart from Gruvi, all dependencies are
provided by the distribution. On Ubuntu::

  $ sudo apt-get -y install gcc make python3-dev python3-pyqt4 python3-pip \
        libssl-dev libffi-dev git curl

While on Fedora::

  $ sudo yum -y install gcc make python3-devel python3-PyQt4 python3-pip \
        openssl-devel libffi-devel git curl

Then run the following commands. These commands install Bluepass from Github
into a virtualenv. Pip itself is installed from source because of
https://github.com/pypa/pip/issues/1408. ::

  $ pyvenv-3.3 --system-site-packages bluepass-dev
  $ . bluepass-dev/bin/activate
  $ curl -O https://pypi.python.org/packages/source/p/pip/pip-1.4.1.tar.gz
  $ tar xvfz pip-1.4.1.tar.gz && pushd pip-1.4.1 && python setup.py install && popd
  $ git clone https://github.com/geertj/bluepass && pushd bluepass
  $ pip install -r requirements.txt
  $ python setup.py install

To run bluepass, use "bluepass" from the command line.

On previous versions of Ubuntu and Fedora use the generic installation
instructions.
