=====================
Welcome to Bluepass!!
=====================

Bluepass is a next-generation password manager. Currently it is available as a
beta version, and needs to be installed from source. Binary packages will be
provided in the future.

NOTE: The instructions below install Bluepass in a virtualenv. This way you
don't need to update or replace system provided packages of e.g. gevent.

Debian/Ubuntu based systems
===========================

Execute the following steps::

  $ sudo apt-get install gcc python-dev cython python-qt4 libdbus-1-dev \
          libssl-dev python-virtualenv python-six python-greenlet
  $ virtualenv --distribute --system-site-packages bluepass-dev
  $ . bluepass-dev/bin/activate
  $ pip install --upgrade git+git://github.com/surfly/gevent.git@1.0rc2#egg=gevent
  $ git clone https://github.com/geertj/bluepass
  $ cd bluepass
  $ python setup.py install

Red Hat/Fedora based systems
============================

Steps::

  $ sudo yum install gcc python-devel Cython PyQt4 dbus-devel openssl-devel \
        python-virtualenv python-six python-greenlet
  $ virtualenv --distribute --system-site-packages bluepass-dev
  $ . bluepass-dev/bin/activate
  $ pip install --upgrade git+git://github.com/surfly/gevent.git@1.0rc2#egg=gevent
  $ git clone https://github.com/geertj/bluepass
  $ cd bluepass
  $ python setup.py install

Mac OSX
=======

NOTE: Bluepass on Mac OSX currently does not support P2P synchronization.

Preparation:

1. Install Xcode via the Mac App Store. This is a free download.
2. Install the Xcode command-line tools. Start up Xcode, select Xcode ->
   Preferences -> Components, and then install the "Command Line Tools"
   component.
3. Install Homebrew from http://brew.sh/

Steps::

  $ brew install pyqt git
  $ sudo easy_install virtualenv
  $ virtualenv --distribute bluepass-dev
  $ echo /usr/local/lib/python2.7/site-packages > \
        bluepass-dev/lib/python2.7/site-packages/brew.pth
  $ bluepass-dev/bin/activate
  $ pip install six cython greenlet
  $ pip install git+git://github.com/surfly/gevent.git@1.0rc2#egg=gevent
  $ git clone https://github.com/geertj/bluepass
  $ cd bluepass
  $ python setup.py install
