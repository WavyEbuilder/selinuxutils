=============
SELinux Utils
=============

Standalone userspace SELinux utilities for Linux systems.

Building
========

SELinux Utils has two official build paths, mesonbuild and autotools.

Meson
-----

.. code-block:: sh

   meson setup build && ninja -C build

Autotools
---------

.. code-block:: sh

   ./autogen.sh && ./configure && make

Licence
-------

SELinux Utils has parts derived from the GNU Project's `coreutils <https://www.gnu.org/software/coreutils/>`_. As such, SELinux Utils is licensed under the GNU GPL3. A copy of the licence text can be found in `COPYING <COPYING>`_.
