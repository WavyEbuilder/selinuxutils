# This file is a part of SELinux Utils.
# Copyright (C) Rahul Sandhu <rahul@sandhuservices.dev>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT([SELinux Utils], [1.0])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_PROG_CXX

AX_CXX_COMPILE_STDCXX(17, [noext], [mandatory])

AM_INIT_AUTOMAKE([foreign -Wall])

PKG_CHECK_MODULES([CLI11], [CLI11])
PKG_CHECK_MODULES([libselinux], [libselinux])

AC_CONFIG_FILES([
    Makefile
])

AC_OUTPUT
