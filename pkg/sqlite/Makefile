# Copyright 2010 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=sqlite

CGOFILES=sqlite.go

ifneq ($(GOOS),windows)
CGO_OFILES=sqlite3.o
endif

ifeq ($(GOOS),linux)
CGO_LDFLAGS=-lpthread -ldl
endif

ifeq ($(GOOS),windows)
# requires a .dll and .def in c:\sqlite
# beware of version incompatibilities:
# build uses sqlite3.h header from this dir
CGO_LDFLAGS=-Lc:/sqlite -lsqlite3
endif

include $(GOROOT)/src/Make.pkg
