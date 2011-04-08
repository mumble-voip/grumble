# Copyright 2010 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=sqlite

CGOFILES=sqlite.go
CGO_OFILES=sqlite3.o

ifeq ($(GOOS),linux)
CGO_LDFLAGS=-lpthread -ldl
endif

include $(GOROOT)/src/Make.pkg
