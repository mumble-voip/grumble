# Copyright (c) 2010 The Grumble Authors
# The use of this source code is goverened by a BSD-style
# license that can be found in the LICENSE-file.

include $(GOROOT)/src/Make.inc

TARG = grumble
ifeq ($(GOOS),windows)
TARG:=$(TARG).exe
endif

PACKAGES = \
	pkg/packetdatastream \
	pkg/cryptstate \
	pkg/mumbleproto \
	pkg/blobstore \
	pkg/serverconf \
	pkg/sessionpool \
	pkg/ban \
	pkg/htmlfilter \
	pkg/freezer

GCFLAGS = \
	-Ipkg/cryptstate/_obj \
	-Ipkg/packetdatastream/_obj \
	-Ipkg/mumbleproto/_obj \
	-Ipkg/blobstore/_obj \
	-Ipkg/serverconf/_obj \
	-Ipkg/sessionpool/_obj \
	-Ipkg/ban/_obj \
	-Ipkg/htmlfilter/_obj \
	-Ipkg/freezer/_obj

LDFLAGS = \
	-Lpkg/cryptstate/_obj \
	-Lpkg/packetdatastream/_obj \
	-Lpkg/mumbleproto/_obj \
	-Lpkg/blobstore/_obj \
	-Lpkg/serverconf/_obj \
	-Lpkg/sessionpool/_obj \
	-Lpkg/ban/_obj \
	-Lpkg/htmlfilter/_obj \
	-Lpkg/freezer/_obj

GOFILES = \
	grumble.go \
	message.go \
	server.go \
	client.go \
	channel.go \
	acl.go \
	group.go \
	user.go \
	freeze.go \
	gencert.go \
	register.go \
	ssh.go \
	log.go \
	args.go \

ifeq ($(SQLITE),1)
	GOFILES += murmurdb.go
	PACKAGES += pkg/sqlite
	GCFLAGS += -Ipkg/sqlite/_obj
	LDFLAGS += -Lpkg/sqlite/_obj
else
	GOFILES += murmurdb_null.go
endif

ifeq ($(GOOS),windows)
	GOFILES += signal_windows.go
else
	GOFILES += signal_unix.go
endif

.PHONY: grumble
grumble: pkg
	$(GC) $(GCFLAGS) -o $(TARG).$(O) $(GOFILES)
	$(LD) $(LDFLAGS) -o $(TARG) $(TARG).$(O)

.PHONY: pkg
pkg:
	for dir in $(PACKAGES); do $(MAKE) -C $$dir; done

.PHONY: pkgclean
pkgclean:
	for dir in $(PACKAGES); do $(MAKE) -C $$dir clean; done

.PHONY: clean
clean: pkgclean
	rm -f grumble
	rm -f *.$(O)
