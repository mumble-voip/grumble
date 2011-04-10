# Copyright (c) 2010 The Grumble Authors
# The use of this source code is goverened by a BSD-style
# license that can be found in the LICENSE-file.

include $(GOROOT)/src/Make.inc

TARG = grumble

PACKAGES = \
	pkg/packetdatastream \
	pkg/cryptstate \
	pkg/mumbleproto \
	pkg/blobstore \
	pkg/sqlite

GCFLAGS = \
	-Ipkg/cryptstate/_obj \
	-Ipkg/packetdatastream/_obj \
	-Ipkg/mumbleproto/_obj \
	-Ipkg/blobstore/_obj \
	-Ipkg/sqlite/_obj

LDFLAGS = \
	-Lpkg/cryptstate/_obj \
	-Lpkg/packetdatastream/_obj \
	-Lpkg/mumbleproto/_obj \
	-Ipkg/blobstore/_obj \
	-Lpkg/sqlite/_obj

GOFILES = \
	grumble.go \
	message.go \
	tlsserver.go \
	server.go \
	client.go \
	channel.go \
	acl.go \
	group.go \
	user.go \
	murmurdb.go \
	freeze.go

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
