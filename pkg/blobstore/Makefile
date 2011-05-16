include $(GOROOT)/src/Make.inc

TARG = grumble/blobstore
GOFILES = \
	blobstore.go \
	blobreader.go

ifeq ($(GOOS),windows)
GOFILES += lock_windows.go
else
GOFILES += lock_unix.go
endif

include $(GOROOT)/src/Make.pkg
