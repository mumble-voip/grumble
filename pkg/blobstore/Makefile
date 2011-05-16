include $(GOROOT)/src/Make.inc

TARG = grumble/blobstore
GOFILES = \
	blobstore.go \
	blobreader.go

ifeq ($(GOOS),windows)
GOFILES += pid_windows.go
else
GOFILES += pid_unix.go
endif

include $(GOROOT)/src/Make.pkg
