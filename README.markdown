What is Grumble?
================

Grumble is an implementation of a server for the Mumble voice chat system. It is an alternative to Murmur, the typical Mumble server.

Compiling Grumble from source
=============================

You must have a Go 1 environment installed to build Grumble. Those are available at:

http://code.google.com/p/go/downloads/list

Once Go is installed, you should set up a GOPATH to avoid clobbering your Go environment's root directory with third party packages.

Set up a GOPATH. On Unix, do something like this

    $ export GOPATH=$HOME/gocode
    $ mkdir -p $GOPATH

and on Windows, do something like this (for cmd.exe):

    c:\> set GOPATH=%USERPROFILE\gocode
    c:\> mkdir %GOPATH%

Then, it's time to install Grumble. The following line should do the trick:

    $ go get mumble.info/grumble/cmd/grumble

And that should be it. Grumble has been built, and is available in $GOPATH/bin as 'grumble'.
