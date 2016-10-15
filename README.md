
Linux CI (Travis CI):

[![Build Status](https://travis-ci.org/mumble-voip/grumble.svg?branch=master)](https://travis-ci.org/mumble-voip/grumble)

Windows CI (AppVeyor):

[![Build status](https://ci.appveyor.com/api/projects/status/yfvg0eagpuy9kgg9/branch/master?svg=true)](https://ci.appveyor.com/project/mumble-voip/grumble/branch/master)


What is Grumble?
================

Grumble is an implementation of a server for the Mumble voice chat system. It is an alternative to Murmur, the typical Mumble server.

Compiling Grumble from source
=============================

You must have a Go 1 environment installed to build Grumble. Those are available at:

https://golang.org/dl/

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

Project status
==============

Grumble is pretty much feature complete, except for a few "minor" things.

There is no bandwidth limiting, and there is no API to remote control it.

Grumble's persistence layer is very ad-hoc. It uses an append-only file to store delta updates to each server's internal data, and periodically, it syncs a server's full data to disk.

Grumble is currently architected to have all data in memory. That means it's not ideal for use with very very large servers. (And large servers in this context are servers with many registered users, ACLs, etc.).

It is architected this way because it allowed me to write a pure-Go program with very few external dependencies, back 4-5 years ago.

The current thinking is that if registered users are taking up too much of your memory, you should use an external authenticator. But that code isn't written yet. The concept would be equivalent to Murmur's authenticator API via RPC. But a Grumble authenticator would probably be set up more akin to a webhook -- so just a URL in the config file.

Then there's the API problem. You can't currently remote control Grumble. Which can make it hard to use in production. I imagine Grumble will grow an API that it makes available via HTTP. Murmur's API is already quite stateless in many regards, so it shouldn't be too much of a stretch to put a RESTful API in Grumble to do the same job.
