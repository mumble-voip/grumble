#!/bin/bash
# Syncs the Mumble.proto file with the main Mumble repo

curl -O https://raw.github.com/mumble-voip/mumble/master/src/Mumble.proto
sed -i -e 's,MumbleProto,mumbleproto,' Mumble.proto
