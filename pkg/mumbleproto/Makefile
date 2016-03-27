Mumble.proto:
	curl -O https://raw.githubusercontent.com/mumble-voip/mumble/master/src/Mumble.proto
	sed -i -e 's,MumbleProto,mumbleproto,' $@

Mumble.pb.go: Mumble.proto
	protoc --go_out=. $<
