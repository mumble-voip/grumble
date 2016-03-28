// +build ignore

package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"regexp"
)

var replacements = []string{
	`(?m)^package MumbleProto;$`, `package mumbleproto;`,

	// Add crypto_modes to Version message.
	// It is only present in Grumble, not in upstream Murmur.
	`(?m)^(message Version {)$`, "$1\n\trepeated string crypto_modes = 5;\n",
}

func main() {
	// Fetch Mumble.proto
	resp, err := http.Get("https://raw.githubusercontent.com/mumble-voip/mumble/master/src/Mumble.proto")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Perform replacements
	for i := 0; i < len(replacements); i += 2 {
		re, rp := replacements[i], replacements[i+1]
		regex, err := regexp.Compile(re)
		if err != nil {
			log.Fatal(err)
		}
		data = regex.ReplaceAll(data, []byte(rp))
	}

	// Write Mumble.proto
	if err := ioutil.WriteFile("Mumble.proto", data, 0644); err != nil {
		log.Fatal(err)
	}

	// Run protobuf compiler
	if err := exec.Command("protoc", "--go_out=.", "Mumble.proto").Run(); err != nil {
		log.Fatal(err)
	}
}
