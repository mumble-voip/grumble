#include "CryptState.h"
#include <stdio.h>

unsigned char msg[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static void DumpBytes(unsigned char *bytes, unsigned int len, const char *name) {
	printf("unsigned char %s[] = { ", name);
	for (int i = 0; i < len; i++) {
		printf("0x%.2x, ", bytes[i]);
	}
	printf("}\n");
}

int main(int argc, char *argv[]) {
	MumbleClient::CryptState cs;
	cs.genKey();

	DumpBytes(cs.raw_key, AES_BLOCK_SIZE, "rawkey");
	DumpBytes(cs.encrypt_iv, AES_BLOCK_SIZE, "encrypt_iv");
	DumpBytes(cs.decrypt_iv, AES_BLOCK_SIZE, "decrypt_iv");

	unsigned char buf[19];
	cs.encrypt(msg, &buf[0], 15);

	DumpBytes(buf, 19, "crypted");
}
