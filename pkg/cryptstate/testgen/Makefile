.PHONY: default
default:
	g++ test.cpp CryptState.cpp -o test -lcrypto
	g++ test2.cpp CryptState.cpp -o test2 -lcrypto
	g++ test3.cpp CryptState.cpp -o test3 -lcrypto

.PHONY: clean
clean:
	rm -f test test2 test3
