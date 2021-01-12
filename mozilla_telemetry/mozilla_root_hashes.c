#include <stdint.h>
#include <stdio.h>
#include "RootHashes.inc"

int main() {
	int i, j;
	for (i = 0; i < sizeof(ROOT_TABLE)/sizeof(ROOT_TABLE[0]); i++) {
		printf("INSERT INTO mozilla_root_hashes_new (BIN_NUMBER, CERTIFICATE_SHA256) VALUES (%d, E'\\\\x", ROOT_TABLE[i].binNumber);
		for (j = 0; j < HASH_LEN; j++)
			printf("%02X", ROOT_TABLE[i].hash[j]);
		printf("');\n");
	}
}
