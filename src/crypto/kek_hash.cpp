#include "crypto/kek_hash.h"
#include "crypto/sha256.h"
#include "crypto/scrypt.h"
#include "scrypt.h"
#include <stdlib.h>
#include <iostream>
#include <stdio.h>

void runKekHash(char* source, int length, char* destination)
{
	unsigned static const char strShadilay[] = "Shadilay ";
	unsigned static const char strKek[] = "Kek ";
	char scryptHash[32];
	CSHA256 sha256 = CSHA256();
	// Take SHA256(SHA256(blockHeader))
	sha256.Reset();
	sha256.Write((const unsigned char*)source, length);
	sha256.Finalize((unsigned char*)destination);
	
	printf("Intermediate SHA256 is:\r\n");
	for (int i=0; i<32; i++)
	{
		printf("%02X", destination[i]);
	}
	
	sha256.Reset();
	sha256.Write((const unsigned char*)destination, 32);
	sha256.Finalize((unsigned char*)destination);
	
	printf("\r\nFinal SHA256 is:\r\n");
	for (int i=0; i<32; i++)
	{
		printf("%02X", destination[i]);
	}
	
	unsigned char* scryptScratchPad = (unsigned char*)malloc(131583);
	scrypt_1024_1_1_256_sp_sse2((const char*)source, (char*)scryptHash, (char*)scryptScratchPad);
	free(scryptScratchPad);
	
	printf("\r\nScrypt hash is:\r\n");
	for (int i=0; i<32; i++)
	{
		printf("%02X", scryptHash[i]);
	}

	for (int i=0; i<32; i++)
	{
		destination[i] ^= scryptHash[i];
	}
	
	printf("\r\nScrypt^(SHA256^2) is:\r\n");
	for (int i=0; i<32; i++)
	{
		printf("%02X", destination[i]);
	}
	
	// Xor with Kek or Shadilay, effectively requiring Kek or Shadilay to be written at the end of the xor'd hashes
	if ((destination[0] & 1) == 0)
	{
		for (int i=0; i<32; i++)
		{
			destination[31-i] ^= strShadilay[i%sizeof(strShadilay)];
		}
	}
	else
	{
		for (int i=0; i<32; i++)
		{
			destination[31-i] ^= strKek[i%sizeof(strKek)];
		}
	}
	
	printf("\r\nAfter kek/shadilay overlay is:\r\n");
	for (int i=0; i<32; i++)
	{
		printf("%02X", destination[i]);
	}
}
