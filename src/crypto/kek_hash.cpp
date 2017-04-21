#include "crypto/kek_hash.h"
#include "crypto/sha256.h"
#include "crypto/scrypt.h"
#include <stdlib.h>

void runKekHash(char* source, int length, char* destination)
{
	unsigned static const char strShadilay[] = "Shadilay ";
	unsigned static const char strKek[] = "Kek ";
	char scryptHash[32];
	// Take SHA256(SHA256(blockHeader))
	sha256.Reset();
	sha256.Write(blockHeader, length);
	sha256.Finalize(destination);
	
	sha256.Reset();
	sha256.Write(hash, 32);
	sha256.Finalize(destination);
	
	unsigned char* scryptScratchPad = (unsigned char*)malloc(131583);
	scrypt_1024_1_1_256_sp_sse2((const char*)destination, (char*)scryptHash, (char*)scryptScratchPad);
	free(scryptScratchPad);
	for (int i=0; i<32; i++)
	{
		destination[i] ^= scryptHash[i];
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
}
