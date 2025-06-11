/*
	b64hash - print a base-64 encoded hash of user-supplied strings

	usage:	command [-d] [string ...]

*/
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>
#include <memory.h>             
#include "sha256.h"             
#include "base64.h"             

char *sha_string(BYTE *buf);

int debug = 0;

int b64hash(char *s);

int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int c, err = 0; 
	static char usage[] = "usage: %s [-d] [string ...]\n";

	while ((c = getopt(argc, argv, "d")) != -1)
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case '?':
			err = 1;
			break;
		}
	if (err) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	err = 0;	/* return code */
	if (optind < argc)
		for (; optind < argc; optind++)
			err |= b64hash(argv[optind]);
	else {
		/* no string given */
		char buf[256], *fgets();
		register int blen;

		while (fgets(buf, 256, stdin)) {
			blen=strlen(buf);
			if (blen && buf[blen-1] == '\n')
				buf[blen-1] = '\0';
			err |= b64hash(buf);
		}
	}
	return err;
}

int
b64hash(char *s)
{
	// compute the hash
	SHA256_CTX ctx;
	BYTE sha_result[SHA256_BLOCK_SIZE];

	sha256_init(&ctx); 
	sha256_update(&ctx, (BYTE*) s, strlen(s));
	sha256_final(&ctx, sha_result);

	printf("hash(message): %s\n", sha_string(sha_result));

	// get the base-64 encoding
	unsigned char b64_out[128];
	(void)base64_encode((BYTE *)sha_result, b64_out, 256/8, 0);
	printf("b64 hash = \"%s\"\n", b64_out);
	return 0;
} 

// return a hex string of the sha-256 hash 

char *  
sha_string(BYTE *buf)
{	       
	static char str[(SHA256_BLOCK_SIZE*2)+1];
	char *s = str;
	int i;

	for (i=0; i < SHA256_BLOCK_SIZE; i++) {
		sprintf(s, "%02x", buf[i]&0xff);
		s += 2;
	}
	*s = 0;
	return str;
}       
