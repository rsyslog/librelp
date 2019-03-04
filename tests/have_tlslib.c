/* a simple program to check which TLs libs are available in
 * the current build. Returns 0 if available, 1 if not, 2 if error.
 * Written 2018-11-23 by Rainer Gerhards, released under ASL 2.0
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

int
main(int argc, char *argv[])
{
	if(argc != 2) {
		fprintf(stderr, "usage: have_tlslib <libname>\n");
		exit(2);
	}

	#if defined(ENABLE_TLS)
		if(!strcasecmp(argv[1], "gnutls"))
			exit(0);
	#endif
	#if defined(ENABLE_TLS_OPENSSL)
		if(!strcasecmp(argv[1], "openssl"))
			exit(0);
	#endif
	return 1;
}
