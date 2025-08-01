/* A minimal RELP receiver using librelp
 *
 * Copyright 2014 Mathias Nyman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "librelp.h"

#define TRY(f) if(f != RELP_RET_OK) { printf("%s\n", #f); return 1; }

static relpEngine_t *pRelpEngine;

static void __attribute__((format(printf, 1, 2)))
dbgprintf(char *fmt, ...)
{
	va_list ap;
	char pszWriteBuf[32*1024+1];

	va_start(ap, fmt);
	vsnprintf(pszWriteBuf, sizeof(pszWriteBuf), fmt, ap);
	va_end(ap);
	printf("receive.c: %s", pszWriteBuf);
}

static relpRetVal onSyslogRcv(unsigned char *pHostname, unsigned char *pIP, unsigned char *msg, size_t lenMsg) {

	char *pMsg;

	pMsg = (char *) malloc((int)lenMsg+1);
	memset(pMsg, '\0', lenMsg+1);
	memcpy(pMsg, msg, lenMsg);

	printf("%s\n", pMsg);
	fflush(stdout);

	free(pMsg);

	return RELP_RET_OK;
}

void print_usage()
{
	printf("Usage: receive PORTNUM\n");
}

int main(int argc, char *argv[]) {
	if ((argc != 2)) {
	/* Incorrect parameter count, so just print the usage and return */
	print_usage();
	return -1;
}

	relpSrv_t *pRelpSrv;
	unsigned char *port = (unsigned char*)argv[1];
	int protFamily = 2; /* IPv4=2, IPv6=10 */

	TRY(relpEngineConstruct(&pRelpEngine));
	TRY(relpEngineSetDbgprint(pRelpEngine, dbgprintf));
	TRY(relpEngineSetEnableCmd(pRelpEngine, (unsigned char*) "syslog", eRelpCmdState_Required));
	TRY(relpEngineSetFamily(pRelpEngine, protFamily));
	TRY(relpEngineSetSyslogRcv(pRelpEngine, onSyslogRcv));
	TRY(relpEngineSetDnsLookupMode(pRelpEngine, 0)); /* 0=disable */

	TRY(relpEngineListnerConstruct(pRelpEngine, &pRelpSrv));
	TRY(relpSrvSetLstnPort(pRelpSrv, port));
	TRY(relpEngineListnerConstructFinalize(pRelpEngine, pRelpSrv));

	TRY(relpEngineRun(pRelpEngine)); /* Abort with ctrl-c */

	TRY(relpEngineSetStop(pRelpEngine));
	TRY(relpEngineDestruct(&pRelpEngine));

	return 0;
}
