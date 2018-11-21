/* A RELP sender for the testbench.
 *
 * Copyright 2018 Adiscon GmbH
 * Copyright 2014 Mathias Nyman
 *
 * See getopt() call below for command line options. There is a brief
 * (buf hopefully sufficient) comment describing what each option does.
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include "librelp.h"

#define TRY(f) if(f != RELP_RET_OK) { fprintf(stderr, "send: FAILURE in '%s'\n", #f); ret = 1; goto done; }

static const char *under_ci = NULL; /* if non-null, we run under CI, so be even more sparse with stdout */
static FILE *errFile = NULL;
static FILE *dbgFile = NULL;
static relpEngine_t *pRelpEngine;
static size_t msgDataLen = 0;
static int num_messages = 0;
static size_t lenMsg = 0;
static relpClt_t *pRelpClt = NULL;
static int kill_on_msg = 0;	/* 0 - do not kill, else exact message */
static int kill_signal = SIGUSR1;	/* signal to use when we kill */
static pid_t kill_pid = 0;

#define USR_MAGIC 0x1234FFee
struct usrdata { /* used for testing user pointer pass-back */
	int magic;
	char *progname;
};
struct usrdata *userdata = NULL;


static void __attribute__((format(printf, 1, 2)))
dbgprintf(char *fmt, ...)
{
	va_list ap;
	char pszWriteBuf[32*1024+1];

	va_start(ap, fmt);
	vsnprintf(pszWriteBuf, sizeof(pszWriteBuf), fmt, ap);
	va_end(ap);
	fprintf(dbgFile, "send.c: %s", pszWriteBuf);
}

void print_usage(void)
{
	printf("Usage: send -t <SERVER> -p <PORTNUM> -m <MESSAGE>\n");
}

static void
onErr(void *pUsr, char *objinfo, char* errmesg, __attribute__((unused)) relpRetVal errcode)
{
	struct usrdata *pThis = (struct usrdata*) pUsr;
	if(pUsr != userdata) {
		fprintf(stderr, "send: pUsr NOT pointing to usrdata!\n");
	}
	if(pThis->magic != USR_MAGIC) {
		fprintf(stderr, "send: pUsr magic incorrect in onErr, magic %8.8x "
			"pUsr %p\n", pThis->magic, (void*) pThis);
	}
	printf("%s: error '%s', object '%s'\n", pThis->progname, errmesg, objinfo);
	if(errFile != NULL) {
		fprintf(errFile, "send: error '%s', object '%s'\n", errmesg, objinfo);
	}
}

static void
onGenericErr(char *objinfo, char* errmesg, __attribute__((unused)) relpRetVal errcode)
{
	printf("send: librelp error '%s', object '%s'\n", errmesg, objinfo);
	if(errFile != NULL) {
		fprintf(errFile, "send: librelp error '%s', object '%s'\n", errmesg, objinfo);
	}

}

static void
onAuthErr( __attribute__((unused)) void *pUsr, char *authinfo,
	char* errmesg, __attribute__((unused)) relpRetVal errcode)
{
	printf("send: authentication error '%s', object '%s'\n", errmesg, authinfo);
	if(errFile != NULL) {
		fprintf(errFile, "send: authentication error '%s', object '%s'\n", errmesg, authinfo);
	}
}

static void
exit_hdlr(void)
{
	if(userdata != NULL) {
		free(userdata->progname);
		free(userdata);
	}
	if(errFile != NULL) {
		fclose(errFile);
	}
	if(dbgFile != NULL) {
		fclose(dbgFile);
	}
}


static void
retry_connect(void)
{
	relpRetVal ret;
	int try = 0;
	while(try++ < 15) {
		ret = relpCltReconnect(pRelpClt);
		if(ret == RELP_RET_OK)
			return;
		sleep(1);
	}
	fprintf(stderr, "send: send giving up after max retries\n");
	exit(1);
}


static int
send_msgs_counter(void)
{
	int ret;
	char buf[10];
	relpRetVal r;
	for(int i = 1 ; i <= num_messages ; ++i) {
		const ssize_t len = snprintf(buf, sizeof(buf), "%8.8d", i);
		if(len < 0 || len >= (ssize_t) sizeof(buf)) {
			fprintf(stderr, "send: ERROR: snprintf failed with %lld\n", (long long) len);
			exit(1);
		}
		if(!under_ci && (i % 1000 == 0)) {
			printf("\r%8.8d msgs sent", i);
		}
		r = relpCltSendSyslog(pRelpClt, (unsigned char*)buf, len);
		if(r != RELP_RET_OK) {
			fprintf(stderr, "send: failure %d in relpCltSendSyslog, msg %d\n", r, i);
			if(dbgFile != NULL)
				fprintf(dbgFile, "\n\nfailure %d in relpCltSendSyslog, msg %d\n\n\n", r, i);
			retry_connect();
			--i; /* we need to-resend the failed message */
		}
		if(kill_on_msg == i) {
			kill_on_msg = 0; /* do this only once, even in retry mode */
			fprintf(stderr, " sending signal %d to %lld\n", kill_signal, (long long) kill_pid);
			if(kill(kill_pid, kill_signal) != 0) {
				perror("kill process");
			}
		}
	}
	printf("\r%8.8d msgs sent\n", num_messages);
done:	return ret;
}

static int
send_msgs_single(const char *pMsg)
{
	int ret;
	char *msgData = NULL;

	if(msgDataLen != 0) {
		msgData = malloc(msgDataLen+1);
		strcpy(msgData, pMsg);

		/* fill with 01234567890123... digit sequence */
		size_t i;
		for(i=0; i < (msgDataLen-lenMsg); i++) {
			*(msgData+lenMsg+i) = i%10 + '0';
		}
		msgData[msgDataLen] = '\0';
		pMsg = msgData;
		lenMsg = msgDataLen;
	}

	TRY(relpCltSendSyslog(pRelpClt, (unsigned char *)pMsg, lenMsg));

	if(msgDataLen != 0) {
		free((void *)pMsg);
	}
done:	return ret;
}


int main(int argc, char *argv[]) {

	int c;
	int option_index = 0;
	unsigned char *port = NULL;
	unsigned char *target = NULL;
	const char *pMsg = NULL;
	unsigned timeout = 90;
	int verbose = 0;
	int protFamily = 2; /* IPv4=2, IPv6=10 */
	int bEnableTLS = 0;
	char *caCertFile = NULL;
	char *myCertFile = NULL;
	char *myPrivKeyFile = NULL;
	char *permittedPeer = NULL;
	char *authMode = NULL;
	const char *tlslib = NULL;
	int len = 0;
	int ret = 0;

	under_ci = getenv("UNDER_CI");
	dbgFile = stdout;

	#define KILL_ON_MSG	256
	#define KILL_SIGNAL	257
	#define KILL_PID	258
	#define DBGFILE		259
	static struct option long_options[] =
	{
		{"ca", required_argument, 0, 'x'},
		{"cert", required_argument, 0, 'y'},
		{"key", required_argument, 0, 'z'},
		{"peer", required_argument, 0, 'P'},
		{"authmode", required_argument, 0, 'a'},
		{"errorfile", required_argument, 0, 'e'},
		{"tls-lib", required_argument, 0, 'l'},
		{"debugfile", required_argument, 0, DBGFILE},
		{"num-messages", required_argument, 0, 'n'},
		{"kill-on-msg", required_argument, 0, KILL_ON_MSG},
		{"kill-signal", required_argument, 0, KILL_SIGNAL},
		{"kill-pid", required_argument, 0, KILL_PID},
		{0, 0, 0, 0}
	};

	while((c = getopt_long(argc, argv, "a:e:d:l:m:n:P:p:Tt:vx:y:z:", long_options, &option_index)) != -1) {
		switch(c) {
		case 'a':
			authMode = optarg;
			break;
		case 'e':
			if((errFile = fopen(optarg, "w")) == NULL) {
				perror(optarg);
				fprintf(stderr, "error opening error file\n");
				exit(1);
			}
			break;
		case DBGFILE:
			if((dbgFile = fopen(optarg, "w")) == NULL) {
				perror(optarg);
				fprintf(stderr, "error opening debug file\n");
				exit(1);
			}
			break;
		case 'd':
			len = atoi(optarg);
			if(len < 128) {
				fprintf(stderr, "send.c: messageSize has invalid "
					"value: %d - must be at least 128\n", len);
				exit(1);
			} else {
				msgDataLen = len;
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case 'l': /* tls lib */
			tlslib = optarg;
			break;
		case 'm': /* message text to send */
			pMsg = (const char*)optarg;
			lenMsg = strlen(pMsg);
			break;
		case 'n':
			num_messages = atoi(optarg);
			break;
		case 'P':
			permittedPeer = optarg;
			break;
		case 'p':
			port = (unsigned char*)optarg;
			break;
		case 'T':
			bEnableTLS = 1;
			break;
		case 't':
			target = (unsigned char*)optarg;
			break;
		case 'x':
			caCertFile = optarg;
			break;
		case 'y':
			myCertFile = optarg;
			break;
		case 'z':
			myPrivKeyFile = optarg;
			break;
		case KILL_ON_MSG:
			kill_on_msg = atoi(optarg);
			break;
		case KILL_SIGNAL:
			kill_signal = atoi(optarg);
			break;
		case KILL_PID:
			kill_pid = atoi(optarg);
			break;
		default:
			print_usage();
			exit(1);
		}
	}

	atexit(exit_hdlr);

	if(msgDataLen != 0 && msgDataLen < lenMsg) {
		fprintf(stderr, "send: message is larger than configured message size!\n");
		exit(1);
	}

	if (target == NULL || port == NULL || (pMsg == NULL && num_messages == 0)) {
		printf("Missing parameter\n");
		print_usage();
		exit(1);
	}

	if(authMode != NULL) {
		if(	(strcasecmp(authMode, "certvalid")  != 0 && permittedPeer == NULL) ||
			caCertFile == NULL || myCertFile == NULL || myPrivKeyFile == NULL) {
			printf("send: mode '%s' parameter missing; certificates and permittedPeer required\n",
				authMode);
			exit(1);
		}
	}

	if(caCertFile != NULL || myCertFile != NULL || myPrivKeyFile != NULL) {
		if(bEnableTLS == 0) {
			printf("send: Certificates were specified, but TLS was "
			       "not enabled! To enable it use parameter \"-T\"\n");
			exit(1);
		}
	}



	TRY(relpEngineConstruct(&pRelpEngine));
	TRY(relpEngineSetDbgprint(pRelpEngine, verbose ? dbgprintf : NULL));
	if(tlslib != NULL) {
		TRY(relpEngineSetTLSLibByName(pRelpEngine, tlslib));
	}

	TRY(relpEngineSetOnErr(pRelpEngine, onErr));
	TRY(relpEngineSetOnGenericErr(pRelpEngine, onGenericErr));
	TRY(relpEngineSetOnAuthErr(pRelpEngine, onAuthErr));


	TRY(relpEngineSetEnableCmd(pRelpEngine, (unsigned char*)"syslog", eRelpCmdState_Required));
	TRY(relpEngineCltConstruct(pRelpEngine, &pRelpClt));
	TRY(relpCltSetTimeout(pRelpClt, timeout));
	userdata = calloc(1, sizeof(struct usrdata));
	userdata->magic = USR_MAGIC;
	userdata->progname = strdup("send");
	TRY(relpCltSetUsrPtr(pRelpClt, userdata));

	if(bEnableTLS) {
		TRY(relpCltEnableTLS(pRelpClt));
		if(authMode != NULL) {
			TRY(relpCltSetAuthMode(pRelpClt, authMode));
			TRY(relpCltSetCACert(pRelpClt, caCertFile));
			TRY(relpCltSetOwnCert(pRelpClt, myCertFile));
			TRY(relpCltSetPrivKey(pRelpClt, myPrivKeyFile));
			if (permittedPeer != NULL) {
				TRY(relpCltAddPermittedPeer(pRelpClt, permittedPeer));
			}
		}
	}

	TRY(relpCltConnect(pRelpClt, protFamily, port, target));

	if(num_messages == 0) {
		send_msgs_single(pMsg);
	} else {
		send_msgs_counter();
	}

	TRY(relpEngineCltDestruct(pRelpEngine, &pRelpClt));
	TRY(relpEngineDestruct(&pRelpEngine));

done:
	return ret;
}
