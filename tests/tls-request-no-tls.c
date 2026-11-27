/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Regression test: in a build without TLS support, a server TLS request must
 * be recorded even though the enable call reports RELP_RET_ERR_NO_TLS, so that
 * relpSrvRun() refuses to start instead of falling back to a plaintext
 * listener (fail-open).
 *
 * Oracle: every API call is made unconditionally (not inside assert(), which
 * NDEBUG would remove); the test fails with exit code 1 and a message if a
 * return code or the resulting server state differs from the expectation.
 */
#include <stdio.h>
#include <stddef.h>

#include "config.h"
#include "librelp.h"
#include "relp.h"
#include "relpsrv.h"

#define CHECK(cond, msg) do { \
	if(!(cond)) { \
		fprintf(stderr, "tls-request-no-tls: FAIL: %s\n", msg); \
		return 1; \
	} \
} while(0)

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpSrv_t *server = NULL;
	relpRetVal ret;

	ret = relpEngineConstruct(&engine);
	CHECK(ret == RELP_RET_OK, "relpEngineConstruct failed");
	/* like every real caller, install the debug hook; without it the engine's
	 * dbgprint pointer stays NULL and the first debug call crashes */
	ret = relpEngineSetDbgprint(engine, NULL);
	CHECK(ret == RELP_RET_OK, "relpEngineSetDbgprint failed");
	ret = relpEngineListnerConstruct(engine, &server);
	CHECK(ret == RELP_RET_OK, "relpEngineListnerConstruct failed");

	ret = relpSrvEnableTLS2(server);
	CHECK(ret == RELP_RET_ERR_NO_TLS, "relpSrvEnableTLS2 did not report RELP_RET_ERR_NO_TLS");
	ret = relpSrvEnableTLSZip2(server);
	CHECK(ret == RELP_RET_ERR_NO_TLS, "relpSrvEnableTLSZip2 did not report RELP_RET_ERR_NO_TLS");
	CHECK(server->bEnableTLS == 1, "TLS request was not recorded");
	CHECK(server->bEnableTLSZip == 1, "TLS zip request was not recorded");

	ret = relpSrvRun(server);
	CHECK(ret == RELP_RET_ERR_NO_TLS, "relpSrvRun did not refuse to start without TLS");
	CHECK(server->pTcp == NULL, "relpSrvRun created a listener");

	ret = relpSrvDestruct(&server);
	CHECK(ret == RELP_RET_OK, "relpSrvDestruct failed");
	ret = relpEngineDestruct(&engine);
	CHECK(ret == RELP_RET_OK, "relpEngineDestruct failed");
	return 0;
}
