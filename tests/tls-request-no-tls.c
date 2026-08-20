/*
 * Regression test for recording a server TLS request in a build without TLS
 * support. The request must not fall through to a plaintext listener.
 */
#include <assert.h>
#include <stddef.h>

#include "config.h"
#include "librelp.h"
#include "relp.h"
#include "relpsrv.h"

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpSrv_t *server = NULL;

	assert(relpEngineConstruct(&engine) == RELP_RET_OK);
	assert(relpEngineListnerConstruct(engine, &server) == RELP_RET_OK);

	assert(relpSrvEnableTLS2(server) == RELP_RET_ERR_NO_TLS);
	assert(relpSrvEnableTLSZip2(server) == RELP_RET_ERR_NO_TLS);
	assert(server->bEnableTLS == 1);
	assert(server->bEnableTLSZip == 1);

	assert(relpSrvRun(server) == RELP_RET_ERR_NO_TLS);
	assert(server->pTcp == NULL);

	assert(relpSrvDestruct(&server) == RELP_RET_OK);
	assert(relpEngineDestruct(&engine) == RELP_RET_OK);
	return 0;
}
