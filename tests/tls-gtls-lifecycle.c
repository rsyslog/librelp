/*
 * Verify GnuTLS shutdown ordering and partial-session cleanup.
 */
#include "config.h"

#if defined(ENABLE_TLS)

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gnutls/gnutls.h>

#include "librelp.h"
#include "tcp.h"

static int watched_fd = -1;
static int fd_open_during_bye;
static unsigned int bye_count;
static unsigned int deinit_count;
static unsigned int cert_free_count;
static unsigned int anon_client_free_count;
static unsigned int anon_server_free_count;
static unsigned int dh_free_count;

int __wrap_gnutls_bye(gnutls_session_t session, gnutls_close_request_t how);
void __real_gnutls_deinit(gnutls_session_t session);
void __wrap_gnutls_deinit(gnutls_session_t session);
void __real_gnutls_certificate_free_credentials(gnutls_certificate_credentials_t credentials);
void __wrap_gnutls_certificate_free_credentials(gnutls_certificate_credentials_t credentials);
void __real_gnutls_anon_free_client_credentials(gnutls_anon_client_credentials_t credentials);
void __wrap_gnutls_anon_free_client_credentials(gnutls_anon_client_credentials_t credentials);
void __real_gnutls_anon_free_server_credentials(gnutls_anon_server_credentials_t credentials);
void __wrap_gnutls_anon_free_server_credentials(gnutls_anon_server_credentials_t credentials);
void __real_gnutls_dh_params_deinit(gnutls_dh_params_t params);
void __wrap_gnutls_dh_params_deinit(gnutls_dh_params_t params);

int
__wrap_gnutls_bye(gnutls_session_t session __attribute__((unused)),
	gnutls_close_request_t how __attribute__((unused)))
{
	++bye_count;
	fd_open_during_bye = fcntl(watched_fd, F_GETFD) != -1;
	return GNUTLS_E_SUCCESS;
}

void
__wrap_gnutls_deinit(gnutls_session_t session)
{
	++deinit_count;
	__real_gnutls_deinit(session);
}

void
__wrap_gnutls_certificate_free_credentials(gnutls_certificate_credentials_t credentials)
{
	++cert_free_count;
	__real_gnutls_certificate_free_credentials(credentials);
}

void
__wrap_gnutls_anon_free_client_credentials(gnutls_anon_client_credentials_t credentials)
{
	++anon_client_free_count;
	__real_gnutls_anon_free_client_credentials(credentials);
}

void
__wrap_gnutls_anon_free_server_credentials(gnutls_anon_server_credentials_t credentials)
{
	++anon_server_free_count;
	__real_gnutls_anon_free_server_credentials(credentials);
}

void
__wrap_gnutls_dh_params_deinit(gnutls_dh_params_t params)
{
	++dh_free_count;
	__real_gnutls_dh_params_deinit(params);
}

static void
discard_debug(char *const fmt __attribute__((unused)), ...)
{
}

static int
construct_tcp(relpEngine_t *const engine, relpTcp_t **const tcp)
{
	if(relpTcpConstruct(tcp, engine, RELP_CLT_CONN, NULL) != RELP_RET_OK
	   || gnutls_init(&(*tcp)->session, GNUTLS_CLIENT) != GNUTLS_E_SUCCESS) {
		return -1;
	}
	(*tcp)->bEnableTLS = 1;
	return 0;
}

int
main(void)
{
	relpEngine_t *engine = NULL;
	relpTcp_t *tcp = NULL;
	int connection[2] = {-1, -1};
	int rc = EXIT_FAILURE;

	if(relpEngineConstruct(&engine) != RELP_RET_OK
	   || relpEngineSetDbgprint(engine, discard_debug) != RELP_RET_OK
	   || relpEngineSetTLSLibByName(engine, "gnutls") != RELP_RET_OK
	   || construct_tcp(engine, &tcp) != 0
	   || socketpair(AF_UNIX, SOCK_STREAM, 0, connection) != 0) {
		fprintf(stderr, "failed to construct active GnuTLS test objects\n");
		goto done;
	}

	tcp->sock = connection[0];
	connection[0] = -1;
	tcp->bTLSActive = 1;
	watched_fd = tcp->sock;
	if(relpTcpDestruct(&tcp) != RELP_RET_OK) {
		fprintf(stderr, "failed to destruct active GnuTLS session\n");
		goto done;
	}
	if(bye_count != 1 || !fd_open_during_bye || deinit_count != 1) {
		fprintf(stderr, "active session teardown order is incorrect\n");
		goto done;
	}

	watched_fd = -1;
	if(construct_tcp(engine, &tcp) != 0
	   || gnutls_certificate_allocate_credentials(&tcp->xcred) != GNUTLS_E_SUCCESS
	   || gnutls_anon_allocate_client_credentials(&tcp->anoncred) != GNUTLS_E_SUCCESS
	   || gnutls_anon_allocate_server_credentials(&tcp->anoncredSrv) != GNUTLS_E_SUCCESS
	   || gnutls_dh_params_init(&tcp->dh_params) != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "failed to construct partial GnuTLS test objects\n");
		goto done;
	}
	if(relpTcpDestruct(&tcp) != RELP_RET_OK) {
		fprintf(stderr, "failed to destruct partial GnuTLS session\n");
		goto done;
	}
	if(bye_count != 1 || deinit_count != 2 || cert_free_count != 1
	   || anon_client_free_count != 1 || anon_server_free_count != 1 || dh_free_count != 1) {
		fprintf(stderr, "partial GnuTLS resources were not released\n");
		goto done;
	}

	printf("GnuTLS lifecycle ordering and cleanup verified\n");
	rc = EXIT_SUCCESS;

done:
	if(tcp != NULL)
		(void) relpTcpDestruct(&tcp);
	if(engine != NULL)
		(void) relpEngineDestruct(&engine);
	if(connection[0] >= 0)
		(void) close(connection[0]);
	if(connection[1] >= 0)
		(void) close(connection[1]);
	return rc;
}

#else

int
main(void)
{
	return 77;
}

#endif
