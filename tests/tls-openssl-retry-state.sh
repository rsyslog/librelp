#!/bin/bash
# Verify that OpenSSL WANT_READ send retries use read readiness and are cleared
# once the TLS handshake completes and the write is retried successfully.

exec ./tls-openssl-retry-state
