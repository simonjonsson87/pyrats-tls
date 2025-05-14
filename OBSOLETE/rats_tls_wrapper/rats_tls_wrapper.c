// rats_tls_wrapper.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rats-tls/api.h>

typedef struct {
    rats_tls_conf_t conf;
    rats_tls_handle_t handle;
} rats_tls_connection_t;

// Start server, return connection handle
int start_rats_tls_server(
    const char* ip,
    const char* port,
    int mutual_attestation,
    const char* custom_token,
    const char* policy_file,
    char** attestation_token,
    rats_tls_connection_t** connection
) {
    rats_tls_conf_t conf;
    rats_tls_handle_t handle;
    int ret;

    *attestation_token = NULL;
    *connection = NULL;
    memset(&conf, 0, sizeof(conf));
    memset(&handle, 0, sizeof(handle));

    if (ip) {
        conf.tls_server_conf.ip = strdup(ip);
    }
    if (port) {
        conf.tls_server_conf.port = strdup(port);
    }
    conf.tls_server_conf.is_server = true;
    conf.tls_server_conf.mutual_attestation = mutual_attestation;

    // Handle policy file (unverified)
    if (policy_file && strlen(policy_file) > 0) {
        // ret = rats_tls_load_policy_file(&conf, policy_file);
        fprintf(stderr, "Warning: Policy file support is unverified. Check rats-tls/api.h for policy file loading.\n");
    }

    ret = rats_tls_init(&conf, &handle);
    if (ret != 0) {
        fprintf(stderr, "rats_tls_init failed: %d\n", ret);
        goto cleanup;
    }

    // Set custom attestation token if provided
    if (custom_token && strlen(custom_token) > 0) {
        fprintf(stderr, "Warning: Custom attestation token provided, but RATS-TLS API support is unverified\n");
    }

    // Perform TLS handshake
    ret = rats_tls_negotiate(&conf, &handle);
    if (ret != 0) {
        fprintf(stderr, "rats_tls_negotiate failed: %d\n", ret);
        goto cleanup;
    }

    if (mutual_attestation) {
        // Retrieve client's attestation token
        ret = rats_tls_get_attestation_token(&handle, attestation_token);
        if (ret != 0 || *attestation_token == NULL) {
            fprintf(stderr, "Failed to get client attestation token: %d, checking verification result\n", ret);
            int verified = 0;
            ret = rats_tls_get_verification_result(&handle, &verified);
            if (ret == 0 && verified) {
                *attestation_token = strdup("verified");
            } else {
                fprintf(stderr, "Client attestation verification failed: %d\n", ret);
                ret = -1;
                goto cleanup;
            }
        }
    } else {
        int verified = 1;
        ret = rats_tls_get_verification_result(&handle, &verified);
        if (ret == 0 && verified) {
            *attestation_token = strdup("verified");
        } else {
            fprintf(stderr, "Server attestation verification failed: %d\n", ret);
            ret = -1;
            goto cleanup;
        }
    }

    // Store connection handle
    *connection = malloc(sizeof(rats_tls_connection_t));
    if (!*connection) {
        fprintf(stderr, "Failed to allocate connection handle\n");
        ret = -1;
        goto cleanup;
    }
    (*connection)->conf = conf;
    (*connection)->handle = handle;
    return 0;

cleanup:
    rats_tls_cleanup(&conf, &handle);
    if (conf.tls_server_conf.ip) free((char*)conf.tls_server_conf.ip);
    if (conf.tls_server_conf.port) free((char*)conf.tls_server_conf.port);
    return ret;
}

// Connect client, return connection handle
int connect_rats_tls_client(
    const char* ip,
    const char* port,
    int mutual_attestation,
    char** server_attestation_token,
    rats_tls_connection_t** connection
) {
    rats_tls_conf_t conf;
    rats_tls_handle_t handle;
    int ret;

    *server_attestation_token = NULL;
    *connection = NULL;
    memset(&conf, 0, sizeof(conf));
    memset(&handle, 0, sizeof(handle));

    if (ip) {
        conf.tls_client_conf.ip = strdup(ip);
    }
    if (port) {
        conf.tls_client_conf.port = strdup(port);
    }
    conf.tls_client_conf.is_server = false;
    conf.tls_client_conf.mutual_attestation = mutual_attestation;

    ret = rats_tls_init(&conf, &handle);
    if (ret != 0) {
        fprintf(stderr, "rats_tls_init failed: %d\n", ret);
        goto cleanup;
    }

    ret = rats_tls_negotiate(&conf, &handle);
    if (ret != 0) {
        fprintf(stderr, "rats_tls_negotiate failed: %d\n", ret);
        goto cleanup;
    }

    ret = rats_tls_get_attestation_token(&handle, server_attestation_token);
    if (ret != 0 || *server_attestation_token == NULL) {
        fprintf(stderr, "Failed to get server attestation token: %d, checking verification result\n", ret);
        int verified = 0;
        ret = rats_tls_get_verification_result(&handle, &verified);
        if (ret == 0 && verified) {
            *server_attestation_token = strdup("verified");
        } else {
            fprintf(stderr, "Server attestation verification failed: %d\n", ret);
            ret = -1;
            goto cleanup;
        }
    }

    *connection = malloc(sizeof(rats_tls_connection_t));
    if (!*connection) {
        fprintf(stderr, "Failed to allocate connection handle\n");
        ret = -1;
        goto cleanup;
    }
    (*connection)->conf = conf;
    (*connection)->handle = handle;
    return 0;

cleanup:
    rats_tls_cleanup(&conf, &handle);
    if (conf.tls_client_conf.ip) free((char*)conf.tls_client_conf.ip);
    if (conf.tls_client_conf.port) free((char*)conf.tls_client_conf.port);
    return ret;
}

// Send message over connection
int send_message(rats_tls_connection_t* connection, const char* message, size_t message_len) {
    if (!connection || !message) {
        fprintf(stderr, "Invalid connection or message\n");
        return -1;
    }
    size_t sent_len = message_len;
    int ret = rats_tls_transmit(&connection->handle, (void*)message, &sent_len);
    if (ret != 0 || sent_len != message_len) {
        fprintf(stderr, "rats_tls_transmit failed: %d, sent %zu of %zu bytes\n", ret, sent_len, message_len);
        return -1;
    }
    return 0;
}

// Receive message over connection
int receive_message(rats_tls_connection_t* connection, char** message, size_t* message_len) {
    if (!connection || !message || !message_len) {
        fprintf(stderr, "Invalid connection or output parameters\n");
        return -1;
    }
    char buffer[1024];
    size_t received_len = sizeof(buffer);
    int ret = rats_tls_receive(&connection->handle, buffer, &received_len);
    if (ret != 0) {
        fprintf(stderr, "rats_tls_receive failed: %d\n", ret);
        return -1;
    }
    *message = malloc(received_len + 1);
    if (!*message) {
        fprintf(stderr, "Failed to allocate message buffer\n");
        return -1;
    }
    memcpy(*message, buffer, received_len);
    (*message)[received_len] = '\0';
    *message_len = received_len;
    return 0;
}

// Close connection
int close_connection(rats_tls_connection_t* connection) {
    if (!connection) {
        return -1;
    }
    rats_tls_cleanup(&connection->conf, &connection->handle);
    if (connection->conf.tls_server_conf.ip) free((char*)connection->conf.tls_server_conf.ip);
    if (connection->conf.tls_server_conf.port) free((char*)connection->conf.tls_server_conf.port);
    free(connection);
    return 0;
}

int verify_attestation_token(const char* token) {
    if (strcmp(token, "verified") == 0) {
        return 0;
    }
    int ret = rats_tls_verify_attestation_token(token);
    if (ret != 0) {
        fprintf(stderr, "Attestation token verification failed: %d\n", ret);
    }
    return ret;
}