#ifndef ZMQ_SYNC_H
#define ZMQ_SYNC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialization and cleanup */
int init_zmq_sync(int is_server, const char *endpoint);
void cleanup_zmq_sync(void);

/* Message broadcasting functions */
void broadcast_sync_message(const char *msg, size_t len);
void broadcast_multipart_message(const char *header, const unsigned char *data, size_t data_size);

/* Client subscription and server pull loops */
int zmq_start_subscription(void (*callback)(const char *msg, size_t len));
int run_zmq_pull_loop(void);
void zmq_sync_send_message(const char *msg, size_t len);

/* New functions for sending/receiving signature messages with strict length header */
int send_signature_message(void *socket, const unsigned char *sig_data, size_t sig_len);
unsigned char *recv_signature_message(void *socket, size_t *out_sig_len);

#ifdef __cplusplus
}
#endif

#endif /* ZMQ_SYNC_H */
