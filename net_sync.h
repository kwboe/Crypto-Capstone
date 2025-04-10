#ifndef NET_SYNC_H
#define NET_SYNC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the networking layer (if needed).
void init_net_sync(void);

// Broadcast a sync message to all connected clients (server only).
void broadcast_sync_message(const char *msg, size_t len);

// Send a sync message to the server (client only).
void send_sync_message(const char *msg, size_t len);

// Run the sync server. This function blocks (or can be run in its own thread).
void *run_sync_server(void *arg);

// Run the sync client. The argument is the server IP address (as a void* to char*).
void *run_sync_client(void *server_ip);

// A function pointer that your application sets to process incoming sync messages.
// For example, your blockchain code sets this to its handle_sync_message() function.
extern void (*handle_sync_message_callback)(const char *msg, size_t len);

#ifdef __cplusplus
}
#endif

#endif // NET_SYNC_H
