/*
 * net_sync.c
 *
 * This file implements framed messaging and network sync functions to be used
 * by kingkoinfinalv1.c. It no longer defines main().
 *
 * To compile:
 *   gcc -Wall -Wextra -O2 -c net_sync.c
 * Then link with your kingkoinfinalv1.o.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "net_sync.h"  // Make sure this header now declares the functions as below
#include "ccakem.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Forward declaration for a function defined elsewhere (in kingkoinfinalv1.c) */
extern void handle_sync_message(const char *msg, size_t len);

#define PORT 9000
#define MAX_CLIENTS 10
#define MAX_USERNAME_LENGTH 100

/* --- Framing functions --- */

// Sends a message with a 4-byte length prefix.
int send_framed_message(int sock, const void *data, size_t len) {
    uint32_t net_len = htonl((uint32_t)len);

    // Send length
    if (send(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) {
        perror("send length");
        return -1;
    }

    // Send actual data
    if (send(sock, data, len, 0) != (ssize_t)len) {
        perror("send data");
        return -1;
    }

    return 0;
}


// Receives a message that was framed with a 4-byte length.
void *receive_framed_message(int sock) {
    uint32_t net_len;
    ssize_t total = 0;

    // Read the 4-byte length header
    ssize_t r = recv(sock, &net_len, sizeof(net_len), MSG_WAITALL);
    if (r <= 0) return NULL;

    uint32_t len = ntohl(net_len);
    void *buffer = malloc(len);
    if (!buffer) return NULL;

    while (total < len) {
        r = recv(sock, (char *)buffer + total, len - total, 0);
        if (r <= 0) {
            free(buffer);
            return NULL;
        }
        total += r;
    }

    return buffer;  
}


/* --- Global Client Storage --- */

// For server mode, we use an array for connected client sockets.
static int client_socket[MAX_CLIENTS] = {0};

// For client mode, store the connected socket here.
static int global_client_sock = -1;

/* --- Helper Functions --- */

// Minimal final block processor.
static void process_final_block(const char *msg) {
    printf("FINAL BLOCK RECEIVED:\n%s\n", msg);
    /* In a complete implementation, update the blockchain here */
}

/* --- Networking Functions --- */

/* Server function: Accept connections and process incoming messages. */
void run_server(void *arg) {
    (void)arg;  // Unused

    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Sync server listening on port %d\n", PORT);

    EVP_CIPHER_CTX *client_aes_ctx[MAX_CLIENTS] = {0};

    fd_set readfds;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        int max_sd = server_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_socket[i];
            if (sd > 0)
                FD_SET(sd, &readfds);
            if (sd > max_sd)
                max_sd = sd;
        }

        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if ((activity < 0) && (errno != EINTR)) {
            perror("select error");
        }

        // Handle new connection
        if (FD_ISSET(server_fd, &readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            printf("New client connected from %s:%d\n",
                   inet_ntoa(address.sin_addr), ntohs(address.sin_port));

            // NewHope
            unsigned char pk[CRYPTO_PUBLICKEYBYTES];
            unsigned char sk[CRYPTO_SECRETKEYBYTES];
            crypto_kem_keypair(pk, sk);

            if (send_framed_message(new_socket, pk, CRYPTO_PUBLICKEYBYTES) < 0) {
                printf("Failed to send public key\n");
                close(new_socket);
                continue;
            }

            unsigned char *ct = receive_framed_message(new_socket);
            if (!ct) {
                printf("Client disconnected during key exchange\n");
                close(new_socket);
                continue;
            }

            unsigned char ss[CRYPTO_BYTES];
            crypto_kem_dec(ss, ct, sk);
            free(ct);

            unsigned char aes_key[32];
            unsigned char aes_iv[16] = {0};
            memcpy(aes_key, ss, 32);

            EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_ctr(), NULL, aes_key, aes_iv);
            EVP_CIPHER_CTX_set_padding(aes_ctx, 0);

            // Store the new client socket and AES context
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    client_aes_ctx[i] = aes_ctx;
                    break;
                }
            }
        }

        // Handle messages from existing clients
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = client_socket[i];
            if (sd > 0 && FD_ISSET(sd, &readfds)) {
                unsigned char *cipher_msg = receive_framed_message(sd);
                if (!cipher_msg) {
                    printf("Client disconnected (fd %d)\n", sd);
                    close(sd);
                    client_socket[i] = 0;
                    EVP_CIPHER_CTX_free(client_aes_ctx[i]);
                    client_aes_ctx[i] = NULL;
                    continue;
                }

                unsigned char decrypted[4096];
                int out_len;
                EVP_DecryptInit_ex(client_aes_ctx[i], EVP_aes_256_ctr(), NULL, NULL, NULL);
                EVP_DecryptUpdate(client_aes_ctx[i], decrypted, &out_len, cipher_msg, strlen((char *)cipher_msg));
                decrypted[out_len] = '\0';
                free(cipher_msg);

                // Pass to sync handler
                handle_sync_message((char *)decrypted, out_len);
            }
        }
    }
}



/* Client function: Connects to the sync server and handles incoming messages. */
void run_client(void *server_ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;

    if (sock < 0) {
        perror("Socket creation error");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, (char *)server_ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        return;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return;
    }

    printf("Connected to server %s:%d\n", (char *)server_ip, PORT);
    global_client_sock = sock;

    // NewHope
    unsigned char *pk = receive_framed_message(sock);  
    if (!pk) { printf("Failed to receive server key\n"); return; }

    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss[CRYPTO_BYTES];
    crypto_kem_enc(ct, ss, pk);
    free(pk);

    send_framed_message(sock, ct, CRYPTO_CIPHERTEXTBYTES);  

   
    unsigned char aes_key[32]; 
    unsigned char aes_iv[16] = {0};  

    memcpy(aes_key, ss, 32);  

    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_ctr(), NULL, aes_key, aes_iv);

    while (1) {
        unsigned char *cipher_msg = receive_framed_message(sock);
        if (!cipher_msg) {
            printf("Server disconnected.\n");
            break;
        }

        size_t msg_len = 0;
        EVP_CIPHER_CTX_set_padding(aes_ctx, 0);
        unsigned char decrypted[4096]; 
        int out_len;

        EVP_DecryptUpdate(aes_ctx, decrypted, &out_len, cipher_msg, strlen((char *)cipher_msg));
        decrypted[out_len] = '\0';
        free(cipher_msg);

        if (strncmp((char *)decrypted, "VALIDATORS_SELECTED:", 20) == 0 ||
            strncmp((char *)decrypted, "FINAL_BLOCK:", 12) == 0) {
            handle_sync_message((char *)decrypted, out_len);
        }
    }

    EVP_CIPHER_CTX_free(aes_ctx);
    close(sock);
}



/* --- Sync Messaging API Functions --- */

// Initialization function.
void init_net_sync(void) {
    /* No initialization needed in this simple version */
}

// In server mode: Broadcast a message to all connected clients.
// We do not use 'len', so we cast it to void.
void broadcast_sync_message(const char *msg, size_t len) {
    (void)len;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_socket[i] > 0) {
            send_framed_message(client_socket[i], (unsigned char *)msg, strlen(msg));
        }
    }
}

// In client mode: Send a message to the server.
void send_sync_message(const char *msg, size_t len) {
    (void)len;
    if (global_client_sock != -1) {
        send_framed_message(global_client_sock, (unsigned char *)msg, strlen(msg));
    }
}

/* --- Thread Functions for Sync --- */

// These now have the proper pthread signature.
void *run_sync_server(void *arg) {
    run_server(arg);
    return NULL;
}

void *run_sync_client(void *arg) {
    run_client(arg);
    return NULL;
}
