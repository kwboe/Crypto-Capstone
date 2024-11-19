#include "api.h"
#include "poly.h"
#include "randombytes.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define PORT 7778

void print_hex(const char *label, unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char key_a[CRYPTO_BYTES];
    unsigned char recv_ct[CRYPTO_CIPHERTEXTBYTES];

    // Alice generates her public and secret keys
    crypto_kem_keypair(pk, sk);
    printf("Alice: Public key generated.\n");

    // Create socket
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Socket bind failed");
        return -1;
    }

    // Listen for connection
    listen(server_sock, 1);
    printf("Alice: Waiting for Bob to connect...\n");

    // Accept connection
    if ((client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len)) < 0) {
        perror("Connection accept failed");
        return -1;
    }

    // Receive Bob's public key
    unsigned char bob_pk[CRYPTO_PUBLICKEYBYTES];
    recv(client_sock, bob_pk, CRYPTO_PUBLICKEYBYTES, 0);
    printf("Alice: Received Bob's public key.\n");

    // Send Alice's public key to Bob
    send(client_sock, pk, CRYPTO_PUBLICKEYBYTES, 0);
    printf("Alice: Public key sent to Bob.\n");

    // Receive ciphertext from Bob
    recv(client_sock, recv_ct, CRYPTO_CIPHERTEXTBYTES, 0);
    printf("Alice: Ciphertext received from Bob.\n");

    // Derive shared secret using ciphertext and Alice's private key
    crypto_kem_dec(key_a, recv_ct, sk);
    printf("Alice: Shared secret derived.\n");

    // Print Alice's shared secret
    print_hex("Alice's Shared Secret", key_a, CRYPTO_BYTES);

    // Clean up
    close(client_sock);
    close(server_sock);
    return 0;
}

