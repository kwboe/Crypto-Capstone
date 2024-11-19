#include "api.h"
#include "poly.h"
#include "randombytes.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void print_hex(const char *label, unsigned char *data, size_t len) { // print out hex values of keys/ciphertext for debugging
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES]; // Bob's public key
    unsigned char sk[CRYPTO_SECRETKEYBYTES]; // Bob's secret key
    unsigned char key_b[CRYPTO_BYTES]; // Derived shared secret
    unsigned char recv_pk[CRYPTO_PUBLICKEYBYTES]; // Alice's public key
    unsigned char ciphertext[CRYPTO_CIPHERTEXTBYTES]; // Shared secret encrypted with Alice's public key

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("10.233.105.182");  

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }
    
    // Bob generates his public key with the newhope function crypto_kem_keypair
    crypto_kem_keypair(pk, sk); 
    printf("Bob: Public key generated.\n");
    
    // Sends his public key to Alice
    send(sock, pk, CRYPTO_PUBLICKEYBYTES, 0);
    printf("Bob: Public key sent to Alice.\n");
    print_hex("Bob's Public key", pk, CRYPTO_PUBLICKEYBYTES);

    // Receive Alice's public key from Alice
    recv(sock, recv_pk, CRYPTO_PUBLICKEYBYTES, 0);
    printf("Bob: Received Alice's public key.\n");
    print_hex("Alice's Public key", recv_pk, CRYPTO_PUBLICKEYBYTES);

    // Derives random shared secret and encrypts it with Alice's public key
    crypto_kem_enc(ciphertext, key_b, recv_pk);
    printf("Bob: Shared secret derived and encrypted with Alice's public key.\n");

    // Sends the shared secret to Alice
    send(sock, ciphertext, CRYPTO_CIPHERTEXTBYTES, 0);
    printf("Bob: Ciphertext sent to Alice.\n");
    print_hex("Ciphertext", ciphertext, CRYPTO_CIPHERTEXTBYTES);
    print_hex("Bob's Shared Secret", key_b, CRYPTO_BYTES);

    // Closes socket
    close(sock);
    return 0;
} 
