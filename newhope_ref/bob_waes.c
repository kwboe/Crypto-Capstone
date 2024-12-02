#include "api.h"
#include "poly.h"
#include "randombytes.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>

#define AES_KEY_SIZE 32  // appropriate values for an AES-256-GCM scheme
#define AES_GCM_NONCE_SIZE 12
#define AES_GCM_TAG_SIZE 16

void print_hex(const char *label, unsigned char *data, size_t len) { // print out hex values of keys/ciphertext for debugging
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int aes_gcm_encrypt(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, unsigned char *nonce, unsigned char *tag) { // function will take in plaintext, shared secret, and arrays for nonce, ciphertext, and tag to update accordingly
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    // Generate random nonce
    randombytes(nonce, AES_GCM_NONCE_SIZE);

    // Initialize AES-256-GCM encryption and prepare it for encrypting a message
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        perror("Error initializing AES-256-GCM");
        return -1;
    }

    // Set key and nonce
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) {
        perror("Error setting key and nonce");
        return -1;
    }

    // Take in the plaintext and encrypt it with AES-256-GCM with the appropriate key and nonce
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        perror("Error during encryption");
        return -1;
    }
    ciphertext_len = len;

    // Finalize the encryption
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        perror("Error finalizing encryption");
        return -1;
    }
    ciphertext_len += len;

    // Get the tag for authentication
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag)) {
        perror("Error getting GCM tag");
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int main() {
    int sock;
    struct sockaddr_in server_addr;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES]; // Bob's public key
    unsigned char sk[CRYPTO_SECRETKEYBYTES]; // Bob's secret key
    unsigned char key_b[CRYPTO_BYTES]; // Derived shared secret
    unsigned char recv_pk[CRYPTO_PUBLICKEYBYTES]; // Alice's public key
    unsigned char ciphertext[CRYPTO_CIPHERTEXTBYTES]; // Shared secret encrypted with Alice's public key
    unsigned char aes_ciphertext[128]; // array for the AES ciphertext
    unsigned char nonce[AES_GCM_NONCE_SIZE]; // array for nonce
    unsigned char tag[AES_GCM_TAG_SIZE]; // array for tag
    const char *original_message = "maxam:maxam"; // message
    char adjusted_message[128];
    size_t message_len = strlen(original_message);

    // AES seems to work only if the length is even, so if the message is odd, append ~ to make it even
    if (message_len % 2 != 0) {
        snprintf(adjusted_message, sizeof(adjusted_message), "%s~", original_message);
        message_len += 1; // Account for the added character
    } else {
        snprintf(adjusted_message, sizeof(adjusted_message), "%s", original_message);
    }

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(7778);
    server_addr.sin_addr.s_addr = inet_addr("10.233.105.182");

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    // Generate key pair and send/receive public keys/ciphertext
    crypto_kem_keypair(pk, sk);
    send(sock, pk, CRYPTO_PUBLICKEYBYTES, 0);
    recv(sock, recv_pk, CRYPTO_PUBLICKEYBYTES, 0);
    crypto_kem_enc(ciphertext, key_b, recv_pk);
    send(sock, ciphertext, CRYPTO_CIPHERTEXTBYTES, 0);

    print_hex("Shared Secret (AES Key)", key_b, CRYPTO_BYTES);

    // Encrypt the message using AES-256-GCM
    int enc_len = aes_gcm_encrypt(key_b, (unsigned char *)adjusted_message, message_len,
                                  aes_ciphertext, nonce, tag);
    if (enc_len < 0) {
        perror("AES-256-GCM encryption failed");
        close(sock);
        return -1;
    }

    // Send the AES ciphertext, nonce, and tag to Alice
    send(sock, aes_ciphertext, enc_len, 0);
    send(sock, nonce, AES_GCM_NONCE_SIZE, 0);
    send(sock, tag, AES_GCM_TAG_SIZE, 0);

    print_hex("Encrypted Message", aes_ciphertext, enc_len);
    print_hex("Nonce", nonce, AES_GCM_NONCE_SIZE);
    print_hex("Tag", tag, AES_GCM_TAG_SIZE);

    close(sock);
    return 0;
}
