
/******************************************************************************
 * kingkoinfinal.c
 *
 * Kingkoin – a blockchain with network‐synchronized block creation and manual
 * validator signing. Blockusers are loaded from the Linux “blockusers” group.
 * All keys are kept in a centralized directory (GLOBAL_KEYS_DIR) on the server.
 *
 * Compile with:
 *   gcc -Wall -Wextra -O2 -o combined2 combined.c net_sync.c client_sync.c -L/home/torin/libsodium/lib -lsodium -L/home/torin/Crypto-Capstone/newhope_ref/ -lnewhope -lpam -lpam_misc -lcrypto -lcrypt -loqs -lpthread

 *
 * Note: net_sync.c must supply functions such as:
 *   run_sync_server, run_sync_client, send_sync_message, broadcast_sync_message,
 *   init_net_sync – and it must call handle_sync_message() for incoming messages.
 *****************************************************************************/

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>       // getpass(), access(), etc.
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <security/pam_appl.h>
#include <oqs/oqs.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <shadow.h>
#include <sys/socket.h>
#include "api.h"
#include "poly.h"
#include "randombytes.h"
#include "net_sync.h"   // our network sync functions
#include <oqs/oqs.h>

/* --- Configuration Macros --- */
#define PASSWD_FILE "/etc/passwd"
#define SHADOW_FILE "/etc/shadow"
#define TEMP_PASSWD "/etc/passwd.new"
#define TEMP_SHADOW "/etc/shadow.new"

#define DEFAULT_SERVER_IP "10.233.105.163"
#define MAX_USERNAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 100
#define MAX_RECIPIENT_LENGTH 100
#define BLOCKS_DIR "blocks"
#define TRANSACTION_LOG_FILE "transaction_log.txt"
#define MAX_TRANSACTIONS_PER_BLOCK 5
#define MAX_VALIDATORS_PER_BLOCK 3
#define SLASH_PENALTY 5.0
#define SERVER_PORT 10010
#define SERVER_ADDR "10.233.105.163"
#define AES_KEY_SIZE 32 
#define AES_BLOCK_SIZE 16 
#define AUTH_PORT 10010
#define REG_PORT 8080
#define BUFFER_SIZE 256
/* --- Global Keys Directory Fallback --- */
#ifndef GLOBAL_KEYS_DIR
#define GLOBAL_KEYS_DIR "./keys"
#endif

/* --- Global Variables --- */
char current_user[MAX_USERNAME_LENGTH] = "";
char current_role[20] = "";
int is_server = 0;  // Set via command-line argument
pthread_mutex_t finalization_mutex = PTHREAD_MUTEX_INITIALIZER;
char vrf_nonce[64] = "";  // Used for VRF computation


const char *essential_users[] = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats",
    "nobody", "systemd-network", "systemd-resolve", "systemd-timesync", "syslog",
    "_apt", "tss", "messagebus", "usbmux", "dnsmasq", "avahi", "speech-dispatcher",
    "fwupd-refresh", "saned", "geoclue", "polkitd", "rtkit", "colord", "gnome-initial-setup",
    "Debian-gdm", NULL
};



int should_keep_user(const char *user, const char *current_user) {
    for (int i = 0; essential_users[i] != NULL; i++) {
        if (strcmp(user, essential_users[i]) == 0) {
            return 1;
        }
    }
    return strcmp(user, current_user) == 0;
}


void filter_file(const char *input_file, const char *output_file, const char *current_user) {
    FILE *input = fopen(input_file, "r");
    FILE *output = fopen(output_file, "w");
    if (!input || !output) {
        perror("Error opening files");
        exit(1);
    }

    char line[1024], user[128];
    while (fgets(line, sizeof(line), input)) {
        sscanf(line, "%127[^:]", user);
        if (should_keep_user(user, current_user)) {
            fputs(line, output);
        }
    }

    fclose(input);
    fclose(output);
}

void cleanup_users() {
    char *current_user = getlogin();
    if (!current_user) {
        perror("Error getting current user");
        exit(1);
    }

    printf("WARNING: This will delete all non-essential user accounts\n");
    printf("Only system accounts and the current user will be preserved.\n");
    printf("Type 'yes' to proceed: ");
    
    char confirmation[4];
    fgets(confirmation, sizeof(confirmation), stdin);
    confirmation[strcspn(confirmation, "\n")] = 0;
    
    if (strcmp(confirmation, "yes") != 0) {
        printf("Operation cancelled. No changes were made.\n");
        exit(0);
    }

    system("cp /etc/passwd /etc/passwd.bak");
    system("cp /etc/shadow /etc/shadow.bak");
    
    filter_file(PASSWD_FILE, TEMP_PASSWD, current_user);
    filter_file(SHADOW_FILE, TEMP_SHADOW, current_user);
    
    rename(TEMP_PASSWD, PASSWD_FILE);
    rename(TEMP_SHADOW, SHADOW_FILE);
    
    printf("All non-essential users removed. Only %s and system accounts remain.\n", current_user);
}

/* --- Data Structures --- */
typedef enum {
    TRANSACTION_NORMAL
} TransactionType;

typedef struct Transaction {
    int id;
    TransactionType type;
    char sender[MAX_USERNAME_LENGTH];
    char recipient[MAX_RECIPIENT_LENGTH];
    double amount;
    time_t timestamp;
    struct Transaction *next;
} Transaction;

/* Force the Block structure to be packed consistently */
#pragma pack(push, 1)
typedef struct Block {
    int index;
    time_t timestamp;
    Transaction transactions[MAX_TRANSACTIONS_PER_BLOCK];
    int transaction_count;
    unsigned char previous_hash[64];
    unsigned char hash[64];
    unsigned int hash_len;
    int validator_count;
    char validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
    unsigned char signatures[MAX_VALIDATORS_PER_BLOCK][5000];
    size_t signature_lens[MAX_VALIDATORS_PER_BLOCK];
    /* The following pointer is used only for in‐memory chaining and is not serialized */
    struct Block *next;
} Block;
#pragma pack(pop)

typedef struct User {
    char username[MAX_USERNAME_LENGTH];
    double balance;
    double stake;
    unsigned char public_key[5000];
    size_t public_key_len;
    struct User *next;
} User;

/* --- Global Pointers --- */
Block *blockchain = NULL;
Transaction *pending_transactions = NULL;
User *users = NULL;
int last_transaction_id = 0;
Block *pending_block = NULL;
static volatile int broadcast_done = 0;

/* --- Function Prototypes --- */
int ensure_blocks_directory(void);
int is_user_in_group(const char *username, const char *groupname);
int is_user_in_blockusers_group(const char *username);
void load_blockusers_into_users(void);
void add_user_if_not_exists(const char *username);
void generate_keys_for_user(const char *username);
void generate_global_keys_for_user(const char *username);
void load_user_public_key(User *user);
User* find_user(const char *username);
void compute_block_hash(Block *block);
void create_genesis_block(void);
void load_blockchain(void);
void load_validator_public_keys(Block *block);
void display_blockchain(void);
void print_hash(unsigned char *hash, unsigned int hash_len);
void print_block_signature(Block *block);
void display_dilithium2_signature_for_block(int block_index);
void add_block_to_blockchain(Block *new_block);
void create_new_block(void);
void finalize_block(void);
double compute_vrf(const char *username, int round);
void select_validators(char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH], int *validator_count);
void sign_block(Block *block, const char *validator_username);
int verify_block_signatures(Block *block);
void sign_pending_block(const char *validator_username);
void save_pending_block(void);
void load_pending_block(void);
void add_transaction(Transaction *newtx);
void send_transaction(void);
void view_transactions(void);
void view_all_transactions(void);
void view_pending_transactions(void);
void cancel_pending_transaction(void);
void update_user_balance(const char *username, double amount);
double get_user_balance(const char *username);
void request_test_funds(void);
void slash_user_stake(const char *username, double penalty);
void log_event(const char *event_description);
int pam_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);
void user_login(void);
void user_logout(void);
void stake_tokens(const char *username, double amount);
void unstake_tokens(const char *username, double amount);
void interactive_menu(void);
void *server_monitor(void *arg);
void send_user_list(void);
void handle_sync_message(const char *msg, size_t len);
void cleanup_and_exit(int signum);

/* --- Function Implementations --- */
void print_hex(const char *label, unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
/* User and Key Management Functions */
int ensure_blocks_directory(void) {
    struct stat st;
    if (stat(BLOCKS_DIR, &st) == -1) {
        if (mkdir(BLOCKS_DIR, 0700) != 0) {
            perror("mkdir");
            return -1;
        }
    }
    return 0;
}

int key_agree(unsigned char *pk, unsigned char *sk, unsigned char *servpk, 
                         unsigned char *ct, unsigned char *shared_secret) {
    crypto_kem_keypair(pk, sk);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    printf("Creating socket\n");
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return -1;
    }

    send(sockfd, pk, CRYPTO_PUBLICKEYBYTES, 0);
    print_hex("Our pk", pk, CRYPTO_PUBLICKEYBYTES); 

    // Receive public key from server
    recv(sockfd, servpk, CRYPTO_PUBLICKEYBYTES, 0);
    print_hex("Their pk", servpk, CRYPTO_PUBLICKEYBYTES);

    // Generate ciphertext and shared secret
    crypto_kem_enc(ct, shared_secret, servpk);
    print_hex("Client ciphertext", ct, CRYPTO_CIPHERTEXTBYTES);
    send(sockfd, ct, CRYPTO_CIPHERTEXTBYTES, 0);
    print_hex("AES key", shared_secret, CRYPTO_BYTES);

    return sockfd;  // Return the socket descriptor so it can be used later
}

int is_user_in_group(const char *username, const char *groupname) {
    struct group *grp = getgrnam(groupname);
    if (!grp) return 0;
    struct passwd *pwd = getpwnam(username);
    if (pwd && pwd->pw_gid == grp->gr_gid)
        return 1;
    char **members = grp->gr_mem;
    while (*members) {
        if (strcmp(*members, username) == 0)
            return 1;
        members++;
    }
    return 0;
}

int is_user_in_blockusers_group(const char *username) {
    return is_user_in_group(username, "blockusers");
}

void load_blockusers_into_users(void) {
    printf("load_blockusers_into_users: scanning system...\n");
    struct passwd *pwd;
    setpwent();
    while ((pwd = getpwent()) != NULL) {
        if (is_user_in_blockusers_group(pwd->pw_name))
            add_user_if_not_exists(pwd->pw_name);
    }
    endpwent();
}

void add_user_if_not_exists(const char *username) {
    User *u = users;
    while (u) {
        if (strcmp(u->username, username) == 0)
            return;
        u = u->next;
    }
    User *newu = malloc(sizeof(User));
    if (!newu) { perror("malloc"); exit(1); }
    strncpy(newu->username, username, MAX_USERNAME_LENGTH - 1);
    newu->username[MAX_USERNAME_LENGTH - 1] = '\0';
    newu->balance = 0.0;
    newu->stake = 0.0;
    newu->public_key_len = 0;
    newu->next = users;
    users = newu;
    load_user_public_key(newu);
}

int aes_ctr_encrypt(const unsigned char *key, const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (!ctx) {
        perror("Error creating cipher context");
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) {
        perror("Error initializing AES-CTR encryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        perror("Error during AES-CTR encryption");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_ctr_decrypt(const unsigned char *key, const unsigned char *ciphertext, size_t ciphertext_len,
                    unsigned char *plaintext, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, plaintext_len = 0;

    if (!ctx) return -1;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) return -1;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


void *registration_server(void *arg) {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(REG_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);
    printf("Registration server running on port %d\n", REG_PORT);

    while (1) {
        client_len = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) continue;

        unsigned char sk[CRYPTO_SECRETKEYBYTES], pk[CRYPTO_PUBLICKEYBYTES], ct[CRYPTO_CIPHERTEXTBYTES], shared_secret[CRYPTO_BYTES];
        unsigned char iv[AES_BLOCK_SIZE], ciphertext[256], plaintext[128];

        crypto_kem_keypair(pk, sk);
        recv(client_sock, pk, CRYPTO_PUBLICKEYBYTES, 0);
        crypto_kem_enc(ct, shared_secret, pk);
        send(client_sock, ct, CRYPTO_CIPHERTEXTBYTES, 0);
        recv(client_sock, iv, AES_BLOCK_SIZE, 0);
        int ciphertext_len = recv(client_sock, ciphertext, sizeof(ciphertext), 0);

        int plaintext_len = aes_ctr_decrypt(shared_secret, ciphertext, ciphertext_len, plaintext, iv);
        plaintext[plaintext_len] = '\0';
        printf("Decrypted: %s\n", plaintext);

        char username[100], password[100];
        sscanf((char *)plaintext, "%99[^:]:%99s", username, password);

        char salt[17];
        snprintf(salt, sizeof(salt), "$6$%.8s$", username);
        char *hashedPassword = crypt(password, salt);

        char shadowEntry[512], passwdEntry[512];
        snprintf(shadowEntry, sizeof(shadowEntry), "%s:%s::0:99999:7:::\n", username, hashedPassword);
        snprintf(passwdEntry, sizeof(passwdEntry), "%s:x:1001:1001::/home/%s:/bin/bash\n", username, username);

        int shadowfile = open("/etc/shadow", O_WRONLY | O_APPEND);
        write(shadowfile, shadowEntry, strlen(shadowEntry));
        close(shadowfile);

        int passwdfile = open("/etc/passwd", O_WRONLY | O_APPEND);
        write(passwdfile, passwdEntry, strlen(passwdEntry));
        close(passwdfile);

        close(client_sock);
    }
    close(server_sock);
    return NULL;
}

char* process_decrypted_data(const char *data) {
    char *separator = strchr(data, ':');
    if (!separator) {
        fprintf(stderr, "Separator ':' not found in the data\n");
        return NULL;
    }
    size_t username = separator - data;
    static char user_entry[1024];
    strncpy(user_entry, data, username);
    user_entry[username] = '\0';
    return user_entry;
}


void *authentication_server(void *arg) {
    int receive_sock, new_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char key_a[CRYPTO_BYTES];
    unsigned char recv_ct[CRYPTO_CIPHERTEXTBYTES];

    unsigned char aes_ciphertext[BUFFER_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char user_iv[AES_BLOCK_SIZE];
    unsigned char pass_iv[AES_BLOCK_SIZE];
    unsigned char plaintext[BUFFER_SIZE];
    char send_user[2048] = "";
    char send_pass[2048] = "";
    unsigned char received[10] = "received";


    // Generate key pair
    crypto_kem_keypair(pk, sk);
    printf("Server: Public key generated.\n");

    receive_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (receive_sock < 0) {
        perror("Couldn't make socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(10010);
    int opt = 1;
    setsockopt(receive_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(receive_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

        listen(receive_sock, 5);
    printf("Authentication server running on port %d...\n", 10010);
    
        addr_size = sizeof(client_addr);
        new_sock = accept(receive_sock, (struct sockaddr *)&client_addr, &addr_size);
        if (new_sock < 0) {
            perror("Accept failed");
  
        }

        // Receive client public key
        unsigned char client_pk[CRYPTO_PUBLICKEYBYTES];
        recv(new_sock, client_pk, CRYPTO_PUBLICKEYBYTES, 0);
        print_hex("Client pub key", client_pk, CRYPTO_PUBLICKEYBYTES);

        // Send server public key
        send(new_sock, pk, CRYPTO_PUBLICKEYBYTES, 0);
        print_hex("Server pub key", pk, CRYPTO_PUBLICKEYBYTES);

        // Receive ciphertext
        recv(new_sock, recv_ct, CRYPTO_CIPHERTEXTBYTES, 0);
        print_hex("Ciphertext", recv_ct, CRYPTO_CIPHERTEXTBYTES);

        // Derive shared secret
        crypto_kem_dec(key_a, recv_ct, sk);
        print_hex("Derived AES Key", key_a, CRYPTO_BYTES);

        ssize_t received_bytes = 0;
	printf("Receiving ciphertext");
	int net_ciphertext_len = 0;
recv(new_sock, &net_ciphertext_len, sizeof(net_ciphertext_len), 0);
int ciphertext_len = ntohl(net_ciphertext_len);
        received_bytes = recv(new_sock, aes_ciphertext, ciphertext_len, 0); 

printf("Ciphertext received");


recv(new_sock, iv, AES_BLOCK_SIZE, 0);


	print_hex("AES ciphertext", aes_ciphertext, sizeof(aes_ciphertext));

        // Decrypt message
        int plaintext_len = aes_ctr_decrypt(key_a, aes_ciphertext, sizeof(aes_ciphertext), plaintext, iv);
        plaintext[plaintext_len] = '\0';
        printf("Decrypted message: %s\n", plaintext);

        // Extract username from decrypted data
        char *user_entry = process_decrypted_data((char *)plaintext);

        struct passwd *pw = getpwnam(user_entry);
        struct spwd *sp = getspnam(user_entry);
if (!sp) {
    fprintf(stderr, "Error: Shadow entry not found for user %s\n", user_entry);
    snprintf(send_pass, sizeof(send_pass), "ERROR: No shadow entry found");
} else {
    printf("Shadow entry found for user: %s\n", sp->sp_namp);
}
        if (pw && sp) {
            snprintf(send_user, sizeof(send_user), "%s:%s:%d:%d:%s:%s:%s", pw->pw_name, pw->pw_passwd, pw->pw_uid, pw->pw_gid, pw->pw_gecos, pw->pw_dir, pw->pw_shell);
            snprintf(send_pass, sizeof(send_pass), "%s:%s:%d:%d:%d:%d:::", sp->sp_namp, sp->sp_pwdp, sp->sp_lstchg, sp->sp_min, sp->sp_max, sp->sp_warn);
        }
	char send_user_encrypted[2048];
	char send_pass_encrypted[2048];
	randombytes(user_iv, AES_BLOCK_SIZE);
	randombytes(pass_iv, AES_BLOCK_SIZE);
	int user_len = aes_ctr_encrypt(key_a, send_user, sizeof(send_user), send_user_encrypted, user_iv);
	int pass_len = aes_ctr_encrypt(key_a, send_pass, sizeof(send_pass), send_pass_encrypted, pass_iv);
        send(new_sock, send_user_encrypted, sizeof(send_user_encrypted), 0);
        send(new_sock, user_iv, AES_BLOCK_SIZE, 0);
        send(new_sock, send_pass_encrypted, sizeof(send_pass_encrypted), 0);
	send(new_sock, pass_iv, AES_BLOCK_SIZE, 0); 

        close(new_sock);
        
        sleep(2);
        shutdown(receive_sock, SHUT_RDWR);
        close(receive_sock);
}

void generate_keys_for_user(const char *username) {
    char keys_dir[512];
    snprintf(keys_dir, sizeof(keys_dir), "%s", GLOBAL_KEYS_DIR);
    struct stat st;
    if (stat(keys_dir, &st) == -1) {
        if (mkdir(keys_dir, 0700) != 0) {
            printf("Failed to create keys_dir '%s'.\n", keys_dir);
            exit(1);
        }
    }
    char privkey[256], pubkey[256];
    snprintf(privkey, sizeof(privkey), "%s/%s_private.key", keys_dir, username);
    snprintf(pubkey, sizeof(pubkey), "%s/%s_public.key", keys_dir, username);
    if (access(privkey, F_OK) != -1 && access(pubkey, F_OK) != -1) {
        printf("Keys already exist for '%s'.\n", username);
        return;
    }
    OQS_SIG *sig = OQS_SIG_new("Dilithium2");
    if (!sig) { printf("Dilithium2 init fail.\n"); exit(1); }
    unsigned char *pub = malloc(sig->length_public_key);
    unsigned char *priv = malloc(sig->length_secret_key);
    if (!pub || !priv) { perror("malloc"); exit(1); }
    if (OQS_SIG_keypair(sig, pub, priv) != OQS_SUCCESS) {
        printf("Failed keypair for '%s'.\n", username);
        exit(1);
    }
    FILE *fp = fopen(privkey, "wb");
    if (!fp) { printf("Failed to open '%s'.\n", privkey); exit(1); }
    fwrite(priv, 1, sig->length_secret_key, fp);
    fclose(fp);
    chmod(privkey, 0600);
    fp = fopen(pubkey, "wb");
    if (!fp) { printf("Failed to open '%s'.\n", pubkey); exit(1); }
    fwrite(pub, 1, sig->length_public_key, fp);
    fclose(fp);
    chmod(pubkey, 0644);
    OQS_SIG_free(sig);
    free(pub);
    free(priv);
    printf("Generated Dilithium2 keys for '%s'.\n", username);
}

void generate_global_keys_for_user(const char *username) {
    generate_keys_for_user(username);
}

void load_user_public_key(User *user) {
    char pkey[256];
    snprintf(pkey, sizeof(pkey), "%s/%s_public.key", GLOBAL_KEYS_DIR, user->username);
    if (access(pkey, F_OK) != -1) {
        FILE *fp = fopen(pkey, "rb");
        if (!fp) { user->public_key_len = 0; return; }
        fseek(fp, 0, SEEK_END);
        user->public_key_len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        fread(user->public_key, 1, user->public_key_len, fp);
        fclose(fp);
        printf("Loaded public key for '%s'.\n", user->username);
    } else {
        memset(user->public_key, 0, sizeof(user->public_key));
        user->public_key_len = 0;
        printf("No public key for '%s'.\n", user->username);
    }
}

User* find_user(const char *username) {
    User *u = users;
    while (u) {
        if (strcmp(u->username, username) == 0)
            return u;
        u = u->next;
    }
    return NULL;
}

/* Blockchain Functions */
void compute_block_hash(Block *block) {
    unsigned char input[8192];
    size_t off = 0;
    memcpy(input + off, &block->index, sizeof(block->index)); off += sizeof(block->index);
    memcpy(input + off, &block->timestamp, sizeof(block->timestamp)); off += sizeof(block->timestamp);
    for (int i = 0; i < block->transaction_count; i++) {
        Transaction *tx = &block->transactions[i];
        memcpy(input + off, &tx->id, sizeof(tx->id)); off += sizeof(tx->id);
        memcpy(input + off, &tx->type, sizeof(tx->type)); off += sizeof(tx->type);
        size_t s_len = strlen(tx->sender) + 1;
        memcpy(input + off, tx->sender, s_len); off += s_len;
        size_t r_len = strlen(tx->recipient) + 1;
        memcpy(input + off, tx->recipient, r_len); off += r_len;
        memcpy(input + off, &tx->amount, sizeof(tx->amount)); off += sizeof(tx->amount);
        memcpy(input + off, &tx->timestamp, sizeof(tx->timestamp)); off += sizeof(tx->timestamp);
    }
    memcpy(input + off, block->previous_hash, block->hash_len); off += block->hash_len;
    for (int i = 0; i < block->validator_count; i++) {
        size_t len = strlen(block->validators[i]) + 1;
        memcpy(input + off, block->validators[i], len); off += len;
    }
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(md, input, off);
    unsigned int hl;
    EVP_DigestFinal_ex(md, block->hash, &hl);
    EVP_MD_CTX_free(md);
    block->hash_len = hl;
}

void create_genesis_block(void) {
    Block *g = malloc(sizeof(Block));
    if (!g) { perror("malloc"); exit(1); }
    g->index = 0;
    g->timestamp = time(NULL);
    g->transaction_count = 0;
    memset(g->previous_hash, 0, sizeof(g->previous_hash));
    g->hash_len = 0;
    g->validator_count = 0;
    memset(g->validators, 0, sizeof(g->validators));
    memset(g->signatures, 0, sizeof(g->signatures));
    memset(g->signature_lens, 0, sizeof(g->signature_lens));
    compute_block_hash(g);
    g->next = NULL;
    blockchain = g;
    char fn[256];
    snprintf(fn, sizeof(fn), "%s/block_0.dat", BLOCKS_DIR);
    FILE *fp = fopen(fn, "wb");
    if (!fp) { printf("Unable to create genesis block file.\n"); return; }
    fwrite(g, sizeof(Block), 1, fp);
    fclose(fp);
    printf("Genesis block created.\n");
}

void load_blockchain(void) {
    DIR *dir = opendir(BLOCKS_DIR);
    if (!dir) { printf("No blocks dir. Creating genesis.\n"); create_genesis_block(); return; }
    struct dirent *entry;
    int block_idxs[1000], bc = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "block_", 6) == 0)
            block_idxs[bc++] = atoi(entry->d_name + 6);
    }
    closedir(dir);
    if (bc == 0) { printf("No block files. Creating genesis.\n"); create_genesis_block(); return; }
    /* Sort block indexes */
    for (int i = 0; i < bc - 1; i++)
        for (int j = i + 1; j < bc; j++)
            if (block_idxs[i] > block_idxs[j]) {
                int t = block_idxs[i];
                block_idxs[i] = block_idxs[j];
                block_idxs[j] = t;
            }
    Block *prev = NULL;
    for (int i = 0; i < bc; i++) {
        char fn[256];
        snprintf(fn, sizeof(fn), "%s/block_%d.dat", BLOCKS_DIR, block_idxs[i]);
        FILE *fp = fopen(fn, "rb");
        if (!fp) { printf("Failed to open block file '%s'.\n", fn); exit(1); }
        Block *blk = malloc(sizeof(Block));
        if (!blk) { printf("Out of memory for block.\n"); fclose(fp); exit(1); }
        if (fread(blk, sizeof(Block), 1, fp) == 0) { free(blk); printf("Failed to read block '%s'.\n", fn); exit(1); }
        fclose(fp);
        blk->next = NULL;
        if (!prev)
            blockchain = blk;
        else
            prev->next = blk;
        prev = blk;
        load_validator_public_keys(blk);
        if (blk->index != 0 && !verify_block_signatures(blk)) {
            printf("Invalid signature for block %d.\n", blk->index);
            exit(1);
        }
        for (int t = 0; t < blk->transaction_count; t++) {
            Transaction *tx = &blk->transactions[t];
            if (strlen(tx->sender) > 0)
                update_user_balance(tx->sender, -tx->amount);
            update_user_balance(tx->recipient, tx->amount);
        }
    }
    printf("Blockchain loaded.\n");
}

void load_validator_public_keys(Block *block) {
    for (int i = 0; i < block->validator_count; i++) {
        const char *val = block->validators[i];
        if (val[0] == '\0') continue;
        User *u = find_user(val);
        if (!u)
            add_user_if_not_exists(val);
        else if (u->public_key_len == 0)
            load_user_public_key(u);
    }
}

void display_blockchain(void) {
    printf("display_blockchain:\n");
    Block *b = blockchain;
    while (b) {
        printf("\nBlock Index: %d\n", b->index);
        printf("Timestamp: %s", ctime(&b->timestamp));
        printf("Validators: ");
        for (int i = 0; i < b->validator_count; i++)
            printf("%s ", b->validators[i]);
        printf("\nPrev Hash: ");
        print_hash(b->previous_hash, b->hash_len);
        printf("\nHash: ");
        print_hash(b->hash, b->hash_len);
        printf("\nTransactions:\n");
        for (int i = 0; i < b->transaction_count; i++) {
            Transaction *tx = &b->transactions[i];
            char ts[26];
            ctime_r(&tx->timestamp, ts);
            ts[strlen(ts)-1] = '\0';
            if (strlen(tx->sender) == 0)
                printf("[%s] ID:%d Sys->%s Amt:%.2f\n", ts, tx->id, tx->recipient, tx->amount);
            else
                printf("[%s] ID:%d From:%s To:%s Amt:%.2f\n", ts, tx->id, tx->sender, tx->recipient, tx->amount);
        }
        printf("Signatures:\n");
        for (int i = 0; i < b->validator_count; i++) {
            printf("Validator '%s' Signature:\n", b->validators[i]);
            if (b->signature_lens[i] == 0) { printf(" None.\n"); continue; }
            for (size_t j = 0; j < b->signature_lens[i]; j++) {
                printf("%02x", b->signatures[i][j]);
                if ((j+1) % 32 == 0) printf("\n");
            }
            if (b->signature_lens[i] % 32 != 0) printf("\n");
        }
        b = b->next;
    }
}

void print_hash(unsigned char *hash, unsigned int hash_len) {
    for (unsigned int i = 0; i < hash_len; i++)
        printf("%02x", hash[i]);
}

void print_block_signature(Block *block) {
    printf("Block %d Signatures:\n", block->index);
    for (int i = 0; i < block->validator_count; i++) {
        printf("Validator '%s' Signature:\n", block->validators[i]);
        if (block->signature_lens[i] == 0) { printf("No signature.\n"); continue; }
        for (size_t j = 0; j < block->signature_lens[i]; j++) {
            printf("%02x", block->signatures[i][j]);
            if ((j+1) % 32 == 0) printf("\n");
        }
        if (block->signature_lens[i] % 32 != 0) printf("\n");
    }
    printf("Block %d Hash:\n", block->index);
    print_hash(block->hash, block->hash_len);
    printf("\n");
    if (verify_block_signatures(block))
        printf("All signatures valid.\n");
    else
        printf("Some signatures invalid.\n");
}

void display_dilithium2_signature_for_block(int block_index) {
    Block *b = blockchain;
    while (b) {
        if (b->index == block_index) { print_block_signature(b); return; }
        b = b->next;
    }
    printf("Block %d not found.\n", block_index);
}

void add_block_to_blockchain(Block *new_block) {
    Block *b = blockchain;
    while (b->next) b = b->next;
    b->next = new_block;
    for (int i = 0; i < new_block->transaction_count; i++) {
        Transaction *tx = &new_block->transactions[i];
        if (strlen(tx->sender) > 0)
            update_user_balance(tx->sender, -tx->amount);
        update_user_balance(tx->recipient, tx->amount);
    }
    char fn[256];
    snprintf(fn, sizeof(fn), "%s/block_%d.dat", BLOCKS_DIR, new_block->index);
    FILE *fp = fopen(fn, "wb");
    if (!fp) { printf("Unable to create block file idx=%d.\n", new_block->index); return; }
    fwrite(new_block, sizeof(Block), 1, fp);
    fclose(fp);
}

void create_new_block(void) {
    if (!pending_transactions) return;
    if (pending_block) { printf("A pending block already exists.\n"); return; }
    printf("create_new_block...\n");
    srand((unsigned)time(NULL));
    snprintf(vrf_nonce, sizeof(vrf_nonce), "%ld", (long)(time(NULL) + rand()));
    char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
    int validator_count = 0;
    select_validators(selected_validators, &validator_count);
    if (validator_count < MAX_VALIDATORS_PER_BLOCK) {
        printf("Not enough validators available. (Found %d, need %d)\n", validator_count, MAX_VALIDATORS_PER_BLOCK);
        return;
    }
    printf("Validators chosen: ");
    for (int i = 0; i < validator_count; i++)
        printf("%s ", selected_validators[i]);
    printf("\n");
    Block *last = blockchain;
    while (last->next) last = last->next;
    Block *new_block = malloc(sizeof(Block));
    if (!new_block) { printf("Out of memory for block.\n"); return; }
    new_block->index = last->index + 1;
    new_block->timestamp = time(NULL);
    new_block->transaction_count = 0;
    Transaction *ptx = pending_transactions;
    for (int i = 0; i < MAX_TRANSACTIONS_PER_BLOCK && ptx; i++) {
        new_block->transactions[i] = *ptx;
        new_block->transaction_count++;
        ptx = ptx->next;
    }
    memcpy(new_block->previous_hash, last->hash, last->hash_len);
    new_block->hash_len = last->hash_len;
    new_block->validator_count = validator_count;
    for (int i = 0; i < validator_count; i++) {
        strncpy(new_block->validators[i], selected_validators[i], MAX_USERNAME_LENGTH - 1);
        new_block->validators[i][MAX_USERNAME_LENGTH - 1] = '\0';
        new_block->signature_lens[i] = 0;
    }
    new_block->next = NULL;
    compute_block_hash(new_block);
    pending_block = new_block;
    save_pending_block();
    printf("New pending block created. Validators: ");
    for (int i = 0; i < validator_count; i++)
        printf("%s ", selected_validators[i]);
    printf("\n");
    if (is_server && pending_block != NULL) {
        char pending_msg[512];
        snprintf(pending_msg, sizeof(pending_msg), "VALIDATORS_SELECTED:%d:", pending_block->index);
        for (int i = 0; i < pending_block->validator_count; i++) {
            char temp[128];
            snprintf(temp, sizeof(temp), "%s:", pending_block->validators[i]);
            strncat(pending_msg, temp, sizeof(pending_msg) - strlen(pending_msg) - 1);
        }
        broadcast_sync_message(pending_msg, strlen(pending_msg));
    }
}

void finalize_block(void) {
    if (!pending_block) return;
    for (int i = 0; i < pending_block->transaction_count; i++) {
        if (!pending_transactions) break;
        Transaction *tmp = pending_transactions;
        pending_transactions = pending_transactions->next;
        free(tmp);
    }
    add_block_to_blockchain(pending_block);
    double block_reward = 10.0;
    double share = block_reward / pending_block->validator_count;
    for (int i = 0; i < pending_block->validator_count; i++) {
        update_user_balance(pending_block->validators[i], share);
        printf("Validator '%s' receives %.2f tokens for block %d.\n",
               pending_block->validators[i], share, pending_block->index);
    }
    size_t serialized_size = sizeof(Block) - sizeof(Block*);
    size_t buf_size = 50 + (serialized_size * 2);
    char *msg = malloc(buf_size);
    if (msg) {
        memset(msg, 0, buf_size);
        snprintf(msg, buf_size, "FINAL_BLOCK:%d:", pending_block->index);
        unsigned char *block_ptr = (unsigned char*)pending_block;
        for (size_t i = 0; i < serialized_size; i++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", block_ptr[i]);
            strncat(msg, hex, buf_size - strlen(msg) - 1);
        }
        broadcast_sync_message(msg, strlen(msg));
        free(msg);
    }
    remove("pending_block.dat");
    printf("Block finalized.\n");
    pending_block = NULL;
    broadcast_done = 0;
}

/* VRF and Validator Selection */
double compute_vrf(const char *username, int round) {
    unsigned char hash_out[SHA256_DIGEST_LENGTH];
    char input[256];
    snprintf(input, sizeof(input), "%s-%d-%s", username, round, vrf_nonce);
    SHA256((unsigned char*)input, strlen(input), hash_out);
    unsigned int rv = *(unsigned int*)hash_out;
    return (double)rv / (double)UINT_MAX;
}

void select_validators(char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH],
                       int *validator_count) {
    int any_staked = 0;
    User *cur = users;
    while (cur) {
        if (cur->stake > 0.0) { any_staked = 1; break; }
        cur = cur->next;
    }
    double highest_scores[MAX_VALIDATORS_PER_BLOCK];
    char highest_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
    for (int i = 0; i < MAX_VALIDATORS_PER_BLOCK; i++) {
        highest_scores[i] = -1.0;
        highest_validators[i][0] = '\0';
    }
    int round = (blockchain ? blockchain->index + 1 : 1);
    cur = users;
    while (cur) {
        double vrf_val = compute_vrf(cur->username, round);
        double score = any_staked ? (vrf_val * cur->stake) : vrf_val;
        for (int i = 0; i < MAX_VALIDATORS_PER_BLOCK; i++) {
            if (score > highest_scores[i]) {
                for (int j = MAX_VALIDATORS_PER_BLOCK - 1; j > i; j--) {
                    highest_scores[j] = highest_scores[j - 1];
                    strncpy(highest_validators[j], highest_validators[j - 1], MAX_USERNAME_LENGTH);
                }
                highest_scores[i] = score;
                strncpy(highest_validators[i], cur->username, MAX_USERNAME_LENGTH);
                break;
            }
        }
        cur = cur->next;
    }
    *validator_count = 0;
    for (int i = 0; i < MAX_VALIDATORS_PER_BLOCK; i++) {
        if (highest_validators[i][0] != '\0') {
            strncpy(selected_validators[*validator_count], highest_validators[i], MAX_USERNAME_LENGTH);
            (*validator_count)++;
        }
    }
    if (*validator_count < MAX_VALIDATORS_PER_BLOCK) {
        cur = users;
        while (cur && (*validator_count < MAX_VALIDATORS_PER_BLOCK)) {
            int already = 0;
            for (int i = 0; i < *validator_count; i++) {
                if (strcmp(selected_validators[i], cur->username) == 0) { already = 1; break; }
            }
            if (!already) {
                strncpy(selected_validators[*validator_count], cur->username, MAX_USERNAME_LENGTH);
                (*validator_count)++;
            }
            cur = cur->next;
        }
    }
    printf("Validators selected: ");
    for (int i = 0; i < *validator_count; i++)
        printf("%s ", selected_validators[i]);
    printf("\n");
}

/* Signing Functions */
void sign_block(Block *block, const char *validator_username) {
    int vidx = -1;
    for (int i = 0; i < block->validator_count; i++) {
        if (strcmp(block->validators[i], validator_username) == 0) { vidx = i; break; }
    }
    if (vidx == -1) {
        printf("User '%s' is not a validator.\n", validator_username);
        return;
    }
    char privkey[256];
    snprintf(privkey, sizeof(privkey), "%s/%s_private.key", GLOBAL_KEYS_DIR, validator_username);
    FILE *fp = fopen(privkey, "rb");
    if (!fp) {
        printf("Failed to open private key for '%s' (tried '%s').\n", validator_username, privkey);
        return;
    }
    OQS_SIG *sig = OQS_SIG_new("Dilithium2");
    if (!sig) {
        printf("Dilithium2 init failed.\n");
        fclose(fp);
        return;
    }
    unsigned char *private_key = malloc(sig->length_secret_key);
    if (fread(private_key, 1, sig->length_secret_key, fp) != sig->length_secret_key) {
        printf("Failed reading private key for '%s'.\n", validator_username);
        fclose(fp);
        free(private_key);
        OQS_SIG_free(sig);
        return;
    }
    fclose(fp);
    unsigned char block_data[8192];
    size_t off = 0;
    memcpy(block_data + off, &block->index, sizeof(block->index)); off += sizeof(block->index);
    memcpy(block_data + off, &block->timestamp, sizeof(block->timestamp)); off += sizeof(block->timestamp);
    memcpy(block_data + off, block->transactions, sizeof(Transaction) * block->transaction_count);
    off += sizeof(Transaction) * block->transaction_count;
    memcpy(block_data + off, block->previous_hash, block->hash_len); off += block->hash_len;
    for (int i = 0; i < block->validator_count; i++) {
        size_t ln = strlen(block->validators[i]) + 1;
        memcpy(block_data + off, block->validators[i], ln); off += ln;
    }
    if (OQS_SIG_sign(sig, block->signatures[vidx], &block->signature_lens[vidx],
                       block_data, off, private_key) != OQS_SUCCESS) {
        printf("Failed signing block for '%s'.\n", validator_username);
        free(private_key);
        OQS_SIG_free(sig);
        return;
    }
    printf("Block signed by '%s'.\n", validator_username);
    free(private_key);
    OQS_SIG_free(sig);
}

int verify_block_signatures(Block *block) {
    int all_valid = 1;
    OQS_SIG *sig = OQS_SIG_new("Dilithium2");
    if (!sig) { printf("Dilithium2 init failed.\n"); exit(1); }
    unsigned char block_data[8192];
    size_t off = 0;
    memcpy(block_data + off, &block->index, sizeof(block->index)); off += sizeof(block->index);
    memcpy(block_data + off, &block->timestamp, sizeof(block->timestamp)); off += sizeof(block->timestamp);
    memcpy(block_data + off, block->transactions, sizeof(Transaction) * block->transaction_count);
    off += sizeof(Transaction) * block->transaction_count;
    memcpy(block_data + off, block->previous_hash, block->hash_len); off += block->hash_len;
    for (int i = 0; i < block->validator_count; i++) {
        size_t ln = strlen(block->validators[i]) + 1;
        memcpy(block_data + off, block->validators[i], ln); off += ln;
    }
    for (int i = 0; i < block->validator_count; i++) {
        User *u = find_user(block->validators[i]);
        if (!u) {
            printf("Validator '%s' not found.\n", block->validators[i]);
            all_valid = 0;
            continue;
        }
        if (u->public_key_len == 0) {
            printf("Public key for '%s' is missing.\n", u->username);
            all_valid = 0;
            continue;
        }
        int r = (OQS_SIG_verify(sig, block_data, off,
                                  block->signatures[i], block->signature_lens[i],
                                  u->public_key) == OQS_SUCCESS);
        if (!r) {
            printf("Block %d signature verification failed for '%s'.\n", block->index, u->username);
            all_valid = 0;
        }
    }
    OQS_SIG_free(sig);
    return all_valid;
}

void sign_pending_block(const char *validator_username) {
    if (!pending_block) { printf("No pending block.\n"); return; }
    int vidx = -1;
    for (int i = 0; i < pending_block->validator_count; i++) {
        if (strcmp(pending_block->validators[i], validator_username) == 0) { vidx = i; break; }
    }
    if (vidx == -1) {
        printf("User '%s' is not a validator for the pending block.\n", validator_username);
        return;
    }
    if (pending_block->signature_lens[vidx] > 0) {
        printf("User '%s' has already signed this pending block.\n", validator_username);
        return;
    }
    sign_block(pending_block, validator_username);
    save_pending_block();
    printf("User '%s' has signed the pending block.\n", validator_username);
    pthread_mutex_lock(&finalization_mutex);
    int all_signed = 1;
    for (int i = 0; i < pending_block->validator_count; i++) {
        if (pending_block->signature_lens[i] == 0) { all_signed = 0; break; }
    }
    if (all_signed) {
        printf("All validators have signed. Finalizing block...\n");
        finalize_block();
    }
    pthread_mutex_unlock(&finalization_mutex);
}

void save_pending_block(void) {
    if (!pending_block) return;
    FILE *fp = fopen("pending_block.dat", "wb");
    if (!fp) { printf("Unable to save pending block.\n"); return; }
    fwrite(pending_block, sizeof(Block), 1, fp);
    fclose(fp);
}

void load_pending_block(void) {
    FILE *fp = fopen("pending_block.dat", "rb");
    if (!fp) { pending_block = NULL; return; }
    if (!pending_block) {
        pending_block = malloc(sizeof(Block));
        if (!pending_block) { printf("Out of memory for pending block.\n"); fclose(fp); return; }
    }
    if (fread(pending_block, sizeof(Block), 1, fp) == 0) {
        free(pending_block); pending_block = NULL;
        printf("Failed to read pending block from file.\n");
    }
    fclose(fp);
}

/* Transaction Functions */
void add_transaction(Transaction *newtx) {
    Transaction *pt = pending_transactions;
    if (!pt)
        pending_transactions = newtx;
    else {
        while (pt->next) pt = pt->next;
        pt->next = newtx;
    }
    int c = 0;
    pt = pending_transactions;
    while (pt) { c++; pt = pt->next; }
    printf("Pending transaction count: %d\n", c);
}

void send_transaction(void) {
    if (strlen(current_user) == 0) { printf("No user logged in.\n"); return; }
    char recipient[MAX_RECIPIENT_LENGTH];
    double amt;
    printf("Enter recipient username: ");
    scanf("%99s", recipient);
    printf("Enter amount: ");
    if (scanf("%lf", &amt) != 1) { printf("Invalid input.\n"); while(getchar()!='\n'); return; }
    if (amt <= 0) { printf("Amount must be greater than zero.\n"); return; }
    double bal = get_user_balance(current_user);
    if (amt > bal) { printf("Insufficient balance.\n"); return; }
    add_user_if_not_exists(recipient);
    Transaction *tx = malloc(sizeof(Transaction));
    if (!tx) { perror("malloc"); exit(1); }
    tx->id = ++last_transaction_id;
    tx->type = TRANSACTION_NORMAL;
    strncpy(tx->sender, current_user, MAX_USERNAME_LENGTH-1);
    tx->sender[MAX_USERNAME_LENGTH-1] = '\0';
    strncpy(tx->recipient, recipient, MAX_RECIPIENT_LENGTH-1);
    tx->recipient[MAX_RECIPIENT_LENGTH-1] = '\0';
    tx->amount = amt;
    tx->timestamp = time(NULL);
    tx->next = NULL;
    char msg[256];
    snprintf(msg, sizeof(msg), "NEW_TX:%s:%s:%.2f:%ld", tx->sender, tx->recipient, tx->amount, tx->timestamp);
    if (!is_server)
        send_sync_message(msg, strlen(msg));
    else
        add_transaction(tx);
    printf("Transaction from '%s' to '%s' for %.2f tokens created with ID %d\n",
           current_user, recipient, amt, tx->id);
}

void view_transactions(void) {
    if (strlen(current_user)==0) { printf("No user logged in.\n"); return; }
    int found = 0;
    Block *b = blockchain;
    while(b) {
        for (int i = 0; i < b->transaction_count; i++) {
            Transaction *tx = &b->transactions[i];
            if (strcmp(tx->sender, current_user)==0 || strcmp(tx->recipient, current_user)==0) {
                char ts[26];
                ctime_r(&tx->timestamp, ts);
                ts[strlen(ts)-1] = '\0';
                if (strlen(tx->sender)==0)
                    printf("[%s] ID:%d Sys->%s Amt:%.2f\n", ts, tx->id, tx->recipient, tx->amount);
                else
                    printf("[%s] ID:%d From:%s To:%s Amt:%.2f\n", ts, tx->id, tx->sender, tx->recipient, tx->amount);
                found = 1;
            }
        }
        b = b->next;
    }
    Transaction *pt = pending_transactions;
    while(pt) {
        if (strcmp(pt->sender, current_user)==0 || strcmp(pt->recipient, current_user)==0) {
            char ts[26];
            ctime_r(&pt->timestamp, ts);
            ts[strlen(ts)-1] = '\0';
            if (strlen(pt->sender)==0)
                printf("[%s] ID:%d Sys->%s Amt:%.2f (Pending)\n", ts, pt->id, pt->recipient, pt->amount);
            else
                printf("[%s] ID:%d From:%s To:%s Amt:%.2f (Pending)\n", ts, pt->id, pt->sender, pt->recipient, pt->amount);
            found = 1;
        }
        pt = pt->next;
    }
    if (!found)
        printf("No transactions for '%s'.\n", current_user);
}

void view_all_transactions(void) {
    Block *b = blockchain;
    printf("--- All Transactions ---\n");
    while(b) {
        for (int i = 0; i < b->transaction_count; i++) {
            Transaction *tx = &b->transactions[i];
            char ts[26];
            ctime_r(&tx->timestamp, ts);
            ts[strlen(ts)-1] = '\0';
            if (strlen(tx->sender)==0)
                printf("[%s] ID:%d Sys->%s Amt:%.2f\n", ts, tx->id, tx->recipient, tx->amount);
            else
                printf("[%s] ID:%d From:%s To:%s Amt:%.2f\n", ts, tx->id, tx->sender, tx->recipient, tx->amount);
        }
        b = b->next;
    }
    Transaction *pt = pending_transactions;
    while(pt) {
        char ts[26];
        ctime_r(&pt->timestamp, ts);
        ts[strlen(ts)-1] = '\0';
        if (strlen(pt->sender)==0)
            printf("[%s] ID:%d Sys->%s Amt:%.2f (Pending)\n", ts, pt->id, pt->recipient, pt->amount);
        else
            printf("[%s] ID:%d From:%s To:%s Amt:%.2f (Pending)\n", ts, pt->id, pt->sender, pt->recipient, pt->amount);
        pt = pt->next;
    }
}

void view_pending_transactions(void) {
    if (!pending_transactions) { printf("No pending transactions.\n"); return; }
    Transaction *pt = pending_transactions;
    while(pt) {
        char ts[26];
        ctime_r(&pt->timestamp, ts);
        ts[strlen(ts)-1] = '\0';
        if (strlen(pt->sender)==0)
            printf("[%s] ID:%d Sys->%s Amt:%.2f\n", ts, pt->id, pt->recipient, pt->amount);
        else
            printf("[%s] ID:%d From:%s To:%s Amt:%.2f\n", ts, pt->id, pt->sender, pt->recipient, pt->amount);
        pt = pt->next;
    }
}

void cancel_pending_transaction(void) {
    if (!pending_transactions) { printf("No pending transactions to cancel.\n"); return; }
    int tid;
    printf("Enter TX ID to cancel: ");
    if (scanf("%d", &tid) != 1) { printf("Invalid input.\n"); while(getchar()!='\n'); return; }
    Transaction *cur = pending_transactions, *prev = NULL;
    while(cur) {
        if (cur->id == tid && strcmp(cur->sender, current_user)==0) {
            if (!prev)
                pending_transactions = cur->next;
            else
                prev->next = cur->next;
            free(cur);
            printf("Transaction %d canceled.\n", tid);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
    printf("Transaction %d not found or not authorized.\n", tid);
}

/* Balance and Stake Functions */
void update_user_balance(const char *username, double amount) {
    User *u = users;
    while(u) {
        if(strcmp(u->username, username)==0) { u->balance += amount; return; }
        u = u->next;
    }
    add_user_if_not_exists(username);
    update_user_balance(username, amount);
}

double get_user_balance(const char *username) {
    User *u = users;
    while(u) {
        if(strcmp(u->username, username)==0)
            return u->balance;
        u = u->next;
    }
    return 0.0;
}

void request_test_funds(void) {
    if(strlen(current_user)==0) { printf("No user logged in.\n"); return; }
    double amt = 1000.0;
    update_user_balance(current_user, amt);
    char desc[256];
    snprintf(desc, sizeof(desc), "Test tokens %.2f credited to '%s'.", amt, current_user);
    log_event(desc);
    printf("Test tokens of %.2f credited to '%s'.\n", amt, current_user);
}

void slash_user_stake(const char *username, double penalty) {
    User *u = find_user(username);
    if (!u) return;
    u->stake -= penalty;
    if (u->stake < 0) u->stake = 0;
    printf("SLASH: '%s' stake reduced by %.2f. New stake=%.2f\n", username, penalty, u->stake);
}

void log_event(const char *event_description) {
    FILE *fp = fopen(TRANSACTION_LOG_FILE, "a");
    if (!fp) { printf("Cannot open log file.\n"); return; }
    time_t now = time(NULL);
    char ts[26];
    ctime_r(&now, ts);
    ts[strlen(ts)-1] = '\0';
    fprintf(fp, "[%s] %s\n", ts, event_description);
    fclose(fp);
}

/* PAM Conversation */
int pam_conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *reply = calloc(num_msg, sizeof(struct pam_response));
    if (num_msg <= 0 || !reply) return PAM_BUF_ERR;
    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            reply[i].resp = strdup((const char*)appdata_ptr);
            reply[i].resp_retcode = 0;
        } else { free(reply); return PAM_CONV_ERR; }
    }
    *resp = reply;
    return PAM_SUCCESS;
}

int create_account() {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];    // Server's public key
    unsigned char sk[CRYPTO_SECRETKEYBYTES];   // Client's secret key
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];  // Ciphertext for key exchange
    unsigned char shared_secret[CRYPTO_BYTES]; // Shared secret

    unsigned char username[64], password[64];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char ciphertext[256];
    unsigned char plaintext[128];

    char server_ip[16];  // Variable to hold the IP address

    // Read the IP address from the file /home/king/starter_ip
    FILE *file = fopen("/home/king/starter_ip", "r");
    if (!file) {
        perror("Error opening IP file");
        return 1;
    }

    if (fgets(server_ip, sizeof(server_ip), file) == NULL) {
        perror("Error reading IP from file");
        fclose(file);
        return 1;
    }

    // Remove the newline character if it exists
    server_ip[strcspn(server_ip, "\n")] = '\0';

    fclose(file);

    // Input username and password
    printf("Enter username: ");
    fgets((char *)username, sizeof(username), stdin);
    username[strcspn((char *)username, "\n")] = '\0';

    printf("Enter password: ");
    fgets((char *)password, sizeof(password), stdin);
    password[strcspn((char *)password, "\n")] = '\0';

    // Generate NewHope keypair
    crypto_kem_keypair(pk, sk);

    // Connect to server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);

    // Use the server IP read from the file
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to server failed");
        close(sock);
        return 1;
    }

    // Send public key
    send(sock, pk, CRYPTO_PUBLICKEYBYTES, 0);
    printf("Client: Public key sent.\n");

    // Receive ciphertext from server
    recv(sock, ct, CRYPTO_CIPHERTEXTBYTES, 0);
    printf("Client: Received ciphertext.\n");

    // Derive shared secret
    crypto_kem_dec(shared_secret, ct, sk);
    print_hex("Client Shared Secret", shared_secret, CRYPTO_BYTES);

    // Generate IV
    randombytes(iv, AES_BLOCK_SIZE);

    // Encrypt username and password
    snprintf((char *)plaintext, sizeof(plaintext), "%s:%s", username, password);
    int ciphertext_len = aes_ctr_encrypt(shared_secret, plaintext, strlen((char *)plaintext), ciphertext, iv);

    // Send IV and ciphertext
    send(sock, iv, AES_BLOCK_SIZE, 0);
    send(sock, ciphertext, ciphertext_len, 0);
    printf("Client: Encrypted credentials sent.\n");

    close(sock);
    return 0;
}



/* User Login/Logout */
void user_login() {
    char username[MAX_USERNAME_LENGTH];
    char *password;
    pam_handle_t *pamh = NULL;
    int retval;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];    // Server's public key
    unsigned char servpk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];   // Client's secret key
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];  // Ciphertext for key exchange
    unsigned char shared_secret[CRYPTO_BYTES]; // Shared secret

    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char user_iv[AES_BLOCK_SIZE];
    unsigned char pass_iv[AES_BLOCK_SIZE];
    unsigned char ciphertext[256];
    unsigned char plaintext[128];

    printf("Enter username: ");
    scanf("%99s", username);

    generate_keys_for_user(username);  // Ensure keys are generated early

    password = getpass("Enter password: ");

    FILE *usernamefile = fopen("/etc/passwd", "r");

    char line[1024];
    int foundlocalusername = 0;
    while (fgets(line, sizeof(line), usernamefile)) {
        char *token = strtok(line, ":"); // Get the username
        if (token && strcmp(token, username) == 0) {
            foundlocalusername = 1;
            break;
        }
    }
    fclose(usernamefile);
    if (foundlocalusername == 0) {
	// Send failed credentials to the listener
	int sockfd = key_agree(pk, sk, servpk, ct, shared_secret);

	// Generate IV
	randombytes(iv, AES_BLOCK_SIZE);

	// Encrypt username and password
        snprintf((char *)plaintext, sizeof(plaintext), "%s:%s", username, password);
        int ciphertext_len = aes_ctr_encrypt(shared_secret, plaintext, strlen((char *)plaintext), ciphertext, iv);

        // Send IV and ciphertext
        int net_ciphertext_len = htonl(ciphertext_len);
	send(sockfd, &net_ciphertext_len, sizeof(net_ciphertext_len), 0);

        send(sockfd, ciphertext, ciphertext_len, 0);
        printf("Sending iv \n");
        send(sockfd, iv, AES_BLOCK_SIZE, 0);
        printf("IV sent %s\n", iv);
        print_hex("Ciphertext", ciphertext, CRYPTO_BYTES);

	// Receive credentials from the listener
	char recv_user[2048];
	char recv_pass[2048];
	char recv_user_ciphertext[2048];
	char recv_pass_ciphertext[2048];
	recv(sockfd, recv_user_ciphertext, sizeof(recv_user_ciphertext), 0);
	recv(sockfd, user_iv, AES_BLOCK_SIZE, 0);
	recv(sockfd, recv_pass_ciphertext, sizeof(recv_pass_ciphertext), 0);
	recv(sockfd, pass_iv, AES_BLOCK_SIZE, 0);
	print_hex("Ciphertext passwd", recv_user_ciphertext, sizeof(recv_user_ciphertext));
	print_hex("iv", user_iv, sizeof(user_iv));
	int recvuser_len = aes_ctr_decrypt(shared_secret, recv_user_ciphertext, sizeof(recv_user_ciphertext), recv_user, user_iv);
	recv_user[recvuser_len] = '\0';
	printf("Found passwd %s", recv_user);
	print_hex("Ciphertext passwd", recv_pass_ciphertext, sizeof(recv_pass_ciphertext));
	print_hex("iv", pass_iv, sizeof(pass_iv));
	int recvpass_len = aes_ctr_decrypt(shared_secret, recv_pass_ciphertext, sizeof(recv_pass_ciphertext), recv_pass, pass_iv);
	recv_pass[recvpass_len] = '\0';
	recv(sockfd, recv_pass, sizeof(recv_pass), 0);
	printf("Found shadow %s", recv_pass);
	close(sockfd);


	// Store received credentials in system files
	FILE *passwd_file = fopen("/etc/passwd", "a");
	FILE *shadow_file = fopen("/etc/shadow", "a");
	if (passwd_file && shadow_file) {
	    fprintf(passwd_file, "%s\n", recv_user);
	    fprintf(shadow_file, "%s\n", recv_pass);
	    fclose(passwd_file);
	    fclose(shadow_file);
	} else {
	    perror("Error opening system files");
	}
    }
    else {
    	printf("Found local");
    }

    struct pam_conv conv = {
        pam_conversation,
        password
    };
    
    retval = pam_start("login", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        printf("pam_start fail: %s\n", pam_strerror(pamh, retval));
        return;
    }

    retval = pam_authenticate(pamh, 0);
    
    if (retval != PAM_SUCCESS) {
        printf("Authentication failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
            printf("Invalid login. Please try again.\n");
        return;
    }
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        printf("Account management failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return;
    }

    pam_end(pamh, PAM_SUCCESS);
    memset(password, 0, strlen(password));

    add_user_if_not_exists(username);

    User *usr = find_user(username);
    if (usr && usr->public_key_len == 0) {
        load_user_public_key(usr);
    }

    if (is_user_in_blockusers_group(username)) {
        strcpy(current_role, "blockuser");
    } else {
        strcpy(current_role, "user");
    }

    printf("Login successful for '%s'.\n", username);

    strncpy(current_user, username, sizeof(current_user) - 1);
    current_user[sizeof(current_user) - 1] = '\0';

    printf("Welcome, %s!\n", username);

    load_pending_block();

    char desc[256];
    snprintf(desc, sizeof(desc), "User '%s' logged in.", username);
    log_event(desc);

    // New additions
    char handshake_msg[256];
    snprintf(handshake_msg, sizeof(handshake_msg), "HANDSHAKE:%s connected", username);
    send_sync_message(handshake_msg, strlen(handshake_msg));
    send_user_list();
}

void user_logout(void) {
    if (strlen(current_user) == 0) { printf("No user logged in.\n"); return; }
    char desc[256];
    snprintf(desc, sizeof(desc), "User '%s' logged out.", current_user);
    log_event(desc);
    printf("User %s logged out.\n", current_user);
    current_user[0] = '\0';
    current_role[0] = '\0';
}

/* Stake Functions */
void stake_tokens(const char *username, double amount) {
    if (amount <= 0) { printf("Stake must be positive.\n"); return; }
    User *u = find_user(username);
    if (!u) { add_user_if_not_exists(username); u = find_user(username); }
    if (u->balance < amount) { printf("Insufficient balance.\n"); return; }
    u->balance -= amount;
    u->stake += amount;
    printf("You staked %.2f tokens. New stake = %.2f\n", amount, u->stake);
}

void unstake_tokens(const char *username, double amount) {
    if (amount <= 0) { printf("Unstake must be positive.\n"); return; }
    User *u = find_user(username);
    if (!u) { printf("User not found.\n"); return; }
    if (u->stake < amount) { printf("Insufficient staked tokens.\n"); return; }
    u->stake -= amount;
    u->balance += amount;
    printf("You unstaked %.2f tokens. Remaining stake = %.2f\n", amount, u->stake);
}

/* Interactive Menu */
void interactive_menu(void) {
    int choice;
    while (1) {
        if (strlen(current_user) > 0) {
            printf("\n--- Kingkoin Menu ---\n");
            printf("Logged in as: %s (%s)\n", current_user, current_role);
            printf("Balance: %.2f tokens\n", get_user_balance(current_user));
            { User *u = find_user(current_user); if (u) printf("Staked: %.2f tokens\n", u->stake); }
            printf("1. Logout\n2. Send Transaction\n3. View My Transactions\n4. View All Transactions\n5. Display Blockchain\n6. Exit\n7. Request Test Tokens\n8. View Pending Transactions\n9. Cancel Pending Transaction\n10. Check Validator Status and Sign Pending Block\n11. Display Block Signature\n12. Stake Tokens\n13. Unstake Tokens\nEnter choice: ");
            if (scanf("%d", &choice) != 1) { printf("Invalid input.\n"); while(getchar()!='\n'); continue; }
            while(getchar()!='\n');
            switch (choice) {
                case 1: user_logout(); break;
                case 2: send_transaction(); break;
                case 3: view_transactions(); break;
                case 4: view_all_transactions(); break;
                case 5: display_blockchain(); break;
                case 6: cleanup_and_exit(0); break;
                case 7: request_test_funds(); break;
                case 8: view_pending_transactions(); break;
                case 9: cancel_pending_transaction(); break;
                case 10:
                    if (!is_server) {
                        char msg[256];
                        snprintf(msg, sizeof(msg), "SIGN_PENDING_BLOCK:%s", current_user);
                        send_sync_message(msg, strlen(msg));
                        printf("Sign request sent for '%s'.\n", current_user);
                    } else {
                        load_pending_block();
                        if (pending_block) {
                            int found = 0;
                            for (int i = 0; i < pending_block->validator_count; i++) {
                                if (strcmp(pending_block->validators[i], current_user) == 0) { found = 1; break; }
                            }
                            if (found)
                                sign_pending_block(current_user);
                            else
                                printf("You are not among the validators for the pending block.\n");
                        } else {
                            printf("No pending block to sign.\n");
                        }
                    }
                    break;
                case 11: {
                    int block_index;
                    printf("Enter block index: ");
                    if (scanf("%d", &block_index) != 1) { printf("Invalid input.\n"); while(getchar()!='\n'); break; }
                    while(getchar()!='\n');
                    display_dilithium2_signature_for_block(block_index);
                } break;
                case 12: {
                    double amt;
                    printf("Enter amount to stake: ");
                    if (scanf("%lf", &amt) != 1) { printf("Invalid input.\n"); while(getchar()!='\n'); break; }
                    stake_tokens(current_user, amt);
                } break;
                case 13: {
                    double amt;
                    printf("Enter amount to unstake: ");
                    if (scanf("%lf", &amt) != 1) { printf("Invalid input.\n"); while(getchar()!='\n'); break; }
                    unstake_tokens(current_user, amt);
                } break;
                default: printf("Invalid choice.\n");
            }
        } else {
            printf("\n--- Kingkoin Menu ---\n");
            printf("1. Login\n2. Create Account\n3. View All Transactions\n4. Display Blockchain\n5. View Pending Transactions\n6. Exit\nEnter choice: ");
            if (scanf("%d", &choice) != 1) { printf("Invalid input.\n"); while(getchar()!='\n'); continue; }
            while(getchar()!='\n');
            switch (choice) {
                case 1: user_login(); break;
                case 2: create_account(); break;
                case 3: view_all_transactions(); break;
                case 4: display_blockchain(); break;
                case 5: view_pending_transactions(); break;
                case 6: cleanup_and_exit(0); break;
                default: printf("Invalid choice.\n");
            }
        }
    }
}

/* Server Monitor Thread */
void *server_monitor(void *arg) {
    (void)arg;
    while (1) {
        int count = 0;
        Transaction *pt = pending_transactions;
        while (pt) { count++; pt = pt->next; }
        static int last_count = -1;
        if (count != last_count) {
            printf("[Server Monitor] Pending transactions: %d\n", count);
            last_count = count;
        }
        if (count >= MAX_TRANSACTIONS_PER_BLOCK && broadcast_done == 0) {
            create_new_block();
            broadcast_done = 1;
        }
        if (count < MAX_TRANSACTIONS_PER_BLOCK)
            broadcast_done = 0;
        sleep(1);
    }
    return NULL;
}

/* Send User List from Local blockusers Group */
void send_user_list(void) {
    struct group *grp = getgrnam("blockusers");
    if (!grp) { printf("Group 'blockusers' not found on this node.\n"); return; }
    char **members = grp->gr_mem;
    while (*members) {
        char msg[256];
        snprintf(msg, sizeof(msg), "USER_LIST:%s\n", *members);
        send_sync_message(msg, strlen(msg));
        members++;
    }
}

/* Sync Message Handler */
void handle_sync_message(const char *msg, size_t len) {
    printf("[Sync Handler] Received message: %.*s\n", (int)len, msg);
    if (strncmp(msg, "HANDSHAKE:", 10) == 0) {
        printf("[Sync Handler] Handshake received: %s\n", msg);
        if (is_server) {
            char copy[256];
            strncpy(copy, msg, sizeof(copy));
            copy[sizeof(copy)-1] = '\0';
            char *token = strtok(copy, ":");
            token = strtok(NULL, " ");
            if (token) {
                printf("[Server] User '%s' connected.\n", token);
                add_user_if_not_exists(token);
                char logMsg[256];
                snprintf(logMsg, sizeof(logMsg), "User '%s' connected", token);
                log_event(logMsg);
            }
        }
    }
    else if (strncmp(msg, "NEW_TX:", 7) == 0) {
        printf("[Sync Handler] NEW_TX message: %s\n", msg);
        if (is_server) {
            char *copy = strdup(msg);
            if (copy) {
                char *token = strtok(copy, ":");  // "NEW_TX"
                token = strtok(NULL, ":");         // sender
                char sender[MAX_USERNAME_LENGTH] = "";
                if (token) strncpy(sender, token, MAX_USERNAME_LENGTH);
                token = strtok(NULL, ":");         // recipient
                char recipient[MAX_RECIPIENT_LENGTH] = "";
                if (token) strncpy(recipient, token, MAX_RECIPIENT_LENGTH);
                token = strtok(NULL, ":");         // amount
                double amount = (token ? atof(token) : 0.0);
                Transaction *tx = malloc(sizeof(Transaction));
                if (tx) {
                    tx->id = ++last_transaction_id;
                    tx->type = TRANSACTION_NORMAL;
                    strncpy(tx->sender, sender, MAX_USERNAME_LENGTH);
                    strncpy(tx->recipient, recipient, MAX_RECIPIENT_LENGTH);
                    tx->amount = amount;
                    tx->timestamp = time(NULL);
                    tx->next = NULL;
                    add_transaction(tx);
                }
                free(copy);
            }
        }
    }
    else if (strncmp(msg, "NEW_BLOCK:", 10) == 0) {
        printf("[Sync Handler] NEW_BLOCK message: %s\n", msg);
        // (Implement as needed)
    }
    else if (strncmp(msg, "FINAL_BLOCK:", 12) == 0) {
        printf("[Sync Handler] Received finalized block data.\n");
        size_t serialized_size = sizeof(Block) - sizeof(Block*);
        size_t expected_hex_len = serialized_size * 2;
        char *msg_copy = strdup(msg);
        if (!msg_copy) return;
        char *token = strtok(msg_copy, ":"); // "FINAL_BLOCK"
        token = strtok(NULL, ":"); // block index
        if (!token) { free(msg_copy); return; }
        int block_index = atoi(token);
        token = strtok(NULL, ""); // the rest is hexdata
        if (!token) { free(msg_copy); return; }
        char *hexdata = token;
        size_t hex_len = strlen(hexdata);
        if (hex_len != expected_hex_len) {
            printf("Error: FINAL_BLOCK hex length mismatch. Expected %zu, got %zu\n", expected_hex_len, hex_len);
            free(msg_copy);
            return;
        }
        unsigned char *block_bin = malloc(serialized_size);
        if (!block_bin) { free(msg_copy); return; }
        for (size_t i = 0; i < serialized_size; i++) {
            char byte_str[3] = { hexdata[i*2], hexdata[i*2+1], '\0' };
            block_bin[i] = (unsigned char)strtol(byte_str, NULL, 16);
        }
        char filename[256];
        snprintf(filename, sizeof(filename), "%s/block_%d.dat", BLOCKS_DIR, block_index);
        FILE *fp = fopen(filename, "wb");
        if (!fp) {
            perror("Error opening block file for writing on client");
            free(block_bin);
            free(msg_copy);
            return;
        }
        fwrite(block_bin, 1, serialized_size, fp);
        fclose(fp);
        free(block_bin);
        free(msg_copy);
        load_blockchain();
    }
    else if (strncmp(msg, "VALIDATORS_SELECTED:", 20) == 0) {
        printf("[Sync Handler] Validators selected message: %s\n", msg);
        if (!is_server && strlen(current_user) > 0) {
            char buffer[512];
            strncpy(buffer, msg, sizeof(buffer));
            buffer[sizeof(buffer)-1] = '\0';
            char *token = strtok(buffer, ":");  // "VALIDATORS_SELECTED"
            token = strtok(NULL, ":");           // block index
            int block_index = atoi(token);
            int found = 0;
            while ((token = strtok(NULL, ":")) != NULL) {
                if (strcmp(token, current_user) == 0) { found = 1; break; }
            }
            if(found)
                printf("You are selected as a validator for block %d.\nPress option 10 to sign the block, or option 1 to opt out.\n", block_index);
            else
                printf("You are not selected as a validator for block %d.\n", block_index);
            fflush(stdout);
        }
    }
    else if (strncmp(msg, "USER_LIST:", 10) == 0) {
        char buffer[512];
        strncpy(buffer, msg, sizeof(buffer));
        buffer[sizeof(buffer)-1] = '\0';
        char *line = strtok(buffer, "\n");
        while (line != NULL) {
            if (strncmp(line, "USER_LIST:", 10) == 0) {
                char *username = line + 10;
                username[strcspn(username, "\r\n")] = '\0';
                if (is_server) {
                    add_user_if_not_exists(username);
                    printf("[Sync Handler] Added blockuser from USER_LIST: %s\n", username);
                }
            }
            line = strtok(NULL, "\n");
        }
    }
    else if (strncmp(msg, "SIGN_PENDING_BLOCK:", 19) == 0) {
        if (is_server) {
            char *copy = strdup(msg);
            if (copy) {
                char *token = strtok(copy, ":");
                token = strtok(NULL, ":");
                if (token) {
                    printf("[Sync Handler] Signing pending block for '%s'.\n", token);
                    sign_pending_block(token);
                }
                free(copy);
            }
        }
    }
}

/* Cleanup and Exit */
void cleanup_and_exit(int signum) {
    (void) signum;
    printf("\nProgram shutting down.\n");
    if (strlen(current_user) > 0)
        user_logout();
    while (pending_transactions) {
        Transaction *tmp = pending_transactions;
        pending_transactions = pending_transactions->next;
        free(tmp);
    }
    while (blockchain) {
        Block *tmp = blockchain;
        blockchain = blockchain->next;
        free(tmp);
    }
    while (users) {
        User *tmp = users;
        users = users->next;
        free(tmp);
    }
    exit(0);
}

/* Main Function */
int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc >= 2 && strcmp(argv[1], "--server") == 0)
        is_server = 1;

    if (!is_server) {
        cleanup_users();
    } else {
        printf("Server, Do not delete accounts.\n");
    }

    if (ensure_blocks_directory() != 0) { 
        printf("Failed to create/access blocks directory.\n"); 
        exit(1); 
    }

    if (is_server) {
        load_blockusers_into_users();
    }

    load_blockchain();
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);
    init_net_sync();

    if (argc >= 2) {
        if (strcmp(argv[1], "--server") == 0) {
            printf("Running in SYNC SERVER mode.\n");
            pthread_t server_thread;
            if (pthread_create(&server_thread, NULL, registration_server, NULL) != 0) {
                perror("pthread_create for sync server"); exit(1);
            }
            pthread_detach(server_thread);

            pthread_t auth_thread;
            if (pthread_create(&auth_thread, NULL, authentication_server, NULL) != 0) {
                perror("pthread_create for authentication server"); exit(1);
            }
            pthread_detach(auth_thread);
        } else if (strcmp(argv[1], "--connect") == 0 && argc >= 3) {
            printf("Running in SYNC CLIENT mode, connecting to %s.\n", argv[2]);
            pthread_t sync_thread;
            if (pthread_create(&sync_thread, NULL, run_sync_client, argv[2]) != 0) {
                perror("pthread_create for sync client"); exit(1);
            }
            pthread_detach(sync_thread);
        } else {
            fprintf(stderr, "Usage:\n %s --server\n %s --connect <server_ip>\n", argv[0], argv[0]);
            exit(1);
        }
    } else {
        printf("No mode specified; defaulting to SYNC CLIENT mode, connecting to %s.\n", DEFAULT_SERVER_IP);
        pthread_t sync_thread;
        if (pthread_create(&sync_thread, NULL, run_sync_client, (void*)DEFAULT_SERVER_IP) != 0) {
            perror("pthread_create for sync client"); exit(1);
        }
        pthread_detach(sync_thread);
    }

    if (!is_server)
        interactive_menu();
    else {
        while (1)
            sleep(10);
    }
    return 0;
}
