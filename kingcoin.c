// Filename: kingcoin.c

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>       // For getpass()
#include <pwd.h>          // For getpwnam()
#include <grp.h>          // For getgrnam()
#include <time.h>         // For time functions
#include <signal.h>       // For signal handling
#include <fcntl.h>        // For file operations
#include <sys/file.h>     // For file locking
#include <sys/stat.h>     // For mkdir()
#include <dirent.h>       // For directory operations
#include <openssl/sha.h>  // For SHA256 hashing
#include <openssl/evp.h>  // For SHA3-512 via OpenSSL EVP interface
#include <security/pam_appl.h>  // For PAM authentication

// Include the OQS library header for Dilithium2
#include <oqs/oqs.h>

#define MAX_USERNAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 100
#define MAX_RECIPIENT_LENGTH 100
#define BLOCKS_DIR "blocks"
#define TRANSACTION_LOG_FILE "transaction_log.txt"
#define MAX_TRANSACTIONS_PER_BLOCK 5
#define MAX_VALIDATORS_PER_BLOCK 3 // Adjust as needed

// Global variables to store the currently logged-in user and role
char current_user[MAX_USERNAME_LENGTH] = "";
char current_role[20] = ""; // User role: user, validator, blockuser

// Enum for transaction types
typedef enum {
    TRANSACTION_NORMAL
} TransactionType;

// Structure to represent a transaction
typedef struct Transaction {
    int id;                                        // Unique transaction ID
    TransactionType type;                          // Type of transaction
    char sender[MAX_USERNAME_LENGTH];              // Sender's username
    char recipient[MAX_RECIPIENT_LENGTH];          // Recipient's username
    double amount;                                 // Transaction amount
    time_t timestamp;                              // Timestamp of the transaction
    struct Transaction *next;                      // Pointer to the next transaction (for pending transactions list)
} Transaction;

// Structure to represent a block in the blockchain
typedef struct Block {
    int index;                                    // Block index in the blockchain
    time_t timestamp;                             // Timestamp of the block creation
    Transaction transactions[MAX_TRANSACTIONS_PER_BLOCK]; // Array of transactions in the block
    int transaction_count;                        // Number of transactions in the block
    unsigned char previous_hash[64];              // Hash of the previous block (64 bytes for SHA3-512)
    unsigned char hash[64];                       // Hash of the current block
    unsigned int hash_len;                        // Length of the hash

    int validator_count; // Number of validators
    char validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH]; // Validators' usernames

    unsigned char signatures[MAX_VALIDATORS_PER_BLOCK][5000]; // Signatures from validators
    size_t signature_lens[MAX_VALIDATORS_PER_BLOCK]; // Lengths of the signatures

    struct Block *next;                           // Pointer to the next block in the blockchain
} Block;

// Structure to represent a user
typedef struct User {
    char username[MAX_USERNAME_LENGTH];
    double balance;
    double stake;  // ADDED: Amount of tokens staked for PoS
    unsigned char public_key[5000]; // Adjusted size for Dilithium2 public key
    size_t public_key_len;          // Store the length of the public key
    struct User *next;
} User;

// Head pointers for the blockchain, pending transactions list, and user list
Block *blockchain = NULL;
Transaction *pending_transactions = NULL;
User *users = NULL; // Head of the user list

// Global transaction ID counter
int last_transaction_id = 0;

// Global pending block
Block *pending_block = NULL;

// Function prototypes
int is_user_in_group(const char *username, const char *groupname);
void add_transaction(Transaction *new_transaction);
void compute_block_hash(Block *block);
void create_genesis_block();
void add_block_to_blockchain(Block *new_block);
void create_new_block();
void load_blockchain();
void display_blockchain();
void user_login();
void user_logout();
void send_transaction();
void view_transactions();
void view_all_transactions();
void view_pending_transactions();
void cancel_pending_transaction();
void update_user_balance(const char *username, double amount);
double get_user_balance(const char *username);
void request_test_funds();
void test_keccak_hash();
void log_event(const char *event_description);
void cleanup_blockchain();
void cleanup_pending_transactions();
void cleanup_users();
void cleanup_and_exit(int signum);
void print_hash(unsigned char *hash, unsigned int hash_len);
double compute_vrf(const char *username, int round);
void select_validators(char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH], int *validator_count);
void check_and_create_block();
void add_user_if_not_exists(const char *username);
void load_blockusers_into_users();
int is_user_in_blockusers_group(const char *username);
int ensure_blocks_directory();
void generate_keys_for_user(const char *username);
void sign_block(Block *block, const char *validator_username);
int verify_block_signatures(Block *block);
void print_block_signature(Block *block);
void display_dilithium2_signature_for_block(int block_index);
void load_validator_public_keys(Block *block);
void load_user_public_key(User *user);
void save_pending_block();
void load_pending_block();
void sign_pending_block(const char *validator_username);
void finalize_block();

// ADDED: staking-related prototypes
void stake_tokens(const char *username, double amount);
void unstake_tokens(const char *username, double amount);

// Utility to find a user in the linked list
User *find_user(const char *username);

// PAM conversation function prototype
int pam_conversation(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr);

int main() {
    int choice;

    // Ensure the blocks directory exists
    if (ensure_blocks_directory() != 0) {
        printf("Failed to create or access the blocks directory.\n");
        exit(1);
    }

    // Load blockchain from files
    load_blockusers_into_users();
    // Load blockusers into users list
    load_blockchain();
    // Register signal handlers for graceful exit
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    while (1) {
        printf("\n--- Simple Login and Blockchain System (with basic PoS) ---\n");

        if (strlen(current_user) > 0) {
            // User is logged in
            printf("Logged in as: %s (%s)\n", current_user, current_role);
            printf("Balance: %.2f tokens\n", get_user_balance(current_user));

            // Find user struct to also display stake:
            User *u = find_user(current_user);
            if (u) {
                printf("Staked: %.2f tokens\n", u->stake);
            }

            printf("1. Logout\n");
            printf("2. Send Transaction\n");
            printf("3. View My Transactions\n");
            printf("4. View All Transactions\n");
            printf("5. Display Blockchain\n");
            printf("6. Exit\n");
            printf("7. Request Test Tokens\n");
            printf("8. View Pending Transactions\n");
            printf("9. Cancel Pending Transaction\n");
            printf("10. Check Validator Status and Create Block\n");
            printf("11. Display Block Signature\n");
            // ADDED menu items for staking
            printf("12. Stake Tokens\n");
            printf("13. Unstake Tokens\n");

            printf("Enter your choice: ");
            if (scanf("%d", &choice) != 1) {
                printf("Invalid input. Please enter a number.\n");
                while (getchar() != '\n'); // Clear input buffer
                continue;
            }
            while (getchar() != '\n'); // Clear input buffer

            switch (choice) {
                case 1:
                    user_logout();
                    break;
                case 2:
                    send_transaction();
                    break;
                case 3:
                    view_transactions();
                    break;
                case 4:
                    view_all_transactions();
                    break;
                case 5:
                    display_blockchain();
                    break;
                case 6:
                    cleanup_and_exit(0);
                    break;
                case 7:
                    request_test_funds();
                    break;
                case 8:
                    view_pending_transactions();
                    break;
                case 9:
                    cancel_pending_transaction();
                    break;
                case 10:
                    check_and_create_block();
                    break;
                case 11:
                {
                    int block_index;
                    printf("Enter the block index to display its signature: ");
                    if (scanf("%d", &block_index) != 1) {
                        printf("Invalid input.\n");
                        while (getchar() != '\n'); // Clear input buffer
                        break;
                    }
                    while (getchar() != '\n'); // Clear input buffer
                    display_dilithium2_signature_for_block(block_index);
                    break;
                }
                // ADDED: Staking menu handlers
                case 12:
                {
                    double amount;
                    printf("Enter amount to stake: ");
                    if (scanf("%lf", &amount) != 1) {
                        printf("Invalid input.\n");
                        while (getchar() != '\n'); // Clear buffer
                        break;
                    }
                    stake_tokens(current_user, amount);
                    break;
                }
                case 13:
                {
                    double amount;
                    printf("Enter amount to unstake: ");
                    if (scanf("%lf", &amount) != 1) {
                        printf("Invalid input.\n");
                        while (getchar() != '\n'); // Clear buffer
                        break;
                    }
                    unstake_tokens(current_user, amount);
                    break;
                }
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        } else {
            // User is not logged in
            printf("1. Login\n");
            printf("2. View All Transactions\n");
            printf("3. Display Blockchain\n");
            printf("4. View Pending Transactions\n");
            printf("5. Exit\n");
            printf("Enter your choice: ");
            if (scanf("%d", &choice) != 1) {
                printf("Invalid input. Please enter a number.\n");
                while (getchar() != '\n'); // Clear input buffer
                continue;
            }
            while (getchar() != '\n'); // Clear input buffer

            switch (choice) {
                case 1:
                    user_login();
                    break;
                case 2:
                    view_all_transactions();
                    break;
                case 3:
                    display_blockchain();
                    break;
                case 4:
                    view_pending_transactions();
                    break;
                case 5:
                    cleanup_and_exit(0);
                    break;
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        }
    }

    return 0;
}

// Function to ensure the blocks directory exists
int ensure_blocks_directory() {
    struct stat st = {0};
    if (stat(BLOCKS_DIR, &st) == -1) {
        if (mkdir(BLOCKS_DIR, 0700) != 0) {
            perror("mkdir");
            return -1;
        }
    }
    return 0;
}

// Function to test SHA3-512 hash with a known input
void test_keccak_hash() {
    const char *test_input = "abc";
    unsigned char hash_output[64]; // SHA3-512 hash size is 64 bytes

    printf("test_keccak_hash: Testing SHA3-512 hash function via OpenSSL...\n");

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Failed to create EVP_MD_CTX.\n");
        exit(1);
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1) {
        printf("Failed to initialize digest context.\n");
        exit(1);
    }
    if (EVP_DigestUpdate(mdctx, test_input, strlen(test_input)) != 1) {
        printf("Failed to update digest.\n");
        exit(1);
    }
    if (EVP_DigestFinal_ex(mdctx, hash_output, NULL) != 1) {
        printf("Failed to finalize digest.\n");
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);

    printf("SHA3-512 hash of \"%s\":\n", test_input);
    for (unsigned int i = 0; i < 64; i++) {
        printf("%02X", hash_output[i]);
    }
    printf("\n");
}

// Function to check if a user is in a specific group
int is_user_in_group(const char *username, const char *groupname) {
    struct group *grp = getgrnam(groupname);
    if (!grp) {
        return 0;
    }

    // Check if the user's primary group matches
    struct passwd *pwd = getpwnam(username);
    if (pwd && pwd->pw_gid == grp->gr_gid) {
        return 1;
    }

    // Check if the user is in the group's member list
    char **members = grp->gr_mem;
    while (*members) {
        if (strcmp(*members, username) == 0) {
            return 1;
        }
        members++;
    }

    return 0;
}

// Function to check if a user is in blockusers group
int is_user_in_blockusers_group(const char *username) {
    return is_user_in_group(username, "blockusers");
}

// Function to compute the SHA3-512 hash of a block using OpenSSL
void compute_block_hash(Block *block) {
    printf("compute_block_hash: Computing hash for block index %d using SHA3-512 via OpenSSL...\n", block->index);

    unsigned char hash_input[8192]; // Adjust size as needed
    size_t offset = 0;

    // Hash block index
    memcpy(hash_input + offset, &block->index, sizeof(block->index));
    offset += sizeof(block->index);

    // Hash block timestamp
    memcpy(hash_input + offset, &block->timestamp, sizeof(block->timestamp));
    offset += sizeof(block->timestamp);

    // Hash transactions
    for (int i = 0; i < block->transaction_count; i++) {
        Transaction *tx = &block->transactions[i];

        memcpy(hash_input + offset, &tx->id, sizeof(tx->id));
        offset += sizeof(tx->id);

        memcpy(hash_input + offset, &tx->type, sizeof(tx->type));
        offset += sizeof(tx->type);

        size_t sender_len = strlen(tx->sender) + 1;
        memcpy(hash_input + offset, tx->sender, sender_len);
        offset += sender_len;

        size_t recipient_len = strlen(tx->recipient) + 1;
        memcpy(hash_input + offset, tx->recipient, recipient_len);
        offset += recipient_len;

        memcpy(hash_input + offset, &tx->amount, sizeof(tx->amount));
        offset += sizeof(tx->amount);

        memcpy(hash_input + offset, &tx->timestamp, sizeof(tx->timestamp));
        offset += sizeof(tx->timestamp);
    }

    // Hash previous block's hash
    memcpy(hash_input + offset, block->previous_hash, block->hash_len);
    offset += block->hash_len;

    // Hash validators' usernames
    for (int i = 0; i < block->validator_count; i++) {
        size_t validator_len = strlen(block->validators[i]) + 1;
        memcpy(hash_input + offset, block->validators[i], validator_len);
        offset += validator_len;
    }

    // Compute the hash using OpenSSL's SHA3-512
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Failed to create EVP_MD_CTX.\n");
        exit(1);
    }
    if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1) {
        printf("Failed to initialize digest context.\n");
        exit(1);
    }
    if (EVP_DigestUpdate(mdctx, hash_input, offset) != 1) {
        printf("Failed to update digest.\n");
        exit(1);
    }
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, block->hash, &hash_len) != 1) {
        printf("Failed to finalize digest.\n");
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);
    block->hash_len = hash_len;
}

// Function to print the hash in hexadecimal format
void print_hash(unsigned char *hash, unsigned int hash_len) {
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
}

// Function to create the genesis block (first block in the blockchain)
void create_genesis_block() {
    printf("create_genesis_block: Creating genesis block...\n");

    Block *genesis = (Block *)malloc(sizeof(Block));
    if (!genesis) {
        printf("Failed to create genesis block. Memory allocation error.\n");
        exit(1);
    }
    genesis->index = 0;                              // Genesis block index is 0
    genesis->timestamp = time(NULL);                 // Current timestamp
    genesis->transaction_count = 0;                  // No transactions in genesis block
    memset(genesis->previous_hash, 0, sizeof(genesis->previous_hash)); // Previous hash is zero (no previous block)
    genesis->hash_len = 0;                           // Initial hash length is zero

    // Initialize validators
    genesis->validator_count = 0;
    memset(genesis->validators, 0, sizeof(genesis->validators));
    memset(genesis->signatures, 0, sizeof(genesis->signatures));
    memset(genesis->signature_lens, 0, sizeof(genesis->signature_lens));

    compute_block_hash(genesis);                     // Compute hash of the genesis block
    genesis->next = NULL;                            // No next block yet
    blockchain = genesis;                            // Set genesis block as the head of the blockchain

    printf("create_genesis_block: Genesis block created with hash: ");
    print_hash(genesis->hash, genesis->hash_len);
    printf("\n");

    // Save the genesis block to a file
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/block_%d.dat", BLOCKS_DIR, genesis->index);
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Unable to create genesis block file.\n");
        return;
    }
    fwrite(genesis, sizeof(Block), 1, file);
    fclose(file);
}

// Function to add a block to the blockchain
void add_block_to_blockchain(Block *new_block) {
    printf("add_block_to_blockchain: Adding block index %d to blockchain.\n", new_block->index);

    // Append the new block to the blockchain
    Block *current = blockchain;
    while (current->next != NULL)
        current = current->next;
    current->next = new_block;

    // Update user balances
    for (int i = 0; i < new_block->transaction_count; i++) {
        Transaction *tx = &new_block->transactions[i];
        if (strlen(tx->sender) > 0) {
            update_user_balance(tx->sender, -tx->amount);
        }
        update_user_balance(tx->recipient, tx->amount);
    }

    // Save the new block to a file
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/block_%d.dat", BLOCKS_DIR, new_block->index);
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Unable to create block file for block index %d.\n", new_block->index);
        return;
    }
    fwrite(new_block, sizeof(Block), 1, file);
    fclose(file);
}

// Function to create a new block from pending transactions
void create_new_block() {
    if (pending_transactions == NULL)
        return;

    if (pending_block != NULL) {
        printf("A pending block already exists. Waiting for validators to sign.\n");
        return;
    }

    printf("create_new_block: Creating a new pending block...\n");

    // Select the validators
    char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
    int validator_count = 0;
    select_validators(selected_validators, &validator_count);

    // Check if the current user is among the selected validators
    int is_current_user_validator = 0;
    for (int i = 0; i < validator_count; i++) {
        if (strcmp(current_user, selected_validators[i]) == 0) {
            is_current_user_validator = 1;
            break;
        }
    }

    if (!is_current_user_validator) {
        printf("Current user '%s' is not among the selected validators. Block creation deferred.\n", current_user);
        return;
    }

    Block *new_block = (Block *)malloc(sizeof(Block));
    if (!new_block) {
        printf("Failed to create new block. Memory allocation error.\n");
        return;
    }

    // Set block index based on the last block in the blockchain
    Block *last_block = blockchain;
    while (last_block->next != NULL)
        last_block = last_block->next;
    new_block->index = last_block->index + 1;

    new_block->timestamp = time(NULL); // Set current timestamp
    new_block->transaction_count = 0;

    // Copy up to MAX_TRANSACTIONS_PER_BLOCK from pending transactions
    Transaction *current_tx = pending_transactions;
    for (int i = 0; i < MAX_TRANSACTIONS_PER_BLOCK && current_tx != NULL; i++) {
        new_block->transactions[i] = *current_tx;
        new_block->transaction_count++;
        current_tx = current_tx->next;
    }

    // Set previous hash from the last block
    memcpy(new_block->previous_hash, last_block->hash, last_block->hash_len);
    new_block->hash_len = last_block->hash_len;

    // Set validators
    new_block->validator_count = validator_count;
    for (int i = 0; i < validator_count; i++) {
        strncpy(new_block->validators[i], selected_validators[i], MAX_USERNAME_LENGTH - 1);
        new_block->validators[i][MAX_USERNAME_LENGTH - 1] = '\0';
        new_block->signature_lens[i] = 0; // Initialize signature lengths
    }

    new_block->next = NULL;

    // Compute the block hash without signatures
    compute_block_hash(new_block);

    // Set the pending block
    pending_block = new_block;

    // Save the pending block to a file
    save_pending_block();

    // Sign the pending block
    sign_pending_block(current_user);
}

// Function to save the pending block to a file
void save_pending_block() {
    if (pending_block == NULL)
        return;

    FILE *file = fopen("pending_block.dat", "wb");
    if (!file) {
        printf("Unable to save pending block.\n");
        return;
    }
    fwrite(pending_block, sizeof(Block), 1, file);
    fclose(file);
}

// Function to load the pending block from a file
void load_pending_block() {
    FILE *file = fopen("pending_block.dat", "rb");
    if (!file) {
        // No pending block saved
        pending_block = NULL;
        return;
    }

    if (pending_block == NULL) {
        pending_block = (Block *)malloc(sizeof(Block));
        if (!pending_block) {
            printf("Failed to load pending block. Memory allocation error.\n");
            fclose(file);
            return;
        }
    }

    size_t read = fread(pending_block, sizeof(Block), 1, file);
    fclose(file);
    if (read == 0) {
        free(pending_block);
        pending_block = NULL;
        printf("Failed to read pending block from file.\n");
        return;
    }
}

// Function to sign the pending block
void sign_pending_block(const char *validator_username) {
    if (pending_block == NULL) {
        printf("No pending block to sign.\n");
        return;
    }

    // Check if validator has already signed
    int validator_index = -1;
    for (int i = 0; i < pending_block->validator_count; i++) {
        if (strcmp(pending_block->validators[i], validator_username) == 0) {
            validator_index = i;
            break;
        }
    }

    if (validator_index == -1) {
        printf("User '%s' is not a validator for the pending block.\n", validator_username);
        return;
    }

    if (pending_block->signature_lens[validator_index] > 0) {
        printf("User '%s' has already signed the pending block.\n", validator_username);
        return;
    }

    // Sign the block
    sign_block(pending_block, validator_username);

    // Save the pending block after signing
    save_pending_block();

    printf("User '%s' has signed the pending block.\n", validator_username);

    // Check if all validators have signed
    int all_signed = 1;
    for (int i = 0; i < pending_block->validator_count; i++) {
        if (pending_block->signature_lens[i] == 0) {
            all_signed = 0;
            break;
        }
    }

    if (all_signed) {
        printf("All validators have signed the pending block. Finalizing block.\n");
        finalize_block();
    } else {
        printf("Waiting for other validators to sign the block.\n");
    }
}

// Function to finalize the pending block
void finalize_block() {
    // Remove the pending transactions that were included in the block
    for (int i = 0; i < pending_block->transaction_count; i++) {
        Transaction *temp = pending_transactions;
        pending_transactions = pending_transactions->next;
        free(temp);
    }

    // Add the block to the blockchain
    add_block_to_blockchain(pending_block);

    // ADD REWARD DISTRIBUTION
    // Here, we give a fixed reward to each validator of the block
    double block_reward = 10.0; // Example fixed reward
    double share = block_reward / pending_block->validator_count;
    for (int i = 0; i < pending_block->validator_count; i++) {
        update_user_balance(pending_block->validators[i], share);
        printf("Validator '%s' receives %.2f tokens for block %d.\n",
               pending_block->validators[i], share, pending_block->index);
    }

    // Remove the pending block file
    remove("pending_block.dat");

    printf("Block finalized and added to the blockchain.\n");

    // Clear the pending block
    pending_block = NULL;
}

// Function to load the blockchain from files
void load_blockchain() {
    printf("load_blockchain: Loading blockchain from files...\n");

    DIR *dir = opendir(BLOCKS_DIR);
    if (!dir) {
        printf("Blocks directory not found. Creating genesis block.\n");
        create_genesis_block();
        return;
    }

    struct dirent *entry;
    int block_indices[1000]; // Adjust size as needed
    int block_count = 0;

    // Collect block indices from filenames
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "block_", 6) == 0) {
            int index = atoi(entry->d_name + 6);
            block_indices[block_count++] = index;
        }
    }
    closedir(dir);

    if (block_count == 0) {
        printf("No blocks found in the directory. Creating genesis block.\n");
        create_genesis_block();
        return;
    }

    // Sort the block indices
    for (int i = 0; i < block_count - 1; i++) {
        for (int j = i + 1; j < block_count; j++) {
            if (block_indices[i] > block_indices[j]) {
                int temp = block_indices[i];
                block_indices[i] = block_indices[j];
                block_indices[j] = temp;
            }
        }
    }

    Block *prev_block = NULL;
    for (int i = 0; i < block_count; i++) {
        char filename[256];
        snprintf(filename, sizeof(filename), "%s/block_%d.dat", BLOCKS_DIR, block_indices[i]);
        FILE *file = fopen(filename, "rb");
        if (!file) {
            printf("Failed to open block file: %s\n", filename);
            exit(1);
        }

        Block *block = (Block *)malloc(sizeof(Block));
        if (!block) {
            printf("Failed to load block. Memory allocation error.\n");
            fclose(file);
            exit(1);
        }
        size_t read = fread(block, sizeof(Block), 1, file);
        fclose(file);
        if (read == 0) {
            free(block);
            printf("Failed to read block from file: %s\n", filename);
            exit(1);
        }
        block->next = NULL;
        if (prev_block == NULL) {
            blockchain = block; // Set as first block
        } else {
            prev_block->next = block; // Append to blockchain
        }
        prev_block = block;

        // Load public keys for validators
        load_validator_public_keys(block);

        // Verify block signatures
        if (block->index != 0) { // Skip genesis block
            if (!verify_block_signatures(block)) {
                printf("Invalid signatures for block index %d. Exiting.\n", block->index);
                exit(1);
            }
        }

        // Update user balances
        for (int j = 0; j < block->transaction_count; j++) {
            Transaction *tx = &block->transactions[j];
            if (strlen(tx->sender) > 0) {
                update_user_balance(tx->sender, -tx->amount);
            }
            update_user_balance(tx->recipient, tx->amount);
        }
    }

    printf("load_blockchain: Blockchain loaded successfully.\n");
}

// Function to load public keys for validators in a block
void load_validator_public_keys(Block *block) {
    for (int i = 0; i < block->validator_count; i++) {
        const char *validator_username = block->validators[i];

        // Check if user already exists in the users list
        User *validator_user = users;
        while (validator_user != NULL) {
            if (strcmp(validator_user->username, validator_username) == 0) {
                break;
            }
            validator_user = validator_user->next;
        }

        // If user not found, add user and load public key
        if (validator_user == NULL) {
            add_user_if_not_exists(validator_username);
        } else {
            // Ensure public key is loaded
            if (validator_user->public_key_len == 0) {
                load_user_public_key(validator_user);
            }
        }
    }
}

// Function to load a user's public key
void load_user_public_key(User *user) {
    // Get the user's home directory
    struct passwd *pwd = getpwnam(user->username);
    if (pwd == NULL) {
        printf("Failed to get home directory for user '%s'.\n", user->username);
        user->public_key_len = 0;
        return;
    }

    char public_key_filename[256];
    snprintf(public_key_filename, sizeof(public_key_filename),
             "%s/.blockchain_keys/%s_public.key", pwd->pw_dir, user->username);

    if (access(public_key_filename, F_OK) != -1) {
        // File exists, load the public key
        FILE *fp = fopen(public_key_filename, "rb");
        if (!fp) {
            printf("Failed to open public key file for user '%s'.\n", user->username);
            user->public_key_len = 0;
            return;
        }
        fseek(fp, 0, SEEK_END);
        user->public_key_len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        fread(user->public_key, 1, user->public_key_len, fp);
        fclose(fp);
        printf("Debug: Loaded public key for user '%s'.\n", user->username);
    } else {
        memset(user->public_key, 0, sizeof(user->public_key));
        user->public_key_len = 0;
        printf("Debug: Public key not found for user '%s'.\n", user->username);
    }
}

// Function to display the entire blockchain
void display_blockchain() {
    printf("display_blockchain: Displaying blockchain...\n");

    Block *current_block = blockchain;
    while (current_block != NULL) {
        printf("\nBlock Index: %d\n", current_block->index);
        printf("Timestamp: %s", ctime(&current_block->timestamp));
        printf("Validators: ");
        for (int i = 0; i < current_block->validator_count; i++) {
            printf("%s ", current_block->validators[i]);
        }
        printf("\nPrevious Hash: ");
        print_hash(current_block->previous_hash, current_block->hash_len);
        printf("\nHash: ");
        print_hash(current_block->hash, current_block->hash_len);
        printf("\nTransactions:\n");
        for (int i = 0; i < current_block->transaction_count; i++) {
            Transaction *tx = &current_block->transactions[i];
            char timestamp_str[26];
            ctime_r(&tx->timestamp, timestamp_str);
            timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

            if (strlen(tx->sender) == 0) {
                // System transaction (e.g., faucet)
                printf("  [%s] ID: %d, System -> %s, Amount: %.2f tokens\n",
                       timestamp_str, tx->id, tx->recipient, tx->amount);
            } else {
                printf("  [%s] ID: %d, From: %s, To: %s, Amount: %.2f tokens\n",
                       timestamp_str, tx->id, tx->sender, tx->recipient, tx->amount);
            }
        }

        // Print the signatures
        printf("Signatures:\n");
        for (int i = 0; i < current_block->validator_count; i++) {
            printf("Validator '%s' Signature:\n", current_block->validators[i]);
            if (current_block->signature_lens[i] == 0) {
                printf("  No signature from this validator.\n");
                continue;
            }
            for (size_t j = 0; j < current_block->signature_lens[i]; j++) {
                printf("%02x", current_block->signatures[i][j]);
                if ((j + 1) % 32 == 0) { // Print 32 bytes per line
                    printf("\n");
                }
            }
            if (current_block->signature_lens[i] % 32 != 0) {
                printf("\n");
            }
        }

        current_block = current_block->next;
    }
}

// Function to add a transaction to the pending transactions list
void add_transaction(Transaction *new_transaction) {
    printf("add_transaction: Adding a new transaction.\n");

    Transaction *current_tx = pending_transactions;
    if (current_tx == NULL) {
        pending_transactions = new_transaction;
    } else {
        while (current_tx->next != NULL)
            current_tx = current_tx->next;
        current_tx->next = new_transaction;
    }

    // Check if we have enough transactions to create a new block
    int tx_count = 0;
    current_tx = pending_transactions;
    while (current_tx != NULL) {
        tx_count++;
        current_tx = current_tx->next;
    }
    printf("add_transaction: Pending transactions count: %d\n", tx_count);

    // If pending transactions reach the threshold, display the next validators
    if (tx_count >= MAX_TRANSACTIONS_PER_BLOCK) {
        printf("add_transaction: Pending transactions have reached %d.\n", MAX_TRANSACTIONS_PER_BLOCK);
        printf("add_transaction: Selecting the next validators...\n");
        char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
        int validator_count = 0;
        select_validators(selected_validators, &validator_count);
        if (validator_count > 0) {
            printf("The next validators are: ");
            for (int i = 0; i < validator_count; i++) {
                printf("%s ", selected_validators[i]);
            }
            printf("\n");
        } else {
            printf("No validators could be selected.\n");
        }
    }
}

// PAM conversation function
int pam_conversation(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *reply = NULL;
    if (num_msg <= 0) {
        return PAM_CONV_ERR;
    }

    reply = (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
    if (reply == NULL) {
        return PAM_BUF_ERR;
    }

    for (int i = 0; i < num_msg; ++i) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            reply[i].resp = strdup((const char *)appdata_ptr);
            reply[i].resp_retcode = 0;
        } else {
            free(reply);
            return PAM_CONV_ERR;
        }
    }

    *resp = reply;
    return PAM_SUCCESS;
}

// Function to handle user login using PAM
void user_login() {
    printf("user_login: Starting login process.\n");

    char username[MAX_USERNAME_LENGTH];
    char *password;
    pam_handle_t *pamh = NULL;
    int retval;

    // Get the username
    printf("Enter username: ");
    scanf("%99s", username);

    // Ensure keys are generated before login
    printf("Debug: Ensuring keys are generated for '%s'.\n", username);
    generate_keys_for_user(username);

    // Get the password securely
    password = getpass("Enter password: ");

    // Set up PAM conversation
    struct pam_conv conv = {
        pam_conversation,
        password
    };

    // Start PAM authentication
    retval = pam_start("login", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        printf("pam_start failed: %s\n", pam_strerror(pamh, retval));
        return;
    }

    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        printf("Authentication failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return;
    }

    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        printf("Account management failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return;
    }

    // Authentication successful
    pam_end(pamh, PAM_SUCCESS);

    // Clear password from memory
    memset(password, 0, strlen(password));

    // Add user to the users list if not already present
    add_user_if_not_exists(username);

    // Ensure the public key is loaded
    User *current_user_ptr = users;
    while (current_user_ptr != NULL) {
        if (strcmp(current_user_ptr->username, username) == 0) {
            if (current_user_ptr->public_key_len == 0) {
                load_user_public_key(current_user_ptr);
            }
            break;
        }
        current_user_ptr = current_user_ptr->next;
    }

    // Set current user role
    if (is_user_in_blockusers_group(username)) {
        strcpy(current_role, "blockuser");
        printf("Blockuser login successful!\n");
    } else {
        strcpy(current_role, "user");
        printf("User login successful!\n");
    }

    // Update current_user
    strncpy(current_user, username, sizeof(current_user) - 1);
    current_user[sizeof(current_user) - 1] = '\0';

    printf("Welcome, %s!\n", username);

    // Load pending block if any
    load_pending_block();

    // Log the login event
    char event_description[256];
    snprintf(event_description, sizeof(event_description), "User '%s' logged in.", username);
    log_event(event_description);
}

// Function to generate keys for a user (using Dilithium2)
void generate_keys_for_user(const char *username) {
    char private_key_filename[256];
    char public_key_filename[256];

    // Get the user's home directory
    struct passwd *pwd = getpwnam(username);
    if (pwd == NULL) {
        printf("Failed to get home directory for user '%s'.\n", username);
        exit(1);
    }

    // Ensure the keys directory exists in the user's home directory
    char keys_dir[512];
    snprintf(keys_dir, sizeof(keys_dir), "%s/.blockchain_keys", pwd->pw_dir);
    struct stat st = {0};
    if (stat(keys_dir, &st) == -1) {
        if (mkdir(keys_dir, 0700) != 0) {
            printf("Failed to create keys directory '%s' for user '%s'.\n", keys_dir, username);
            exit(1);
        }
    }

    snprintf(private_key_filename, sizeof(private_key_filename), "%s/%s_private.key", keys_dir, username);
    snprintf(public_key_filename, sizeof(public_key_filename), "%s/%s_public.key", keys_dir, username);

    // Debugging: Print the key filenames
    printf("Debug: Generating keys for user '%s'.\n", username);
    printf("Debug: Private key path: %s\n", private_key_filename);
    printf("Debug: Public key path: %s\n", public_key_filename);

    // Check if keys already exist
    if (access(private_key_filename, F_OK) != -1 && access(public_key_filename, F_OK) != -1) {
        printf("Keys already exist for user '%s'.\n", username);
        return;
    }

    printf("Debug: Keys do not exist for '%s'. Generating keys.\n", username);

    // Initialize the signature object
    OQS_SIG *sig = OQS_SIG_new("Dilithium2");
    if (sig == NULL) {
        printf("Failed to initialize Dilithium2 signature object.\n");
        exit(1);
    }

    // Allocate memory for keys
    unsigned char *public_key = malloc(sig->length_public_key);
    unsigned char *private_key = malloc(sig->length_secret_key);

    // Generate key pair
    if (OQS_SIG_keypair(sig, public_key, private_key) != OQS_SUCCESS) {
        printf("Failed to generate key pair for user '%s'.\n", username);
        exit(1);
    }

    // Save keys to files
    FILE *fp = fopen(private_key_filename, "wb");
    if (!fp) {
        printf("Failed to save private key for user '%s'.\n", username);
        printf("Debug: Check file permissions and directory existence.\n");
        exit(1);
    }
    fwrite(private_key, 1, sig->length_secret_key, fp);
    fclose(fp);

    // Set file permissions to owner read/write only
    chmod(private_key_filename, 0600);

    fp = fopen(public_key_filename, "wb");
    if (!fp) {
        printf("Failed to save public key for user '%s'.\n", username);
        printf("Debug: Check file permissions and directory existence.\n");
        exit(1);
    }
    fwrite(public_key, 1, sig->length_public_key, fp);
    fclose(fp);

    // Set file permissions to owner read/write and group/others read
    chmod(public_key_filename, 0644);

    printf("Generated Dilithium2 keys for user '%s'.\n", username);

    // Clean up
    OQS_SIG_free(sig);
    free(public_key);
    free(private_key);
}

// Function to add users from blockusers group to the users list
void load_blockusers_into_users() {
    printf("load_blockusers_into_users: Loading blockusers into users list.\n");

    struct passwd *pwd;
    setpwent();
    while ((pwd = getpwent()) != NULL) {
        if (is_user_in_blockusers_group(pwd->pw_name)) {
            add_user_if_not_exists(pwd->pw_name);
        }
    }
    endpwent();
}

// Function to add a user to the users list if not already present
void add_user_if_not_exists(const char *username) {
    printf("Debug: Checking if user '%s' exists in users list.\n", username);

    User *current_user_ptr = users;
    while (current_user_ptr != NULL) {
        if (strcmp(current_user_ptr->username, username) == 0) {
            // User already exists
            printf("Debug: User '%s' already exists in users list.\n", username);
            return;
        }
        current_user_ptr = current_user_ptr->next;
    }

    printf("Debug: Adding new user '%s' to users list.\n", username);

    // Add new user
    User *new_user = (User *)malloc(sizeof(User));
    strncpy(new_user->username, username, MAX_USERNAME_LENGTH - 1);
    new_user->username[MAX_USERNAME_LENGTH - 1] = '\0';
    new_user->balance = 0.0;
    // Initialize stake to 0
    new_user->stake = 0.0;
    // Load public key
    load_user_public_key(new_user);

    new_user->next = users;
    users = new_user;
}

// ADDED: Function to find a user by username
User *find_user(const char *username) {
    User *u = users;
    while (u != NULL) {
        if (strcmp(u->username, username) == 0) {
            return u;
        }
        u = u->next;
    }
    return NULL;
}

// Function to handle user logout
void user_logout() {
    printf("user_logout: Logging out user '%s'.\n", current_user);

    if (strlen(current_user) == 0) {
        printf("No user is currently logged in.\n");
        return;
    }

    // Log the logout event
    char event_description[256];
    snprintf(event_description, sizeof(event_description), "User '%s' logged out.", current_user);
    log_event(event_description);

    // Clear current_user and current_role
    printf("User %s has been logged out successfully.\n", current_user);
    current_user[0] = '\0';
    current_role[0] = '\0';
}

// Function to send a transaction
void send_transaction() {
    printf("send_transaction: User '%s' initiating a transaction.\n", current_user);

    if (strlen(current_user) == 0) {
        printf("No user is currently logged in. Please log in to send a transaction.\n");
        return;
    }

    char recipient[MAX_RECIPIENT_LENGTH];
    double amount;

    printf("Enter recipient username: ");
    scanf("%99s", recipient);

    printf("Enter amount to send (tokens): ");
    if (scanf("%lf", &amount) != 1) {
        printf("Invalid input. Transaction cancelled.\n");
        while (getchar() != '\n'); // Clear input buffer
        return;
    }

    if (amount <= 0) {
        printf("Invalid amount. Please enter a positive value.\n");
        return;
    }

    // Check if sender has sufficient balance
    double sender_balance = get_user_balance(current_user);
    if (amount > sender_balance) {
        printf("Insufficient balance. Your balance is %.2f tokens. Transaction cancelled.\n", sender_balance);
        return;
    }

    // Add recipient to the users list if not already present
    add_user_if_not_exists(recipient);

    Transaction *new_transaction = (Transaction *)malloc(sizeof(Transaction));
    if (!new_transaction) {
        printf("Failed to create transaction. Memory allocation error.\n");
        return;
    }

    new_transaction->id = ++last_transaction_id;
    new_transaction->type = TRANSACTION_NORMAL;
    strncpy(new_transaction->sender, current_user, MAX_USERNAME_LENGTH - 1);
    new_transaction->sender[MAX_USERNAME_LENGTH - 1] = '\0';

    strncpy(new_transaction->recipient, recipient, MAX_RECIPIENT_LENGTH - 1);
    new_transaction->recipient[MAX_RECIPIENT_LENGTH - 1] = '\0';

    new_transaction->amount = amount;
    new_transaction->timestamp = time(NULL);
    new_transaction->next = NULL;

    // Add transaction to pending transactions
    add_transaction(new_transaction);

    printf("Transaction from '%s' to '%s' for amount %.2f tokens has been created with ID %d.\n",
           current_user, recipient, amount, new_transaction->id);
}

// Function to view the current user's transaction history
void view_transactions() {
    printf("view_transactions: Displaying transactions for user '%s'.\n", current_user);

    if (strlen(current_user) == 0) {
        printf("No user is currently logged in.\n");
        return;
    }

    int found = 0;
    Block *current_block = blockchain;
    while (current_block != NULL) {
        for (int i = 0; i < current_block->transaction_count; i++) {
            Transaction *tx = &current_block->transactions[i];
            if (strcmp(tx->sender, current_user) == 0 || strcmp(tx->recipient, current_user) == 0) {
                char timestamp_str[26];
                ctime_r(&tx->timestamp, timestamp_str);
                timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

                if (strlen(tx->sender) == 0) {
                    // System transaction
                    printf("[%s] ID: %d, System -> %s, Amount: %.2f tokens\n",
                           timestamp_str, tx->id, tx->recipient, tx->amount);
                } else {
                    printf("[%s] ID: %d, From: %s, To: %s, Amount: %.2f tokens\n",
                           timestamp_str, tx->id, tx->sender, tx->recipient, tx->amount);
                }
                found = 1;
            }
        }
        current_block = current_block->next;
    }

    // Also check pending transactions
    Transaction *current_tx = pending_transactions;
    while (current_tx != NULL) {
        if (strcmp(current_tx->sender, current_user) == 0 || strcmp(current_tx->recipient, current_user) == 0) {
            char timestamp_str[26];
            ctime_r(&current_tx->timestamp, timestamp_str);
            timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

            if (strlen(current_tx->sender) == 0) {
                // System transaction
                printf("[%s] ID: %d, System -> %s, Amount: %.2f tokens (Pending)\n",
                       timestamp_str, current_tx->id, current_tx->recipient, current_tx->amount);
            } else {
                printf("[%s] ID: %d, From: %s, To: %s, Amount: %.2f tokens (Pending)\n",
                       timestamp_str, current_tx->id, current_tx->sender, current_tx->recipient, current_tx->amount);
            }
            found = 1;
        }
        current_tx = current_tx->next;
    }

    if (!found) {
        printf("No transactions found for user %s.\n", current_user);
    }
}

// Function to view all transactions
void view_all_transactions() {
    printf("view_all_transactions: Displaying all transactions.\n");

    Block *current_block = blockchain;
    printf("\n--- All Transactions ---\n");
    while (current_block != NULL) {
        for (int i = 0; i < current_block->transaction_count; i++) {
            Transaction *tx = &current_block->transactions[i];
            char timestamp_str[26];
            ctime_r(&tx->timestamp, timestamp_str);
            timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

            if (strlen(tx->sender) == 0) {
                // System transaction
                printf("[%s] ID: %d, System -> %s, Amount: %.2f tokens\n",
                       timestamp_str, tx->id, tx->recipient, tx->amount);
            } else {
                printf("[%s] ID: %d, From: %s, To: %s, Amount: %.2f tokens\n",
                       timestamp_str, tx->id, tx->sender, tx->recipient, tx->amount);
            }
        }
        current_block = current_block->next;
    }

    // Also display pending transactions
    Transaction *current_tx = pending_transactions;
    while (current_tx != NULL) {
        char timestamp_str[26];
        ctime_r(&current_tx->timestamp, timestamp_str);
        timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

        if (strlen(current_tx->sender) == 0) {
            // System transaction
            printf("[%s] ID: %d, System -> %s, Amount: %.2f tokens (Pending)\n",
                   timestamp_str, current_tx->id, current_tx->recipient, current_tx->amount);
        } else {
            printf("[%s] ID: %d, From: %s, To: %s, Amount: %.2f tokens (Pending)\n",
                   timestamp_str, current_tx->id, current_tx->sender, current_tx->recipient, current_tx->amount);
        }
        current_tx = current_tx->next;
    }
}

// Function to view pending transactions
void view_pending_transactions() {
    printf("view_pending_transactions: Displaying pending transactions.\n");

    if (pending_transactions == NULL) {
        printf("There are no pending transactions at the moment.\n");
        return;
    }

    Transaction *current_tx = pending_transactions;
    printf("\n--- Pending Transactions ---\n");
    while (current_tx != NULL) {
        char timestamp_str[26];
        ctime_r(&current_tx->timestamp, timestamp_str);
        timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

        if (strlen(current_tx->sender) == 0) {
            // System transaction
            printf("[%s] ID: %d, System -> %s, Amount: %.2f tokens\n",
                   timestamp_str, current_tx->id, current_tx->recipient, current_tx->amount);
        } else {
            printf("[%s] ID: %d, From: %s, To: %s, Amount: %.2f tokens\n",
                   timestamp_str, current_tx->id, current_tx->sender, current_tx->recipient, current_tx->amount);
        }

        current_tx = current_tx->next;
    }
}

// Function to cancel a pending transaction
void cancel_pending_transaction() {
    printf("cancel_pending_transaction: Cancelling a pending transaction.\n");

    if (pending_transactions == NULL) {
        printf("There are no pending transactions to cancel.\n");
        return;
    }

    int transaction_id;
    printf("Enter the Transaction ID to cancel: ");
    if (scanf("%d", &transaction_id) != 1) {
        printf("Invalid input.\n");
        while (getchar() != '\n'); // Clear input buffer
        return;
    }

    Transaction *current_tx = pending_transactions;
    Transaction *prev_tx = NULL;
    while (current_tx != NULL) {
        if (current_tx->id == transaction_id && strcmp(current_tx->sender, current_user) == 0) {
            // Found the transaction
            if (prev_tx == NULL) {
                // It's the first transaction in the list
                pending_transactions = current_tx->next;
            } else {
                prev_tx->next = current_tx->next;
            }
            free(current_tx);
            printf("Transaction ID %d has been cancelled.\n", transaction_id);
            return;
        }
        prev_tx = current_tx;
        current_tx = current_tx->next;
    }

    printf("Transaction ID %d not found or you are not authorized to cancel it.\n", transaction_id);
}

// Function to update user balance
void update_user_balance(const char *username, double amount) {
    User *current_user_ptr = users;
    while (current_user_ptr != NULL) {
        if (strcmp(current_user_ptr->username, username) == 0) {
            current_user_ptr->balance += amount;
            return;
        }
        current_user_ptr = current_user_ptr->next;
    }
    // User not found, add new user
    add_user_if_not_exists(username);
    update_user_balance(username, amount);
}

// Function to get user balance
double get_user_balance(const char *username) {
    User *current_user_ptr = users;
    while (current_user_ptr != NULL) {
        if (strcmp(current_user_ptr->username, username) == 0) {
            return current_user_ptr->balance;
        }
        current_user_ptr = current_user_ptr->next;
    }
    return 0.0;
}

// Function to request test tokens (now updates balance directly)
void request_test_funds() {
    printf("request_test_funds: User '%s' requesting test tokens.\n", current_user);

    if (strlen(current_user) == 0) {
        printf("No user is currently logged in. Please log in to request test tokens.\n");
        return;
    }

    double amount = 1000.0; // Amount of test tokens to grant

    // Update user balance directly
    update_user_balance(current_user, amount);

    // Log the event
    char event_description[256];
    snprintf(event_description, sizeof(event_description),
             "Test tokens of amount %.2f have been credited to '%s'.",
             amount, current_user);
    log_event(event_description);

    printf("Test tokens of amount %.2f have been credited to '%s'.\n",
           amount, current_user);
}

// Function to log events (login/logout) to a file
void log_event(const char *event_description) {
    FILE *file = fopen(TRANSACTION_LOG_FILE, "a");
    if (!file) {
        printf("Unable to open transaction log file.\n");
        return;
    }
    time_t now = time(NULL);
    char timestamp_str[26];
    ctime_r(&now, timestamp_str);
    timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline
    fprintf(file, "[%s] %s\n", timestamp_str, event_description);
    fclose(file);
}

// Function to clean up the blockchain (free memory)
void cleanup_blockchain() {
    printf("cleanup_blockchain: Cleaning up blockchain...\n");

    Block *current = blockchain;
    while (current) {
        Block *temp = current;
        current = current->next;
        free(temp);
    }
    blockchain = NULL;
}

// Function to clean up pending transactions (free memory)
void cleanup_pending_transactions() {
    printf("cleanup_pending_transactions: Cleaning up pending transactions...\n");

    Transaction *current = pending_transactions;
    while (current) {
        Transaction *temp = current;
        current = current->next;
        free(temp);
    }
    pending_transactions = NULL;
}

// Function to clean up users (free memory)
void cleanup_users() {
    printf("cleanup_users: Cleaning up user list...\n");

    User *current = users;
    while (current) {
        User *temp = current;
        current = current->next;
        free(temp);
    }
    users = NULL;
}

// Function to handle program exit and cleanup
void cleanup_and_exit(int signum) {
    printf("\nProgram terminated. Cleaning up and saving data.\n");

    // Log the logout event if user is logged in
    if (strlen(current_user) > 0) {
        user_logout();
    }

    cleanup_pending_transactions();
    cleanup_blockchain();
    cleanup_users();
    exit(0);
}

// Function to compute a hash-based random value (simulating a VRF)
double compute_vrf(const char *username, int round) {
    unsigned char hash_output[SHA256_DIGEST_LENGTH];
    char input[256];
    snprintf(input, sizeof(input), "%s-%d", username, round);
    SHA256((unsigned char*)input, strlen(input), hash_output);
    // Convert the hash output to a double between 0 and 1
    unsigned int random_value = *(unsigned int*)hash_output;
    return (double)random_value / (double)UINT_MAX;
}

// Function to select validators for the next block
void select_validators(char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH], int *validator_count) {
    printf("select_validators: Selecting validators for the next block.\n");

    double highest_scores[MAX_VALIDATORS_PER_BLOCK];
    char highest_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
    for (int i = 0; i < MAX_VALIDATORS_PER_BLOCK; i++) {
        highest_scores[i] = -1.0;
        highest_validators[i][0] = '\0';
    }

    User *current_user_ptr = users;
    int round = blockchain->index + 1; // Use the next block index as the round number

    while (current_user_ptr != NULL) {
        // Only consider users in the "blockusers" group
        if (!is_user_in_blockusers_group(current_user_ptr->username)) {
            current_user_ptr = current_user_ptr->next;
            continue;
        }

        // Skip users with zero stake
        if (current_user_ptr->stake <= 0.0) {
            current_user_ptr = current_user_ptr->next;
            continue;
        }

        double vrf_output = compute_vrf(current_user_ptr->username, round);
        // Incorporate stake into final score
        double score = vrf_output * current_user_ptr->stake;

        // Check if this user's score is among the highest
        for (int i = 0; i < MAX_VALIDATORS_PER_BLOCK; i++) {
            if (score > highest_scores[i]) {
                // Shift lower scores down
                for (int j = MAX_VALIDATORS_PER_BLOCK - 1; j > i; j--) {
                    highest_scores[j] = highest_scores[j - 1];
                    strncpy(highest_validators[j], highest_validators[j - 1], MAX_USERNAME_LENGTH);
                }
                highest_scores[i] = score;
                strncpy(highest_validators[i], current_user_ptr->username, MAX_USERNAME_LENGTH);
                break;
            }
        }

        current_user_ptr = current_user_ptr->next;
    }

    // Set the selected validators
    *validator_count = 0;
    for (int i = 0; i < MAX_VALIDATORS_PER_BLOCK; i++) {
        if (highest_validators[i][0] != '\0') {
            strncpy(selected_validators[*validator_count], highest_validators[i], MAX_USERNAME_LENGTH);
            (*validator_count)++;
        }
    }

    printf("Validators selected: ");
    for (int i = 0; i < *validator_count; i++) {
        printf("%s ", selected_validators[i]);
    }
    printf("\n");
}

// Function to check validator status and create block
void check_and_create_block() {
    printf("check_and_create_block: Checking validator status for user '%s'.\n", current_user);

    // Load pending block if any
    load_pending_block();

    if (pending_block != NULL) {
        // Check if current user is a validator and hasn't signed
        int is_validator = 0;
        int already_signed = 0;
        for (int i = 0; i < pending_block->validator_count; i++) {
            if (strcmp(pending_block->validators[i], current_user) == 0) {
                is_validator = 1;
                if (pending_block->signature_lens[i] > 0) {
                    already_signed = 1;
                }
                break;
            }
        }

        if (is_validator) {
            if (!already_signed) {
                sign_pending_block(current_user);
            } else {
                printf("You have already signed the pending block. Waiting for others.\n");
            }
        } else {
            printf("You are not a validator for the pending block.\n");
        }
    } else {
        // No pending block, check if enough transactions to create a new block
        int tx_count = 0;
        Transaction *current_tx = pending_transactions;
        while (current_tx != NULL) {
            tx_count++;
            current_tx = current_tx->next;
        }
        if (tx_count < MAX_TRANSACTIONS_PER_BLOCK) {
            printf("Not enough pending transactions to create a block. Need at least %d.\n", MAX_TRANSACTIONS_PER_BLOCK);
            return;
        }

        // Attempt to create a new block
        create_new_block();
    }
}

// Function to sign a block with Dilithium2
void sign_block(Block *block, const char *validator_username) {
    // Check if validator_username is among the block's validators
    int is_validator = 0;
    int validator_index = -1;
    for (int i = 0; i < block->validator_count; i++) {
        if (strcmp(block->validators[i], validator_username) == 0) {
            is_validator = 1;
            validator_index = i;
            break;
        }
    }
    if (!is_validator) {
        printf("User '%s' is not a validator for this block.\n", validator_username);
        return;
    }

    // Get the validator's home directory
    struct passwd *pwd = getpwnam(validator_username);
    if (pwd == NULL) {
        printf("Failed to get home directory for validator '%s'.\n", validator_username);
        exit(1);
    }

    char private_key_filename[256];
    snprintf(private_key_filename, sizeof(private_key_filename),
             "%s/.blockchain_keys/%s_private.key", pwd->pw_dir, validator_username);

    // Load the private key
    FILE *fp = fopen(private_key_filename, "rb");
    if (!fp) {
        printf("Failed to open private key file for validator '%s'.\n", validator_username);
        exit(1);
    }

    // Initialize the signature object
    OQS_SIG *sig = OQS_SIG_new("Dilithium2");
    if (sig == NULL) {
        printf("Failed to initialize Dilithium2 signature object.\n");
        exit(1);
    }

    unsigned char *private_key = malloc(sig->length_secret_key);
    if (fread(private_key, 1, sig->length_secret_key, fp) != sig->length_secret_key) {
        printf("Failed to read private key for validator '%s'.\n", validator_username);
        fclose(fp);
        OQS_SIG_free(sig);
        free(private_key);
        exit(1);
    }
    fclose(fp);

    // Serialize the block data (excluding the signatures)
    unsigned char block_data[8192];
    size_t block_data_len = 0;

    // Include block fields in block_data
    // Exclude signatures to avoid circular dependency
    memcpy(block_data + block_data_len, &block->index, sizeof(block->index));
    block_data_len += sizeof(block->index);

    memcpy(block_data + block_data_len, &block->timestamp, sizeof(block->timestamp));
    block_data_len += sizeof(block->timestamp);

    memcpy(block_data + block_data_len, block->transactions,
           sizeof(Transaction) * block->transaction_count);
    block_data_len += sizeof(Transaction) * block->transaction_count;

    memcpy(block_data + block_data_len, block->previous_hash, block->hash_len);
    block_data_len += block->hash_len;

    memcpy(block_data + block_data_len, block->hash, block->hash_len);
    block_data_len += block->hash_len;

    // Include validators' usernames
    for (int i = 0; i < block->validator_count; i++) {
        size_t validator_len = strlen(block->validators[i]) + 1;
        memcpy(block_data + block_data_len, block->validators[i], validator_len);
        block_data_len += validator_len;
    }

    // Sign the block data
    if (OQS_SIG_sign(sig, block->signatures[validator_index], &block->signature_lens[validator_index],
                     block_data, block_data_len, private_key) != OQS_SUCCESS) {
        printf("Failed to sign the block.\n");
        OQS_SIG_free(sig);
        free(private_key);
        exit(1);
    }

    printf("Block signed by validator '%s' using Dilithium2.\n", validator_username);

    // Clean up
    OQS_SIG_free(sig);
    free(private_key);
}

// Function to verify a block's signatures
int verify_block_signatures(Block *block) {
    int all_valid = 1;

    // Initialize the signature object
    OQS_SIG *sig = OQS_SIG_new("Dilithium2");
    if (sig == NULL) {
        printf("Failed to initialize Dilithium2 signature object.\n");
        exit(1);
    }

    // Serialize the block data (excluding the signatures)
    unsigned char block_data[8192];
    size_t block_data_len = 0;

    // Include block fields in block_data
    memcpy(block_data + block_data_len, &block->index, sizeof(block->index));
    block_data_len += sizeof(block->index);

    memcpy(block_data + block_data_len, &block->timestamp, sizeof(block->timestamp));
    block_data_len += sizeof(block->timestamp);

    memcpy(block_data + block_data_len, block->transactions,
           sizeof(Transaction) * block->transaction_count);
    block_data_len += sizeof(Transaction) * block->transaction_count;

    memcpy(block_data + block_data_len, block->previous_hash, block->hash_len);
    block_data_len += block->hash_len;

    memcpy(block_data + block_data_len, block->hash, block->hash_len);
    block_data_len += block->hash_len;

    // Include validators' usernames
    for (int i = 0; i < block->validator_count; i++) {
        size_t validator_len = strlen(block->validators[i]) + 1;
        memcpy(block_data + block_data_len, block->validators[i], validator_len);
        block_data_len += validator_len;
    }

    for (int i = 0; i < block->validator_count; i++) {
        // Find the validator's public key
        User *validator_user = users;
        while (validator_user != NULL) {
            if (strcmp(validator_user->username, block->validators[i]) == 0) {
                break;
            }
            validator_user = validator_user->next;
        }

        if (validator_user == NULL) {
            printf("Validator '%s' not found in user list.\n", block->validators[i]);
            all_valid = 0;
            continue;
        }

        if (validator_user->public_key_len == 0) {
            printf("Public key for validator '%s' not loaded.\n", block->validators[i]);
            all_valid = 0;
            continue;
        }

        // Verify the signature
        int result = OQS_SIG_verify(sig, block_data, block_data_len,
                                    block->signatures[i], block->signature_lens[i],
                                    validator_user->public_key) == OQS_SUCCESS;

        if (result) {
            printf("Block index %d signature verified successfully for validator '%s'.\n",
                   block->index, block->validators[i]);
        } else {
            printf("Block index %d signature verification failed for validator '%s'.\n",
                   block->index, block->validators[i]);
            all_valid = 0;
        }
    }

    // Clean up
    OQS_SIG_free(sig);

    return all_valid;
}

// Function to display a block's signatures and hash in hexadecimal format
void print_block_signature(Block *block) {
    printf("Block %d Signatures:\n", block->index);

    // Print the signatures from all validators
    for (int i = 0; i < block->validator_count; i++) {
        printf("Validator '%s' Signature:\n", block->validators[i]);

        if (block->signature_lens[i] == 0) {
            printf("No signature from this validator.\n");
            continue;
        }

        for (size_t j = 0; j < block->signature_lens[i]; j++) {
            printf("%02x", block->signatures[i][j]);
            if ((j + 1) % 32 == 0) {
                printf("\n");
            }
        }
        if (block->signature_lens[i] % 32 != 0) {
            printf("\n");
        }
    }

    // Print the block's hash to demonstrate linkage
    printf("Block %d Hash:\n", block->index);
    for (unsigned int i = 0; i < block->hash_len; i++) {
        printf("%02x", block->hash[i]);
    }
    printf("\n");

    // Verify the signatures and display the result
    if (verify_block_signatures(block)) {
        printf("All signatures are valid and tied to the block hash.\n");
    } else {
        printf("Some signatures failed verification. The block may have been tampered with.\n");
    }
}

// Function to display Dilithium2 signatures for a specific block
void display_dilithium2_signature_for_block(int block_index) {
    Block *current_block = blockchain;

    while (current_block != NULL) {
        if (current_block->index == block_index) {
            print_block_signature(current_block);
            return;
        }
        current_block = current_block->next;
    }

    printf("Block with index %d not found in the blockchain.\n", block_index);
}

// ADDED: Function to stake tokens
void stake_tokens(const char *username, double amount) {
    if (amount <= 0) {
        printf("Amount to stake must be positive.\n");
        return;
    }

    User *u = find_user(username);
    if (!u) {
        // In practice, you'd add the user, but it should exist if logged in
        add_user_if_not_exists(username);
        u = find_user(username);
    }

    // Check balance
    if (u->balance < amount) {
        printf("Insufficient balance to stake.\n");
        return;
    }

    // Transfer from balance to stake
    u->balance -= amount;
    u->stake   += amount;
    printf("You have staked %.2f tokens. New stake: %.2f\n", amount, u->stake);
}

// ADDED: Function to unstake tokens
void unstake_tokens(const char *username, double amount) {
    if (amount <= 0) {
        printf("Amount to unstake must be positive.\n");
        return;
    }

    User *u = find_user(username);
    if (!u) {
        printf("User not found.\n");
        return;
    }

    if (u->stake < amount) {
        printf("Insufficient staked tokens.\n");
        return;
    }

    // Transfer from stake back to balance
    u->stake   -= amount;
    u->balance += amount;
    printf("You have unstaked %.2f tokens. Remaining stake: %.2f\n", amount, u->stake);
}
