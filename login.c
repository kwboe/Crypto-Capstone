#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <shadow.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/file.h>
#include <openssl/evp.h>

#define MAX_USERNAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 100
#define MAX_RECIPIENT_LENGTH 100
#define ACTIVE_USERS_FILE "active_users.log"
#define BLOCKUSERS_FILE "blockusers.txt"
#define BLOCKCHAIN_FILE "blockchain.dat"
#define MAX_TRANSACTIONS_PER_BLOCK 5

// Global variable to store the currently logged-in user
char current_user[MAX_USERNAME_LENGTH] = "";
char current_role[20] = ""; // user role: user, validator, blockuser

// Global variable to track if cleanup is needed
int cleanup_needed = 0;

// Transaction structure
typedef struct Transaction {
    char sender[MAX_USERNAME_LENGTH];
    char recipient[MAX_RECIPIENT_LENGTH];
    double amount;
    time_t timestamp;
    struct Transaction *next;
} Transaction;

// Block structure
typedef struct Block {
    int index;
    time_t timestamp;
    Transaction transactions[MAX_TRANSACTIONS_PER_BLOCK];
    int transaction_count;
    unsigned char previous_hash[EVP_MAX_MD_SIZE];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    struct Block *next;
} Block;

// Head of the blockchain
Block *blockchain = NULL;

// Head of the pending transactions list
Transaction *pending_transactions = NULL;

// Function prototypes
int is_user_in_group(const char *username, const char *groupname);
void add_user_to_blockusers(const char *username);
int is_user_blocked(const char *username);

// Function to print the hash in hexadecimal
void print_hash(unsigned char *hash, unsigned int hash_len) {
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
}

// Function to compute the SHA-256 hash of a block using EVP API
void compute_block_hash(Block *block) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Failed to create hash context\n");
        return;
    }

    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);

    // Hash block index
    EVP_DigestUpdate(mdctx, &block->index, sizeof(block->index));

    // Hash block timestamp
    EVP_DigestUpdate(mdctx, &block->timestamp, sizeof(block->timestamp));

    // Hash transactions
    for (int i = 0; i < block->transaction_count; i++) {
        Transaction *tx = &block->transactions[i];
        EVP_DigestUpdate(mdctx, tx->sender, strlen(tx->sender));
        EVP_DigestUpdate(mdctx, tx->recipient, strlen(tx->recipient));
        EVP_DigestUpdate(mdctx, &tx->amount, sizeof(tx->amount));
        EVP_DigestUpdate(mdctx, &tx->timestamp, sizeof(tx->timestamp));
    }

    // Hash previous block hash
    EVP_DigestUpdate(mdctx, block->previous_hash, block->hash_len);

    // Finalize the hash
    EVP_DigestFinal_ex(mdctx, block->hash, &block->hash_len);
    EVP_MD_CTX_free(mdctx);
}

// Function to create the genesis block
void create_genesis_block() {
    Block *genesis = (Block *)malloc(sizeof(Block));
    if (!genesis) {
        printf("Failed to create genesis block. Memory allocation error.\n");
        exit(1);
    }
    genesis->index = 0;
    genesis->timestamp = time(NULL);
    genesis->transaction_count = 0;
    memset(genesis->previous_hash, 0, EVP_MAX_MD_SIZE);
    compute_block_hash(genesis);
    genesis->next = NULL;
    blockchain = genesis;
}

// Function to add a block to the blockchain
void add_block_to_blockchain(Block *new_block) {
    // Compute hash of the new block
    compute_block_hash(new_block);

    // Add block to the blockchain
    Block *current = blockchain;
    while (current->next != NULL)
        current = current->next;
    current->next = new_block;
}

// Function to create a new block from pending transactions
void create_new_block() {
    if (pending_transactions == NULL)
        return;

    Block *new_block = (Block *)malloc(sizeof(Block));
    if (!new_block) {
        printf("Failed to create new block. Memory allocation error.\n");
        return;
    }

    // Set block index
    Block *last_block = blockchain;
    while (last_block->next != NULL)
        last_block = last_block->next;
    new_block->index = last_block->index + 1;

    new_block->timestamp = time(NULL);
    new_block->transaction_count = 0;

    // Copy up to MAX_TRANSACTIONS_PER_BLOCK from pending_transactions
    Transaction *current_tx = pending_transactions;
    for (int i = 0; i < MAX_TRANSACTIONS_PER_BLOCK && current_tx != NULL; i++) {
        new_block->transactions[i] = *current_tx;
        new_block->transaction_count++;
        current_tx = current_tx->next;
    }

    // Remove the transactions that have been added to the block
    for (int i = 0; i < new_block->transaction_count; i++) {
        Transaction *temp = pending_transactions;
        pending_transactions = pending_transactions->next;
        free(temp);
    }

    // Set previous hash
    memcpy(new_block->previous_hash, last_block->hash, last_block->hash_len);
    new_block->hash_len = last_block->hash_len;

    new_block->next = NULL;

    // Add block to the blockchain
    add_block_to_blockchain(new_block);

    // Save blockchain to file
    FILE *file = fopen(BLOCKCHAIN_FILE, "wb");
    if (!file) {
        printf("Unable to open blockchain file for writing.\n");
        return;
    }
    Block *current_block = blockchain;
    while (current_block != NULL) {
        fwrite(current_block, sizeof(Block), 1, file);
        current_block = current_block->next;
    }
    fclose(file);
}

// Function to load the blockchain from file
void load_blockchain() {
    FILE *file = fopen(BLOCKCHAIN_FILE, "rb");
    if (!file) {
        // No blockchain file exists, create genesis block
        create_genesis_block();
        return;
    }

    Block *prev_block = NULL;
    while (1) {
        Block *block = (Block *)malloc(sizeof(Block));
        if (!block) {
            printf("Failed to load block. Memory allocation error.\n");
            fclose(file);
            exit(1);
        }
        size_t read = fread(block, sizeof(Block), 1, file);
        if (read == 0) {
            free(block);
            break;
        }
        block->next = NULL;
        if (prev_block == NULL) {
            blockchain = block;
        } else {
            prev_block->next = block;
        }
        prev_block = block;
    }
    fclose(file);
}

// Function to display the entire blockchain
void display_blockchain() {
    Block *current_block = blockchain;
    while (current_block != NULL) {
        printf("\nBlock Index: %d\n", current_block->index);
        printf("Timestamp: %s", ctime(&current_block->timestamp));
        printf("Previous Hash: ");
        print_hash(current_block->previous_hash, current_block->hash_len);
        printf("\nHash: ");
        print_hash(current_block->hash, current_block->hash_len);
        printf("\nTransactions:\n");
        for (int i = 0; i < current_block->transaction_count; i++) {
            Transaction *tx = &current_block->transactions[i];
            printf("  [%s] From: %s, To: %s, Amount: %.2f\n",
                   ctime(&tx->timestamp), tx->sender, tx->recipient, tx->amount);
        }
        current_block = current_block->next;
    }
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

// Function to add a user to blockusers.txt
void add_user_to_blockusers(const char *username) {
    FILE *file = fopen(BLOCKUSERS_FILE, "a");
    if (!file) {
        printf("Unable to open blockusers file.\n");
        return;
    }
    fprintf(file, "%s\n", username);
    fclose(file);
}

// Function to check if a user is blocked
int is_user_blocked(const char *username) {
    FILE *file = fopen(BLOCKUSERS_FILE, "r");
    if (!file) {
        // If the file doesn't exist, no users are blocked
        return 0;
    }
    char line[MAX_USERNAME_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        // Remove newline character
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, username) == 0) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

// Function to add a user to the active users list
void add_to_active_users(const char *username) {
    FILE *active_users_file = fopen(ACTIVE_USERS_FILE, "a");
    if (!active_users_file) {
        printf("Unable to open active users file.\n");
        return;
    }

    time_t now = time(NULL);
    fprintf(active_users_file, "%s %ld\n", username, now);
    fclose(active_users_file);
}

// Function to display currently logged-in users
void display_active_users() {
    FILE *active_users_file = fopen(ACTIVE_USERS_FILE, "r");
    if (!active_users_file) {
        printf("No users are currently logged in.\n");
        return;
    }

    char username[MAX_USERNAME_LENGTH];
    time_t login_time;

    printf("\nCurrently Logged-in Users:\n");
    printf("----------------------------\n");

    while (fscanf(active_users_file, "%99s %ld\n", username, &login_time) != EOF) {
        printf("Username: %s, Logged in at: %s", username, ctime(&login_time));
    }

    fclose(active_users_file);
}

// Function to handle user login
void user_login() {
    char username[MAX_USERNAME_LENGTH], password[MAX_PASSWORD_LENGTH];
    struct spwd *user_info;

    // Get the username
    printf("Enter username: ");
    scanf("%99s", username);

    // Fetch the password info for the specified username
    user_info = getspnam(username);
    if (!user_info) {
        printf("User not found or no access to /etc/shadow.\n");
        return;
    }

    // Get the password securely
    char *password_ptr = getpass("Enter password: ");
    strncpy(password, password_ptr, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0'; // Ensure null-termination

    // Check if the password is correct by comparing hashes
    if (strcmp(user_info->sp_pwdp, crypt(password, user_info->sp_pwdp)) == 0) {
        // Clear password from memory
        memset(password, 0, sizeof(password));

        // Determine user role
        if (is_user_in_group(username, "users")) {
            strcpy(current_role, "user");
            printf("User login successful!\n");
        } else if (is_user_in_group(username, "validators")) {
            strcpy(current_role, "validator");
            printf("Validator login successful!\n");
        } else {
            // Add user to blockusers
            add_user_to_blockusers(username);
            strcpy(current_role, "blockuser");
            printf("User '%s' has been added to the 'blockusers' list.\n", username);
        }

        // Add user to active users list
        add_to_active_users(username);

        // Update current_user
        strncpy(current_user, username, sizeof(current_user) - 1);
        current_user[sizeof(current_user) - 1] = '\0';

        printf("Welcome, %s!\n", username);
    } else {
        // Clear password from memory
        memset(password, 0, sizeof(password));
        printf("Login failed!\n");
    }
}

// Function to handle user logout
void user_logout() {
    if (strlen(current_user) == 0) {
        printf("No user is currently logged in.\n");
        return;
    }

    // Clear current_user and current_role
    printf("User %s has been logged out successfully.\n", current_user);
    current_user[0] = '\0';
    current_role[0] = '\0';
}

// Function to send a transaction
void send_transaction() {
    if (strlen(current_user) == 0) {
        printf("No user is currently logged in. Please log in to send a transaction.\n");
        return;
    }

    char recipient[MAX_RECIPIENT_LENGTH];
    double amount;

    printf("Enter recipient username: ");
    scanf("%99s", recipient);

    printf("Enter amount to send: ");
    if (scanf("%lf", &amount) != 1) {
        printf("Invalid input. Transaction cancelled.\n");
        while (getchar() != '\n');
        return;
    }

    if (amount <= 0) {
        printf("Invalid amount. Please enter a positive value.\n");
        return;
    }

    // Allow sending to any user, including blockusers
    // If recipient is in blockusers list, inform the sender
    if (is_user_blocked(recipient)) {
        printf("Note: Recipient '%s' is in the 'blockusers' list.\n", recipient);
    }

    Transaction *new_transaction = (Transaction *)malloc(sizeof(Transaction));
    if (!new_transaction) {
        printf("Failed to create transaction. Memory allocation error.\n");
        return;
    }

    strncpy(new_transaction->sender, current_user, MAX_USERNAME_LENGTH - 1);
    new_transaction->sender[MAX_USERNAME_LENGTH - 1] = '\0';

    strncpy(new_transaction->recipient, recipient, MAX_RECIPIENT_LENGTH - 1);
    new_transaction->recipient[MAX_RECIPIENT_LENGTH - 1] = '\0';

    new_transaction->amount = amount;
    new_transaction->timestamp = time(NULL);
    new_transaction->next = NULL;

    // Add transaction to pending transactions
    Transaction *current_tx = pending_transactions;
    if (current_tx == NULL) {
        pending_transactions = new_transaction;
    } else {
        while (current_tx->next != NULL)
            current_tx = current_tx->next;
        current_tx->next = new_transaction;
    }

    printf("Transaction from '%s' to '%s' for amount %.2f has been created.\n", current_user, recipient, amount);

    // Check if we have enough transactions to create a new block
    int tx_count = 0;
    current_tx = pending_transactions;
    while (current_tx != NULL) {
        tx_count++;
        current_tx = current_tx->next;
    }
    if (tx_count >= MAX_TRANSACTIONS_PER_BLOCK) {
        create_new_block();
    }
}

// Function to view user's transaction history
void view_transactions() {
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

                printf("[%s] From: %s, To: %s, Amount: %.2f\n", timestamp_str, tx->sender, tx->recipient, tx->amount);
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

            printf("[%s] From: %s, To: %s, Amount: %.2f (Pending)\n", timestamp_str, current_tx->sender, current_tx->recipient, current_tx->amount);
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
    Block *current_block = blockchain;
    while (current_block != NULL) {
        for (int i = 0; i < current_block->transaction_count; i++) {
            Transaction *tx = &current_block->transactions[i];
            char timestamp_str[26];
            ctime_r(&tx->timestamp, timestamp_str);
            timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

            printf("[%s] From: %s, To: %s, Amount: %.2f\n", timestamp_str, tx->sender, tx->recipient, tx->amount);
        }
        current_block = current_block->next;
    }

    // Also display pending transactions
    Transaction *current_tx = pending_transactions;
    while (current_tx != NULL) {
        char timestamp_str[26];
        ctime_r(&current_tx->timestamp, timestamp_str);
        timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

        printf("[%s] From: %s, To: %s, Amount: %.2f (Pending)\n", timestamp_str, current_tx->sender, current_tx->recipient, current_tx->amount);
        current_tx = current_tx->next;
    }
}

// Function to clean up blockchain
void cleanup_blockchain() {
    Block *current = blockchain;
    while (current) {
        Block *temp = current;
        current = current->next;
        free(temp);
    }
    blockchain = NULL;
}

// Function to clean up active users on program exit
void cleanup_and_exit(int signum) {
    printf("\nProgram terminated. Cleaning up active users and blockchain.\n");
    cleanup_blockchain();
    exit(0);
}

int main() {
    int choice;

    // Load blockchain from file
    load_blockchain();

    // Register signal handlers
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    while (1) {
        printf("\n--- Simple Login and Blockchain System ---\n");

        if (strlen(current_user) > 0) {
            // User is logged in
            printf("Logged in as: %s (%s)\n", current_user, current_role);
            printf("1. Logout\n");
            printf("2. Send Transaction\n");
            printf("3. View My Transactions\n");
            printf("4. View All Transactions\n");
            printf("5. Display Active Users\n");
            printf("6. Exit\n");
            printf("Enter your choice: ");
            if (scanf("%d", &choice) != 1) {
                printf("Invalid input. Please enter a number.\n");
                while (getchar() != '\n');
                continue;
            }
            while (getchar() != '\n');

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
                    display_active_users();
                    break;
                case 6:
                    cleanup_and_exit(0);
                    break;
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        } else {
            printf("1. Login\n");
            printf("2. View All Transactions\n");
            printf("3. Display Active Users\n");
            printf("4. Exit\n");
            printf("Enter your choice: ");
            if (scanf("%d", &choice) != 1) {
                printf("Invalid input. Please enter a number.\n");
                while (getchar() != '\n');
                continue;
            }
            while (getchar() != '\n');

            switch (choice) {
                case 1:
                    user_login();
                    break;
                case 2:
                    view_all_transactions();
                    break;
                case 3:
                    display_active_users();
                    break;
                case 4:
                    cleanup_and_exit(0);
                    break;
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        }
    }

    return 0;
}
