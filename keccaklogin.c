#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>       // For getpass()
#include <crypt.h>        // For crypt()
#include <shadow.h>       // For getspnam()
#include <pwd.h>          // For getpwnam()
#include <grp.h>          // For getgrnam()
#include <time.h>         // For time functions
#include <signal.h>       // For signal handling
#include <fcntl.h>        // For file operations
#include <sys/file.h>     // For file locking
// Include the Keccak hash functions
#include "KeccakHash.h"
#include "KeccakSponge.h"
#include "brg_endian.h"
#define MAX_USERNAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 100
#define MAX_RECIPIENT_LENGTH 100
#define BLOCKUSERS_FILE "blockusers.txt"
#define BLOCKCHAIN_FILE "blockchain.dat"
#define MAX_TRANSACTIONS_PER_BLOCK 5


#ifndef SUCCESS
#define SUCCESS 0
#endif

// Global variables to store the currently logged-in user and role
char current_user[MAX_USERNAME_LENGTH] = "";
char current_role[20] = ""; // User role: user, validator, blockuser

// Enum for transaction types
typedef enum {
    TRANSACTION_NORMAL,
    TRANSACTION_LOGIN,
    TRANSACTION_LOGOUT
} TransactionType;

// Structure to represent a transaction
typedef struct Transaction {
    TransactionType type;                         // Type of transaction
    char sender[MAX_USERNAME_LENGTH];             // Sender's username
    char recipient[MAX_RECIPIENT_LENGTH];         // Recipient's username
    double amount;                                // Transaction amount
    time_t timestamp;                             // Timestamp of the transaction
    struct Transaction *next;                     // Pointer to the next transaction (for pending transactions list)
} Transaction;

// Structure to represent a block in the blockchain
typedef struct Block {
    int index;                                    // Block index in the blockchain
    time_t timestamp;                             // Timestamp of the block creation
    Transaction transactions[MAX_TRANSACTIONS_PER_BLOCK]; // Array of transactions in the block
    int transaction_count;                        // Number of transactions in the block
    unsigned char previous_hash[64];              // Hash of the previous block
    unsigned char hash[64];                       // Hash of the current block
    unsigned int hash_len;                        // Length of the hash
    struct Block *next;                           // Pointer to the next block in the blockchain
} Block;

// Head pointers for the blockchain and pending transactions list
Block *blockchain = NULL;
Transaction *pending_transactions = NULL;

// Function prototypes
int is_user_in_group(const char *username, const char *groupname);
void add_user_to_blockusers(const char *username);
int is_user_blocked(const char *username);
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
void cleanup_blockchain();
void cleanup_pending_transactions();
void cleanup_and_exit(int signum);
void print_hash(unsigned char *hash, unsigned int hash_len);
double get_user_balance(const char *username);
void request_test_funds(); // Function prototype

int main() {
    int choice;

    // Load blockchain from file
    load_blockchain();

    // Register signal handlers for graceful exit
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    while (1) {
        printf("\n--- Simple Login and Blockchain System ---\n");

        if (strlen(current_user) > 0) {
            // User is logged in
            printf("Logged in as: %s (%s)\n", current_user, current_role);
            printf("Balance: %.2f\n", get_user_balance(current_user));
            printf("1. Logout\n");
            printf("2. Send Transaction\n");
            printf("3. View My Transactions\n");
            printf("4. View All Transactions\n");
            printf("5. Display Blockchain\n");
            printf("6. Exit\n");
            printf("7. Request Test Funds\n");
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
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        } else {
            // User is not logged in
            printf("1. Login\n");
            printf("2. View All Transactions\n");
            printf("3. Display Blockchain\n");
            printf("4. Exit\n");
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
                    cleanup_and_exit(0);
                    break;
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        }
    }

    return 0;
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

// Function to compute the Keccak hash of a block using the Keccak Code Package
void compute_block_hash(Block *block) {
    // Initialize the Keccak hash context
    Keccak_HashInstance hashInstance;
    // Use Keccak-512 (512-bit output)
    if (Keccak_HashInitialize(&hashInstance, 1088, 512, 512, 0x01) != SUCCESS) {
        printf("Failed to initialize Keccak hash instance\n");
        return;
    }

    // Update the hash with block index
    Keccak_HashUpdate(&hashInstance, (const BitSequence *)&block->index, sizeof(block->index) * 8);

    // Update the hash with block timestamp
    Keccak_HashUpdate(&hashInstance, (const BitSequence *)&block->timestamp, sizeof(block->timestamp) * 8);

    // Update the hash with all transactions in the block
    for (int i = 0; i < block->transaction_count; i++) {
        Transaction *tx = &block->transactions[i];
        Keccak_HashUpdate(&hashInstance, (const BitSequence *)&tx->type, sizeof(tx->type) * 8);
        Keccak_HashUpdate(&hashInstance, (const BitSequence *)tx->sender, strlen(tx->sender) * 8);
        Keccak_HashUpdate(&hashInstance, (const BitSequence *)tx->recipient, strlen(tx->recipient) * 8);
        Keccak_HashUpdate(&hashInstance, (const BitSequence *)&tx->amount, sizeof(tx->amount) * 8);
        Keccak_HashUpdate(&hashInstance, (const BitSequence *)&tx->timestamp, sizeof(tx->timestamp) * 8);
    }

    // Update the hash with the previous block's hash
    Keccak_HashUpdate(&hashInstance, (const BitSequence *)block->previous_hash, block->hash_len * 8);

    // Finalize the hash computation
    if (Keccak_HashFinal(&hashInstance, block->hash) != SUCCESS) {
        printf("Failed to finalize Keccak hash computation\n");
        return;
    }
    block->hash_len = 64; // Keccak-512 produces 64-byte (512-bit) hash output
}

// Function to print the hash in hexadecimal format
void print_hash(unsigned char *hash, unsigned int hash_len) {
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
}

// Function to create the genesis block (first block in the blockchain)
void create_genesis_block() {
    Block *genesis = (Block *)malloc(sizeof(Block));
    if (!genesis) {
        printf("Failed to create genesis block. Memory allocation error.\n");
        exit(1);
    }
    genesis->index = 0;                              // Genesis block index is 0
    genesis->timestamp = time(NULL);                 // Current timestamp
    genesis->transaction_count = 0;                  // No transactions in genesis block
    memset(genesis->previous_hash, 0, 64);           // Previous hash is zero (no previous block)
    genesis->hash_len = 0;                           // Initial hash length is zero
    compute_block_hash(genesis);                     // Compute hash of the genesis block
    genesis->next = NULL;                            // No next block yet
    blockchain = genesis;                            // Set genesis block as the head of the blockchain

    // Save the genesis block to file
    FILE *file = fopen(BLOCKCHAIN_FILE, "wb");
    if (!file) {
        printf("Unable to create blockchain file.\n");
        return;
    }
    fwrite(genesis, sizeof(Block), 1, file);
    fclose(file);
}

// Function to add a block to the blockchain
void add_block_to_blockchain(Block *new_block) {
    // Compute hash of the new block
    compute_block_hash(new_block);

    // Find the last block in the blockchain
    Block *current = blockchain;
    while (current->next != NULL)
        current = current->next;
    current->next = new_block; // Append the new block to the blockchain
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

    // Remove the transactions that have been added to the block
    for (int i = 0; i < new_block->transaction_count; i++) {
        Transaction *temp = pending_transactions;
        pending_transactions = pending_transactions->next;
        free(temp);
    }

    // Set previous hash from the last block
    memcpy(new_block->previous_hash, last_block->hash, last_block->hash_len);
    new_block->hash_len = last_block->hash_len;

    new_block->next = NULL;

    // Add the new block to the blockchain
    add_block_to_blockchain(new_block);

    // Save only the new block to file
    FILE *file = fopen(BLOCKCHAIN_FILE, "ab"); // Append in binary mode
    if (!file) {
        printf("Unable to open blockchain file for appending.\n");
        return;
    }
    fwrite(new_block, sizeof(Block), 1, file);
    fclose(file);
}

// Function to load the blockchain from a file
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
            blockchain = block; // Set as first block
        } else {
            prev_block->next = block; // Append to blockchain
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
            char timestamp_str[26];
            ctime_r(&tx->timestamp, timestamp_str);
            timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

            if (tx->type == TRANSACTION_NORMAL) {
                if (strlen(tx->sender) == 0) {
                    // System transaction (e.g., faucet)
                    printf("  [%s] System -> %s, Amount: %.2f\n",
                           timestamp_str, tx->recipient, tx->amount);
                } else {
                    printf("  [%s] From: %s, To: %s, Amount: %.2f\n",
                           timestamp_str, tx->sender, tx->recipient, tx->amount);
                }
            } else if (tx->type == TRANSACTION_LOGIN) {
                printf("  [%s] User '%s' logged in.\n",
                       timestamp_str, tx->sender);
            } else if (tx->type == TRANSACTION_LOGOUT) {
                printf("  [%s] User '%s' logged out.\n",
                       timestamp_str, tx->sender);
            }
        }
        current_block = current_block->next;
    }
}

// Function to add a transaction to the pending transactions list
void add_transaction(Transaction *new_transaction) {
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
    if (tx_count >= MAX_TRANSACTIONS_PER_BLOCK) {
        create_new_block();
    }
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

        // Update current_user
        strncpy(current_user, username, sizeof(current_user) - 1);
        current_user[sizeof(current_user) - 1] = '\0';

        printf("Welcome, %s!\n", username);

        // Create a login transaction
        Transaction *login_tx = (Transaction *)malloc(sizeof(Transaction));
        if (login_tx) {
            login_tx->type = TRANSACTION_LOGIN;
            strncpy(login_tx->sender, username, MAX_USERNAME_LENGTH - 1);
            login_tx->sender[MAX_USERNAME_LENGTH - 1] = '\0';
            login_tx->recipient[0] = '\0';
            login_tx->amount = 0.0;
            login_tx->timestamp = time(NULL);
            login_tx->next = NULL;
            add_transaction(login_tx);
        }

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

    // Create a logout transaction
    Transaction *logout_tx = (Transaction *)malloc(sizeof(Transaction));
    if (logout_tx) {
        logout_tx->type = TRANSACTION_LOGOUT;
        strncpy(logout_tx->sender, current_user, MAX_USERNAME_LENGTH - 1);
        logout_tx->sender[MAX_USERNAME_LENGTH - 1] = '\0';
        logout_tx->recipient[0] = '\0';
        logout_tx->amount = 0.0;
        logout_tx->timestamp = time(NULL);
        logout_tx->next = NULL;
        add_transaction(logout_tx);
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
        printf("Insufficient balance. Your balance is %.2f. Transaction cancelled.\n", sender_balance);
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

    printf("Transaction from '%s' to '%s' for amount %.2f has been created.\n", current_user, recipient, amount);
}

// Function to view the current user's transaction history
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

                if (tx->type == TRANSACTION_NORMAL) {
                    if (strlen(tx->sender) == 0) {
                        // System transaction
                        printf("[%s] System -> %s, Amount: %.2f\n",
                               timestamp_str, tx->recipient, tx->amount);
                    } else {
                        printf("[%s] From: %s, To: %s, Amount: %.2f\n",
                               timestamp_str, tx->sender, tx->recipient, tx->amount);
                    }
                } else if (tx->type == TRANSACTION_LOGIN) {
                    printf("[%s] User '%s' logged in.\n", timestamp_str, tx->sender);
                } else if (tx->type == TRANSACTION_LOGOUT) {
                    printf("[%s] User '%s' logged out.\n", timestamp_str, tx->sender);
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

            if (current_tx->type == TRANSACTION_NORMAL) {
                if (strlen(current_tx->sender) == 0) {
                    // System transaction
                    printf("[%s] System -> %s, Amount: %.2f (Pending)\n",
                           timestamp_str, current_tx->recipient, current_tx->amount);
                } else {
                    printf("[%s] From: %s, To: %s, Amount: %.2f (Pending)\n",
                           timestamp_str, current_tx->sender, current_tx->recipient, current_tx->amount);
                }
            } else if (current_tx->type == TRANSACTION_LOGIN) {
                printf("[%s] User '%s' logged in. (Pending)\n", timestamp_str, current_tx->sender);
            } else if (current_tx->type == TRANSACTION_LOGOUT) {
                printf("[%s] User '%s' logged out. (Pending)\n", timestamp_str, current_tx->sender);
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
    Block *current_block = blockchain;
    printf("\n--- All Transactions ---\n");
    while (current_block != NULL) {
        for (int i = 0; i < current_block->transaction_count; i++) {
            Transaction *tx = &current_block->transactions[i];
            char timestamp_str[26];
            ctime_r(&tx->timestamp, timestamp_str);
            timestamp_str[strlen(timestamp_str) - 1] = '\0'; // Remove newline

            if (tx->type == TRANSACTION_NORMAL) {
                if (strlen(tx->sender) == 0) {
                    // System transaction
                    printf("[%s] System -> %s, Amount: %.2f\n",
                           timestamp_str, tx->recipient, tx->amount);
                } else {
                    printf("[%s] From: %s, To: %s, Amount: %.2f\n",
                           timestamp_str, tx->sender, tx->recipient, tx->amount);
                }
            } else if (tx->type == TRANSACTION_LOGIN) {
                printf("[%s] User '%s' logged in.\n", timestamp_str, tx->sender);
            } else if (tx->type == TRANSACTION_LOGOUT) {
                printf("[%s] User '%s' logged out.\n", timestamp_str, tx->sender);
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

        if (current_tx->type == TRANSACTION_NORMAL) {
            if (strlen(current_tx->sender) == 0) {
                // System transaction
                printf("[%s] System -> %s, Amount: %.2f (Pending)\n",
                       timestamp_str, current_tx->recipient, current_tx->amount);
            } else {
                printf("[%s] From: %s, To: %s, Amount: %.2f (Pending)\n",
                       timestamp_str, current_tx->sender, current_tx->recipient, current_tx->amount);
            }
        } else if (current_tx->type == TRANSACTION_LOGIN) {
            printf("[%s] User '%s' logged in. (Pending)\n", timestamp_str, current_tx->sender);
        } else if (current_tx->type == TRANSACTION_LOGOUT) {
            printf("[%s] User '%s' logged out. (Pending)\n", timestamp_str, current_tx->sender);
        }
        current_tx = current_tx->next;
    }
}

// Function to get user balance
double get_user_balance(const char *username) {
    double balance = 0.0;
    Block *current_block = blockchain;
    while (current_block != NULL) {
        for (int i = 0; i < current_block->transaction_count; i++) {
            Transaction *tx = &current_block->transactions[i];
            if (tx->type == TRANSACTION_NORMAL) {
                if (strcmp(tx->sender, username) == 0) {
                    balance -= tx->amount;
                }
                if (strcmp(tx->recipient, username) == 0) {
                    balance += tx->amount;
                }
            }
        }
        current_block = current_block->next;
    }

    // Include pending transactions
    Transaction *current_tx = pending_transactions;
    while (current_tx != NULL) {
        if (current_tx->type == TRANSACTION_NORMAL) {
            if (strcmp(current_tx->sender, username) == 0) {
                balance -= current_tx->amount;
            }
            if (strcmp(current_tx->recipient, username) == 0) {
                balance += current_tx->amount;
            }
        }
        current_tx = current_tx->next;
    }

    return balance;
}

// Function to request test funds
void request_test_funds() {
    if (strlen(current_user) == 0) {
        printf("No user is currently logged in. Please log in to request test funds.\n");
        return;
    }

    double amount = 1000.0; // Amount of test funds to grant

    Transaction *new_transaction = (Transaction *)malloc(sizeof(Transaction));
    if (!new_transaction) {
        printf("Failed to create transaction. Memory allocation error.\n");
        return;
    }

    new_transaction->type = TRANSACTION_NORMAL;
    new_transaction->sender[0] = '\0'; // Empty sender indicates system or faucet
    strncpy(new_transaction->recipient, current_user, MAX_RECIPIENT_LENGTH - 1);
    new_transaction->recipient[MAX_RECIPIENT_LENGTH - 1] = '\0';
    new_transaction->amount = amount;
    new_transaction->timestamp = time(NULL);
    new_transaction->next = NULL;

    // Add transaction to pending transactions
    add_transaction(new_transaction);

    printf("Test funds of amount %.2f have been credited to '%s'.\n", amount, current_user);
}

// Function to clean up the blockchain (free memory)
void cleanup_blockchain() {
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
    Transaction *current = pending_transactions;
    while (current) {
        Transaction *temp = current;
        current = current->next;
        free(temp);
    }
    pending_transactions = NULL;
}

// Function to handle program exit and cleanup
void cleanup_and_exit(int signum) {
    printf("\nProgram terminated. Cleaning up and saving data.\n");

    // Create a logout transaction if user is logged in
    if (strlen(current_user) > 0) {
        user_logout();
    }

    cleanup_pending_transactions();
    cleanup_blockchain();
    exit(0);
}
