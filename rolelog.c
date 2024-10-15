#include <stdio.h>
#include <shadow.h>
#include <crypt.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

// Function to check if a user belongs to a specific group
int is_user_in_group(const char *username, const char *groupname) {
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        return 0;
    }

    struct group *grp = getgrnam(groupname);
    if (!grp) {
        return 0;
    }

    // Check if the user's primary group matches
    if (pw->pw_gid == grp->gr_gid) {
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

// Function to assign a user to the blockusers group
int add_user_to_blockusers(const char *username) {
    char command[256];
    // Check if the blockusers group exists, if not, create it
    if (getgrnam("blockusers") == NULL) {
        printf("Group 'blockusers' does not exist. Creating it.\n");
        snprintf(command, sizeof(command), "sudo groupadd blockusers");
        if (system(command) != 0) {
            printf("Failed to create 'blockusers' group.\n");
            return 0;
        }
    }

    // Add the user to the blockusers group
    snprintf(command, sizeof(command), "sudo usermod -aG blockusers %s", username);
    if (system(command) != 0) {
        printf("Failed to add user %s to blockusers group.\n", username);
        return 0;
    }

    printf("User %s has been added to the 'blockusers' group.\n", username);
    return 1;
}

// Function to log the login attempts
void log_login_attempt(const char *username, const char *role, const char *status) {
    FILE *log_file = fopen("/var/log/simple_login.log", "a");
    if (!log_file) {
        printf("Unable to open log file.\n");
        return;
    }

    // Get the current timestamp
    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0'; // Remove the newline character

    // Write the log entry
    fprintf(log_file, "[%s] Username: %s, Role: %s, Status: %s\n", timestamp, username, role, status);
    fclose(log_file);
}

int main() {
    char username[100], password[100];
    struct spwd *user_info;
    const char *role = NULL;

    // Get the username
    printf("Enter username: ");
    scanf("%99s", username);

    // Fetch the password info for the specified username
    user_info = getspnam(username);
    if (!user_info) {
        printf("User not found or no access to /etc/shadow.\n");
        log_login_attempt(username, "unknown", "failed");
        return 1;
    }

    // Get the password
    printf("Enter password: ");
    scanf("%99s", password);

    // Check if the password is correct by comparing hashes
    if (strcmp(user_info->sp_pwdp, crypt(password, user_info->sp_pwdp)) == 0) {
        // Determine if the user is in the "users" or "validators" group
        if (is_user_in_group(username, "users")) {
            role = "user";
            printf("User login successful!\n");
            log_login_attempt(username, role, "successful");
        } else if (is_user_in_group(username, "validators")) {
            role = "validator";
            printf("Validator login successful!\n");
            log_login_attempt(username, role, "successful");
        } else {
            // User is not in "users" or "validators" group, add them to "blockusers"
            if (add_user_to_blockusers(username)) {
                role = "blockuser";
                printf("User has been automatically added to the 'blockusers' group.\n");
                log_login_attempt(username, role, "added_to_blockusers");
            } else {
                printf("Failed to add user to the blockusers group.\n");
                log_login_attempt(username, "unknown", "blockuser_assignment_failed");
                return 1;
            }
        }
    } else {
        printf("Login failed!\n");
        log_login_attempt(username, "unknown", "failed");
    }

    return 0;
}
