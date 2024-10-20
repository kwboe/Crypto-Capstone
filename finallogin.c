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

// Function to add a user to the active users list
void add_to_active_users(const char *username) {
    FILE *active_users_file = fopen("/var/log/active_users.log", "a");
    if (!active_users_file) {
        printf("Unable to open active users file.\n");
        return;
    }

    // Get the current timestamp
    time_t now = time(NULL);

    // Write the username and login time
    fprintf(active_users_file, "%s %ld\n", username, now);
    fclose(active_users_file);
}

// Function to remove a user from the active users list
void remove_from_active_users(const char *username) {
    FILE *active_users_file = fopen("/var/log/active_users.log", "r");
    if (!active_users_file) {
        printf("Unable to open active users file.\n");
        return;
    }

    FILE *temp_file = fopen("/var/log/active_users_temp.log", "w");
    if (!temp_file) {
        printf("Unable to open temporary file.\n");
        fclose(active_users_file);
        return;
    }

    char file_username[100];
    time_t login_time;

    // Read each line and write all except the one matching the username
    while (fscanf(active_users_file, "%99s %ld\n", file_username, &login_time) != EOF) {
        if (strcmp(file_username, username) != 0) {
            fprintf(temp_file, "%s %ld\n", file_username, login_time);
        }
    }

    fclose(active_users_file);
    fclose(temp_file);

    // Replace the original file with the temporary file
    rename("/var/log/active_users_temp.log", "/var/log/active_users.log");
}

// Function to display currently logged-in users
void display_active_users() {
    FILE *active_users_file = fopen("/var/log/active_users.log", "r");
    if (!active_users_file) {
        printf("No users are currently logged in.\n");
        return;
    }

    char username[100];
    time_t login_time;
    int user_found = 0;

    printf("\nCurrently Logged-in Users:\n");
    printf("----------------------------\n");

    while (fscanf(active_users_file, "%99s %ld\n", username, &login_time) != EOF) {
        user_found = 1;
        printf("Username: %s, Logged in at: %s", username, ctime(&login_time));
    }

    if (!user_found) {
        printf("No users are currently logged in.\n");
    }

    fclose(active_users_file);
}

// Function to handle user login
void user_login() {
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
        return;
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
                return;
            }
        }

        // Add user to active users list
        add_to_active_users(username);

    } else {
        printf("Login failed!\n");
        log_login_attempt(username, "unknown", "failed");
    }
}

// Function to handle user logout
void user_logout() {
    char username[100], password[100];
    struct spwd *user_info;

    // Get the username
    printf("Enter username to logout: ");
    scanf("%99s", username);

    // Fetch the password info for the specified username
    user_info = getspnam(username);
    if (!user_info) {
        printf("User not found or no access to /etc/shadow.\n");
        return;
    }

    // Get the password
    printf("Enter password: ");
    scanf("%99s", password);

    // Verify password
    if (strcmp(user_info->sp_pwdp, crypt(password, user_info->sp_pwdp)) == 0) {
        // Remove user from active users list
        remove_from_active_users(username);
        printf("User %s has been logged out successfully.\n", username);
    } else {
        printf("Invalid password. Logout failed.\n");
    }
}

int main() {
    int choice;

    while (1) {
        printf("\n--- Simple Login System ---\n");
        printf("1. Login\n");
        printf("2. Logout\n");
        printf("3. Display Active Users\n");
        printf("4. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        // Clear input buffer
        while (getchar() != '\n');

        switch (choice) {
            case 1:
                user_login();
                break;
            case 2:
                user_logout();
                break;
            case 3:
                display_active_users();
                break;
            case 4:
                printf("Exiting...\n");
                exit(0);
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}
