#include <stdio.h>
#include <shadow.h>
#include <crypt.h>
#include <string.h>

int main() {
    char username[100], password[100];  // For username and password input
    struct spwd *user_info;  // To store the user's password info from /etc/shadow

    // Get the username
    printf("Enter username: ");
    scanf("%99s", username);

    // Fetch the user's password
    user_info = getspnam(username);
    if (!user_info) {
        printf("User not found or no access to /etc/shadow.\n");
        return 1;
    }

    // Get the password
    printf("Enter password: ");
    scanf("%99s", password);

    // Check if the password is correct by comparing hashes
    if (strcmp(user_info->sp_pwdp, crypt(password, user_info->sp_pwdp)) == 0) {
        printf("Login successful!\n");
    } else {
        printf("Login failed!\n");
    }

    return 0;
}