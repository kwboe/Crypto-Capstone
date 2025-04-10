#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pwd.h>
#include <shadow.h>

void listener() {
    int receive_sock, new_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size;

    receive_sock = socket(AF_INET, SOCK_STREAM, 0);

    memset(&server_addr, 0, sizeof(server_addr)); // prepare port 10010 for connections, bind to port, and begin listening
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(10010);

    if (bind(receive_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    listen(receive_sock, 5);
    printf("Listener running on port %d...\n", 10010);

    while (1) {
        addr_size = sizeof(client_addr);
        new_sock = accept(receive_sock, (struct sockaddr *)&client_addr, &addr_size);
	
	      char username[256], password[256], send_pass[256], send_user[256];
        recv(new_sock, username, sizeof(username), 0);
        recv(new_sock, password, sizeof(password), 0);
        struct passwd *pw = getpwnam(username); // use the getpwnam and getspnam functions to collect the passwd and shadow lines of a given user
        struct spwd *sp = getspnam(username);

        if (pw && sp) {
           snprintf(send_user, sizeof(send_user), "%s:%s:%d:%d:%s:%s:%s", pw->pw_name, pw->pw_passwd, pw->pw_uid, pw->pw_gid, pw->pw_gecos, pw->pw_dir, pw->pw_shell); // format the passwd and shadow lines
           snprintf(send_pass, sizeof(send_pass), "%s:%s:%d:%d:%d:%d:::", sp->sp_namp, sp->sp_pwdp, sp->sp_lstchg, sp->sp_min, sp->sp_max, sp->sp_warn);
        }

        send(new_sock, send_user, sizeof(send_user), 0); // send them back to the client
        send(new_sock, send_pass, sizeof(send_pass), 0);

        close(new_sock);
    }
    close(receive_sock);
}

int main() {
    listener();
    return 0;
}
