#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <crypt.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h> 

using namespace std;

int getNextAvailableUID() {
    ifstream passwdFile("/etc/passwd"); // open /etc/passwd
    if (!passwdFile.is_open()) {
        perror("Error opening /etc/passwd");
        return -1;
    }

    string line;
    int uid, maxUID = 0;

    while (getline(passwdFile, line)) { // parse each line of /etc/passwd, grab the UIDs, convert the UID string into an integer, and return the next available UID
        stringstream ss(line);
        string token;
        for (int i = 0; i < 3; ++i) {
            getline(ss, token, ':');
        }
        if (!token.empty()) {
            uid = stoi(token);
            if (uid > maxUID) {
                maxUID = uid;
            }
        }
    }

    passwdFile.close();
    return maxUID + 1; 
}

int main() { 
  char username[100], password[100];
	int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket < 0) {
		std::cerr << "Failed to create socket" << std::endl;
		return 1;
	    }

	struct sockaddr_in serverAddr; // set up server socket
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(8080);
	serverAddr.sin_addr.s_addr = INADDR_ANY;

	// bind the socket to the specified port of 8080. if port 8080 is already busy, state the error and close the socket
	if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
		std::cerr << "Binding failed" << std::endl;
		close(serverSocket);
		return 1;
	}

	// Listen for incoming connections, if there's an error, output the error and close
	if (listen(serverSocket, 5) < 0) {
		std::cerr << "Listening failed" << std::endl;
		close(serverSocket);
		return 1;
	}

	std::cout << "create_account listening on port 8080" << std::endl;

	struct sockaddr_in clientAddr;
	socklen_t clientAddrLen = sizeof(clientAddr);

	int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
	if (clientSocket < 0) { // if not able to connect, output, exit the current loop, and continue the loop
		std::cerr << "Failed to accept connection" << std::endl;
	}
			
	char buffer[1024] = {0};
	int valread = read(clientSocket, buffer, sizeof(buffer));
	if (valread <= 0) {
		std::cerr << "Failed to read from socket" << std::endl;
		close(clientSocket);
		return 1;
	}

		// Ensure buffer is null-terminated
	buffer[valread] = '\0';

		// Find the separator (colon) in the received data
	char *separator = strchr(buffer, ':');
	if (separator != nullptr) {
		size_t usernameLength = separator - buffer;
		if (usernameLength >= 100) {
			std::cerr << "Username is too long" << std::endl;
			close(clientSocket);
			return 1;
		}
		strncpy(username, buffer, usernameLength);
		username[usernameLength] = '\0';  // Null-terminate the username

	  // Copy password part (after the separator to the end of the buffer)
		size_t passwordLength = valread - usernameLength - 1; // Minus 1 for the colon
		if (passwordLength >= 100) {
			std::cerr << "Password is too long" << std::endl;
			close(clientSocket);
			return 1;
		}
		strncpy(password, separator + 1, passwordLength);
		password[passwordLength] = '\0';  // Null-terminate the password
	} else {
		std::cerr << "Invalid input format. Expected format: username:password" << std::endl;
    close(serverSocket);
    return 1;
  }

  password[strcspn(password, "\n")] = '\0'; // null-terminate username and password
  username[strcspn(username, "\n")] = '\0';
  char salt[17];
  snprintf(salt, sizeof(salt), "$6$%.8s$", username); // Salt is first 8 characters of username (for now)

  // Hash the password using the crypt function
  char *hashedPassword = crypt(password, salt);
  if (!hashedPassword) {
     perror("Error hashing password");
     return 1; 
  }

  // Get the current date (days since epoch) for shadow entry
  time_t now = time(NULL);
  long daysSinceEpoch = now / (60 * 60 * 24);

  // Get the next available UID
  int uid = getNextAvailableUID();
  if (uid < 0) {
    return 1; // Error in finding UID
  }

  // Construct the entry for /etc/shadow and append it to /etc/shadow (this is why the program must run as a root service or as root/sudo)
  char shadowEntry[512];
  if (snprintf(shadowEntry, sizeof(shadowEntry), "%s:%s:%ld:0:99999:7:::\n", username, hashedPassword, daysSinceEpoch) >= 512) {
      cerr << "Error: shadow entry exceeds maximum length" << endl;
      return 1;
  }

  int shadowfile = open("/etc/shadow", O_WRONLY | O_APPEND);

  if (shadowfile < 0) {
      perror("Error opening /etc/shadow for writing");
      return 1;
  }

  if (write(shadowfile, shadowEntry, strlen(shadowEntry)) < 0) {
     perror("Error writing to /etc/shadow");
     close(shadowfile);
     return 1;
  }
  close(shadowfile);

  // Construct the entry for /etc/passwd, append it to /etc/passwd
  char passwdEntry[512];
  if (snprintf(passwdEntry, sizeof(passwdEntry), "%s:x:%d:%d::/home/%s:/bin/bash\n", username, uid, uid, username) >= 512) {
      cerr << "Error: passwd entry exceeds maximum length" << endl;
      return 1;
  }

  int etcpasswdfile = open("/etc/passwd", O_WRONLY | O_APPEND);
  if (etcpasswdfile < 0) {
     perror("Error opening /etc/passwd for writing");
     return 1;
  }
  if (write(etcpasswdfile, passwdEntry, strlen(passwdEntry)) < 0) {
     perror("Error writing to /etc/passwd");
     close(etcpasswdfile);
     return 1;
  }
  close(etcpasswdfile);
  char combinedEntry[512 + 512]; // combine the passwd and shadow entries
  if (snprintf(combinedEntry, sizeof(combinedEntry), "%s;%s", shadowEntry, passwdEntry) >= sizeof(combinedEntry)) {
    cerr << "Error: combined entry exceeds maximum length" << endl;
    return 1;
  }

  std::ifstream ipFile("/home/Crypto-Capstone/nodeips.txt"); // Open the file with the IP address of the nodes (CHANGE THIS TO YOUR SPECIFIC PATH)
  std::string ipAddress;
    
  if (!ipFile.is_open()) {
      std::cerr << "Error opening IP file" << std::endl;
      return 1;
  }
    
  while (std::getline(ipFile, ipAddress)) {  // Read each IP from the file, connect to it on the specified port, and send the passwd and shadow entries over
      int sock = socket(AF_INET, SOCK_STREAM, 0);
      if (sock < 0) {
          std::cerr << "Socket creation error" << std::endl;
          continue;
      }

      struct sockaddr_in serverAddr;
      serverAddr.sin_family = AF_INET;
      serverAddr.sin_port = htons(10006);  // Server port, listener program runs on 10006
      serverAddr.sin_addr.s_addr = inet_addr(ipAddress.c_str()); 

      if (connect(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
          std::cerr << "Connection to server " << ipAddress << " failed" << std::endl;
          close(sock);
          continue;
      }
      ssize_t sentBytes = send(sock, combinedEntry, strlen(combinedEntry), 0); // send the combined passwd and shadow entries over
      if (sentBytes < 0) {
          std::cerr << "Failed to send data to " << ipAddress << std::endl;
      } else {
           std::cout << "Data sent to " << ipAddress << std::endl;
      }
        close(sock);
    }
    
  ipFile.close();
  cout << "Account created successfully with UID " << uid << "!" << endl;
  return 0;
}
