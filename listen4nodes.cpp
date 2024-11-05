#include <iostream>
#include <fstream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <shadow.h>
#include <crypt.h>
#include <pwd.h>
#include <sstream>

bool uniqueIP(const std::string& ip) {
	std::ifstream infile("nodeips.txt"); // read file to get IPs already in file
	std::string fileip;
	while (std::getline(infile, fileip)) { // check each line to make sure the IP isn't already in the file
		if (fileip == ip) {
			return false; // ip matches one already in file, send false to function so it won't get added in as a duplicate
		}
	}
	return true; // if the ip isn't in file, send true to function and the ip will be added into the file
}
bool verifyUser(const char* username, const char* password) {
	struct spwd *user_info;
	user_info = getspnam(username);
	if (!user_info) {
		printf("User not found or no access to /etc/shadow.\n");
		return false;
	}
	char password_copy[256];
	strncpy(password_copy, password, sizeof(password_copy) - 1); // copies password to another string to help prevent some errors that I ran into, leaves a character for the null terminator
		    
	password_copy[sizeof(password_copy) - 1] = '\0'; // Adds null-termination
	password_copy[strcspn(password_copy, "\n")] = '\0'; // Remove newline character if the null termination wasn't enough (sometimes password would include a newline which threw off the hash)

	char *hashed_password = crypt(password_copy, user_info->sp_pwdp); // hashes password using crypt function

	if (strcmp(user_info->sp_pwdp, hashed_password) == 0) { // if password matches the one in /etc/shadow, return True and allow node ip to be added, otherwise return false and the IP won't be added
		std::cout << "Success" << std::endl;
		return true;
	} else {
		std::cout << "Failed" << std::endl;
		return false;
	}
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
	serverAddr.sin_port = htons(9999);
	serverAddr.sin_addr.s_addr = INADDR_ANY;

	// bind the socket to the specified port of 9999. if port 9999 is already busy, state the error and close the socket
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

	std::cout << "Server listening on port 9999" << std::endl;

  // Run loop to accept connections
	while (true) {
		struct sockaddr_in clientaddr;
		socklen_t clientaddrlength = sizeof(clientaddr);

		
		int clientSocket = accept(serverSocket, (struct sockaddr*)&clientaddr, &clientaddrlength);
		if (clientSocket < 0) { // if not able to connect, output, exit the current loop, and continue the loop
			std::cerr << "Failed to accept connection" << std::endl;
			continue;
		}
			
		char buffer[1024] = {0}; // build buffer to accept the username and password sent
		int valread = read(clientSocket, buffer, sizeof(buffer));
		if (valread <= 0) {
			std::cerr << "Failed to read from socket" << std::endl;
			close(clientSocket);
			return 1;
		}

		// Ensure buffer is null-terminated to prevent errors
		buffer[valread] = '\0';

		// Dig through the input provided by the connecting client, and once a colon is seen, split up the username and password
		char *separator = strchr(buffer, ':');
		if (separator != nullptr) {
			size_t usernameLength = separator - buffer;
			if (usernameLength >= 100) { // if username is more than 100 characters, that's too long and close the socket
				std::cerr << "Username is too long" << std::endl;
				close(clientSocket);
				return 1;
			}
			strncpy(username, buffer, usernameLength);
			username[usernameLength] = '\0';  // Null-terminate the username to prevent errors

			size_t passwordLength = valread - usernameLength - 1; // The minus 1 ensures the colon isn't part of this length calculation
			if (passwordLength >= 100) {
				std::cerr << "Password is too long" << std::endl;
				close(clientSocket);
				return 1;
			}
			strncpy(password, separator + 1, passwordLength);
			password[passwordLength] = '\0';  // Null-terminate the password
		} else {
			std::cerr << "Invalid input format. Expected format: username:password" << std::endl;
		}
		if (verifyUser(username, password)) { // call the verifyUser function with the username and password, if valid, allow the call of uniqueIP
		    	
			// Grabbing the IP address of the connecting client
			char clientIP[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
				
			if (uniqueIP(clientIP)) { // call uniqueIP with the clientIP address, if no duplicates, append it to nodeips.txt
				// Append the IP address to nodeips.txt
				std::ofstream outfile("nodeips.txt", std::ios::app);
				if (outfile.is_open()) {
					outfile << clientIP << std::endl;
					outfile.close();
					std::cout << "Added IP: " << clientIP << " to nodeips.txt" << std::endl;
				} else {
					std::cerr << "Error opening nodeips.txt" << std::endl;
				}
			}
			else {
			std::cout << "Error, ip already in file" << std::endl; 
			}
		}
			
		close(clientSocket); // close the client socket, continue running while loop for further connections
		}

	close(serverSocket); // close the server socket once while loop is broken by CTRL-C or stopping the service
	return 0;
}
