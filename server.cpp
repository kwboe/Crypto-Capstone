#include <iostream>
#include <vector>
#include <cstring>
#include <thread>
#include <chrono>
#include <arpa/inet.h>
#include <unistd.h>

const int lport = 9999;
const std::string node1_ip = "10.233.105.144";
const int dport = 10005; 
const int listentime = 60; // 1 minute

void handleClient(int clientSocket, std::vector<std::string>& connections) {
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    if (getpeername(clientSocket, (struct sockaddr*)&addr, &addrLen) == 0) {
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr.sin_addr), ipStr, INET_ADDRSTRLEN);
        connections.push_back(ipStr); // saves ip address of connecting client and prepares it to send to node 1
    }
    close(clientSocket);
}

void sendConnections(const std::vector<std::string>& connections) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0); // creates UDP socket to transmit connections
    if (sock < 0) {
        std::cerr << "Failed to create socket\n";
        return;
    }

    struct sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(dport);
    inet_pton(AF_INET, node1_ip.c_str(), &destAddr.sin_addr); // converts node 1 ip into numeric address

    for (const auto& conn : connections) {
        sendto(sock, conn.c_str(), conn.length(), 0, (struct sockaddr*)&destAddr, sizeof(destAddr)); // sends ip address to the node 1
    }

    close(sock);
}

void runServer() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0); // creates socket
    if (serverSocket < 0) {
        std::cerr << "Failed to create socket\n";
        return;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(lport); // binds socket to lport (in this case 9999)

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) { // if it cannot bind to the port, specifies bind failed
        std::cerr << "Bind failed\n";
        close(serverSocket);
        return;
    }

    listen(serverSocket, SOMAXCONN);
    std::cout << "Listening on port " << lport << "...\n";

    std::vector<std::string> connections;
    auto startTime = std::chrono::steady_clock::now(); // gets time

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        struct timeval timeout = {1, 0}; // 1 second timeout

        if (select(serverSocket + 1, &readfds, NULL, NULL, &timeout) > 0) {
            int clientSocket = accept(serverSocket, NULL, NULL);
            if (clientSocket >= 0) {
                std::thread(handleClient, clientSocket, std::ref(connections)).detach();
            }
        }

        auto currentTime = std::chrono::steady_clock::now(); // gets current time, breaks out of  the loop if time is up
        if (std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime).count() >= listentime) {
            break;
        }
    }

    std::cout << "Sending connections to " << node1_ip << "...\n"; // sends connections
    sendConnections(connections);
    close(serverSocket);
}
 
int main() {
    while (true) {
        runServer();
        std::cout << "Sent connections, restarting server...\n";
    }
    return 0;
}
