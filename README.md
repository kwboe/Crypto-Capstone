# Quantum Secure Cryptology Implemented in Cryptocurrency

Contributors: Cowen Bland, Kyle Boe, Felix Hernandez-Kossick, Torin Kearney
Advisor: LT. Maxam
Key Words: Quantum Secure, Quantum Cryptology

## Description
This is a project to try and implement multiple quantum secure algorithms in a practical sense. To do this we chose to implement the said
algorithms in a cryptocurrency. We believe that this is the best way to show multiple algorithms working together efficiently and demonstrate
their capabilities.

## Directions
Pre-face: Ideally this should be run on a minimum of 2 machines, 1 as the starter node and 1 as the 1st node.
On the starter node, the create_account.cpp should be compiled. (g++ create_account.c -o create_account -lcrypt) In order for this to work, the program must be run with sudo or as a root service. Additionally, the listen4nodes.cpp should also be compiled, as it is how the nodes will tell the starter node that it is a node (g++ listen4nodes.cpp -o listen4nodes -lcrypt).
On the 1st and 2nd Node we need to add a new library to add our keccak functionality. 
To do this we used the https://github.com/KeccakTeam/KeccakCodePackage, which is the Official open source Keccak github. If you want to create your own library, follow the steps on the readme there. We will provide the library and header files required (libXKCP.a and the .h files). Make sure to move the library and headers to the correct file path. (usr/local/include for the headers and /usr/local/lib for the library).
On the 1st node, the Listener and keccaklogin.c shoud be compiled. (g++ listener.cpp -o listener and gcc keccaklogin.c -o keccaklogin -I/usr/local/include -lcrypt -lXKCP)

1. On the starter node, listen4nodes should be running, either as a root service or with sudo.
2. On the first node, the Listener should be running and ready to recieve information. (either as a root service or with sudo)
3. On the starter, use the built-in Linux adduser command to make a new account. You may also run the create_account program (as root/sudo), connecting with nc localhost 8080 and entering a username and password in the format username:password after connection.
4. On the first node, connect to the listen4nodes program with nc <starter node ip> 9999. Once connected, enter the username and password you just created in the form username:password to validate the first node with the starter node.
5. On either the first or starter node, connect to the create_account program with nc <starter node ip> 8080 and enter a username and password in the format username:password.
6. On the first node, the listener should recieve the username and password in the form of an /etc/shadow and /etc/passwd entry, then input those into their respective files.
7. On the first node, use the login program to login to the first node.
   - This should be the keccaklogin program you compiled earlier. Use sudo ./keccaklogin (or whatever you named it) to access the menu. (Use sudo if you did not make it a root service)
   - Once on the menu, use the username and password you created to login via the login interface.
