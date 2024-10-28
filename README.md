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
On the starter node, the create_account.cpp should be compiled. (g++ create_account.c -o create_account -lcrypt) In order for this to work, the program must be run with sudo or as a root service.
On the 1st node, the Listener (Shadow Listener, Password Listener), and rolelog.c shoud be compiled. (g++ listener.cpp -o listener and gcc login.c -o login -lcrypt -lssl -lcrypto)

1. On the first node, the Listener should be running and ready to recieve information. (either as a service or with sudo)
2. On the starter, the create_account program should be running and ready to be connected to recieve the users username and password. (Ideally a service or with sudo)
3. On the first node, the listener should recieve the username and password in the form of an /etc/shadow and /etc/passwd entry, then input those into their respective files.
4. On the first node, use the login program to login to the first node.
