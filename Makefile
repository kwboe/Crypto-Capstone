all: create_account listen4nodes listener keccak

create_account:
	g++ create_account.cpp -o create_account -lcrypt

listen4nodes:
	g++ listen4nodes.cpp -o listen4nodes -lcrypt

listener:
	g++ listener.cpp -o listener

keccak:
	gcc keccaklogin.c -o keccaklogin -I./Keccak_Headers -L. -lcrypt -lXKCP

clean:
	rm create_account listen4nodes listener keccaklogin