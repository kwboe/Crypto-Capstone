1. First step to use \- download   
   1. sudo apt-get update  
   2. sudo apt-get install libpam0g-dev  
   3. sudo apt-get install -y build-essential
   4. sudo apt-get install -y libpam0g-dev libpam-misc
   5. 

        
2. Download OpenSSL library \-   
   1. sudo apt-get install libssl-dev  
        
3. Download Open Quantum Safe \-   
   1. git clone https://github.com/open-quantum-safe/liboqs.git  
   2. cd liboqs  
   3. mkdir build && cd build  
   4. cmake \-DCMAKE\_INSTALL\_PREFIX=/usr/local ..  
   5. make  
   6. sudo make install

4. Make sure that this is in the correct path : \- run this command to check   
   1. export LD\_LIBRARY\_PATH=/usr/local/lib:$LD\_LIBRARY\_PATH

 

5. Finally run the compiler  
   1. gcc \-o kingcoin kingcoin .c \\ \-lpam \-lcrypto \-loqs
