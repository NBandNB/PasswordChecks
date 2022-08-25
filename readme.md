##Password Checks

A simple program that takes the inputed password and checks it against the have I been pwned pwned password list.

#To Compile

To compile the program you need to have the following installed:
    libcryptopp
    libcurl

This uses CMake to compile the program. To compile the program, run the following commands:

    mkdir build
    cd build
    cmake ..
    make

#To Run

    ./PasswordCheck <password>