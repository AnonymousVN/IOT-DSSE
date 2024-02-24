#IOT-SSE Implementation Use Guide

## Environment Setup

### Install System Packages
Please use the latest version of Ubuntu and run the following commands in the terminal:
````
sudo apt update 
sudo apt install -y ssh openssh-server build-essential libssl-dev libgmp-dev git
````

The above commands install the necessary packages/software (openssl, C/C++ compiler, GNUGMP, git) used in following steps.

### Install the PBC Library

Pairing-based Cryptography (PBC) Library is used to support elliptical curve pairing operations in C/C++ environments. We 
use this library to implement some operations over Zr. Please use the following command to install this library:
````
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
sudo make install
````

After installing the library, you may remove the code by running the following commands:
````
cd ..
sudo rm -rf pbc-0.5.14
````

## Project Download and Compilation
Clone the project from the GitHub by running:
````
git clone https://github.com/hongyentran/IOTSSE.git
````

Then, you should be able to compile the code with the following commands:
````
cd IOTSSE
mkdir build
cd build
cmake ..
make
````

If there is no error in the compilation process, you should be able to see an executable file
named ``IOTSSE`` under the build folder. Please move the file to the ``Data`` folder, and execute it with
````
./IOTSSE
````
