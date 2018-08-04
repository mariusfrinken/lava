# LAVA
A Log Authentication and Verification Algorithm implemented in C++ using Cryptopp

This simple program is intended as a proof of concept, demonstrating the Algorithm introduced by *Freiling, Bajramovic and Frinken* in *...*.

This project consist of two separate programs:
**The Authenticator & The Verifier**

## The Authenticator
The main part of the Algorithm is the creation of signatures of event messages in order to achieve authenticity. This signing and periodically updating the related keys is handled by the authenticator **logauth**.

At the current state it is provided with **N** many mock events (see function *getNextEvent* at [logauth.h](https://github.com/mariusfrinken/lava/blob/master/logauth.h)) and it creates a very simple output log file called *output.txt*.

## The Verifier
To have a method of automatically verifying the created output file of **logauth**, the verifier **logveri** is provided.

It simply reads the *output.txt* file, checks whether the signatures match with the event messages and prints the results to *stdout*.

# Usage
For simple test purposes, just compile both programs with `make all` and run `./logauth`. Once the program is finished, run `./logveri a b c` (default configuration a = 4, b = 64, c = 32) to verify the authenticity of *output.txt*.

## Configuration
To change the default configuration, one has to edit [logauth.cpp](https://github.com/mariusfrinken/lava/blob/master/logauth.cpp).

Change the definition of **A,B,C or N** to alter the respective parameter of the algorithm.

Additionally, one can comment out the various lines used for measuring the time it takes the program to run, see the related comments in the code.

To handle anything different from simple mock events, one has to provide some events using the function *getNextEvent* at [logauth.h](https://github.com/mariusfrinken/lava/blob/master/logauth.h).