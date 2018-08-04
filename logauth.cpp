#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <algorithm>

#include "logauth.h"
#include "cryptopp/hex.h"
#include "cryptopp/integer.h"
#include "cryptopp/dsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"

#ifndef A
#define A 4
#endif

#ifndef B
#define B 64
#endif

#ifndef C
#define C 32
#endif

/* N is the total number of events that shall be processed
*/
#ifndef N
#define N 4097
#endif

using std::string;
using std::ofstream;
using std::ifstream;
using std::time;
using namespace CryptoPP;

static string oldLine = "";
static struct timespec oldTime;

static AutoSeededRandomPool rng;
static DSA::PublicKey pubA;
static DSA::PrivateKey privA;


/* This method computes the Authenticator (signature) on some elements of buffer.
*/
static string computeAuth(string buffer[], int start, int end){
	string concatString;
	for (int i = start; i <= end; ++i){
		concatString += buffer[i];
	}
	string signature;
	DSA::Signer signer(privA);
	StringSource ss1(concatString, true,
		new SignerFilter(rng, signer,
			new HexEncoder(new StringSink(signature))
		)
	);
	return signature;
}

/* This method is used to signal that a timeout has happened.
*/
static bool timeout(){
	struct timespec newTime;
	clock_gettime(CLOCK_MONOTONIC, &newTime);

	if(newTime.tv_sec - oldTime.tv_sec >= 2.0){ // every two seconds a timeout occurs
		oldTime = newTime;
		return true;
	}
	else{
		return false;
	}
}



int main(int argc, char** argv){
	struct timespec start;
	struct timespec finish, globalstart;
	double elapsed;

	//get start times for measurements
	clock_gettime(CLOCK_MONOTONIC, &start);
	clock_gettime(CLOCK_MONOTONIC, &globalstart);

	int j;
	const int a = A;
	const int b = B;
	const int c = C;

	ofstream Log;
	EVENT* currentEvent;

	string buffer[b];
	string abuffer[(int) b/a];
	string vbuffer[(int)b/c];
	string vbuffer2[(int)b/c];

	// Generate Private Key
	privA.GenerateRandomWithKeySize(rng, 2048);

	// Generate Public Key
	pubA.AssignFrom(privA);
	if (!privA.Validate(rng, 3) || !pubA.Validate(rng, 3)){
		throw std::runtime_error("DSA key generation failed");
	}

	//write first public key to a file
	{
		FileSink ouput("firstkey.dat");
		pubA.DEREncode(ouput);
	}

	//used to track whether one of the main events was already handled
	int oldJa = 0;
	int oldJb = 0;
	int oldJc = 0;

	//empty all buffers beforehand
	std::fill(buffer,buffer+b,"");
	std::fill(abuffer,abuffer+b/a,"");
	std::fill(vbuffer,vbuffer+b/c,"");
	std::fill(vbuffer2,vbuffer+b/c,"");

	j = 0;

	// used to measure the time it takes to initialize the program
	clock_gettime(CLOCK_MONOTONIC, &finish);
	elapsed = (finish.tv_sec - start.tv_sec);
	elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
	std::cout << elapsed << std::endl;

	//used to measure the time it takes to handle one block of size b
	clock_gettime(CLOCK_MONOTONIC, &start);

	// the main loop
	// the order in which the following if clauses are, is CRUCIAL
	while(j<N){
		if ((j % a) == 0 && j != oldJa){
			string Z = computeAuth(buffer,((j-a) % b), ((j-1) % b) );
			abuffer[(int)(((j-1)%b)/a)] = Z;
			oldJa = j;
		}

		if((j % c) == 0 && j != 0 && j != oldJc){
			// Generate Private Key
			DSA::PrivateKey privateKey;
			privateKey.GenerateRandomWithKeySize(rng, 2048);

			// Generate Public Key
			DSA::PublicKey publicKey;
			publicKey.AssignFrom(privateKey);
			if (!privateKey.Validate(rng, 3) || !publicKey.Validate(rng, 3)){
				throw std::runtime_error("DSA key generation failed");
			}

			//generate encoded public key
			string encodedPubKey;
			publicKey.Save(HexEncoder(
				new StringSink(encodedPubKey)).Ref()
			);

			//generate encoded signature of encoded public key
			string signature;
			DSA::Signer signer(privA);
			StringSource ss1(encodedPubKey, true,
				new SignerFilter(rng, signer,
					new HexEncoder(new StringSink(signature))
				)
			);

			//overwrite keys and store the new key and signature in vbuffers
			privA = privateKey;
			pubA = publicKey;
			vbuffer[(((j-1) % b)/c)] = signature;
			vbuffer2[(((j-1) % b)/c)] = encodedPubKey;
			oldJc = j;
		}

		if ((j % b) == 0 && j != 0 && j != oldJb){
			//used to measure the time it takes to handle one block of size b
			clock_gettime(CLOCK_MONOTONIC, &finish);
			elapsed = (finish.tv_sec - start.tv_sec);
			elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
			std::cout << elapsed << std::endl;

			Log.open("output.txt", std::ofstream::out | std::ofstream::app);
			Log << "##### j is now " << j << " #############################################" << std::endl;
			Log << "The content of buffer:" << std::endl;
			for (int i = 0; i< b; i++){
				Log << buffer[i] << std::endl;
			}
			Log << "The content of abuffer:" << std::endl;
			for (int i = 0; i< (int)b/a; i++){
				Log <<abuffer[i] << std::endl;
			}
			Log << "The content of vbuffer:" << std::endl;
			for (int i = 0; i< (int)b/c; i++){
				Log << vbuffer[i] << std::endl;
			}
			Log << "The content of vbuffer2:" << std::endl;
			for (int i = 0; i< (int)b/c; i++){
				Log << vbuffer2[i] << std::endl;
			}
			Log.close();

			std::fill(buffer,buffer+b,"");
			std::fill(abuffer,abuffer+b/a,"");
			std::fill(vbuffer,vbuffer+b/c,"");
			std::fill(vbuffer2,vbuffer2+b/c,"");
			oldJb = j;

			//initialize time for measuring a block b
			clock_gettime(CLOCK_MONOTONIC, &start);
		}

		if(timeout()){// if timeout returns true, then write metronome message with current time
			string output;
			char buf[27];
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			ctime_r(&ts.tv_sec, buf);
			output = buf;
			output.erase(std::remove(output.begin(), output.end(), '\n'), output.end());
			buffer[(j % b)] = output;
			j++;
		}
		else{
			currentEvent = getNextEvent();
			if(currentEvent){
				string l = currentEvent->getLog();
				buffer[(j % b)] = l;
				j++;
				delete currentEvent;
			}
			else{
				sleep(1);
			}
		}
	}

	// used to measure the time it takes to execute the whole program
	clock_gettime(CLOCK_MONOTONIC, &finish);
	elapsed = (finish.tv_sec - globalstart.tv_sec);
	elapsed += (finish.tv_nsec - globalstart.tv_nsec) / 1000000000.0;
	std::cout << elapsed << std::endl;

	exit(EXIT_SUCCESS);
}

