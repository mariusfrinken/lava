#include "cryptopp/integer.h"
#include "cryptopp/dsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/integer.h"
#include <fstream>
#include <iostream>
#include <unistd.h>



int main(int argc, char** argv) {
	if (argc < 4)
	{
		fprintf(stderr, "Usage: << logveri a b c >> where a,b,c are integers\n");
		exit(EXIT_FAILURE);
	}

	using namespace CryptoPP;
	using std::string;

	// load first Key from file,
	// Key is DER Encoded
	DSA::PublicKey publicKey;
	{
		FileSource input("firstkey.dat", true);
		publicKey.BERDecode(input);
	}

	int blockNumber = 1;
	//initialize parameter by using the argv command line arguments
	errno = 0;
	char *pEnd;
	long a = strtol(argv[1],&pEnd,10);
	if (pEnd == argv[1] || *pEnd != '\0' || ((a == LONG_MIN || a == LONG_MAX) && errno == ERANGE)){
		fprintf(stderr, "Could not convert '%s' to long and leftover string is: '%s'\n", argv[1], pEnd);
		exit(EXIT_FAILURE);
	}
	long b = strtol(argv[2],&pEnd,10);
	if (pEnd == argv[2] || *pEnd != '\0' || ((b == LONG_MIN || b == LONG_MAX) && errno == ERANGE)){
		fprintf(stderr, "Could not convert '%s' to long and leftover string is: '%s'\n", argv[2], pEnd);
		exit(EXIT_FAILURE);
	}
	long c = strtol(argv[3],&pEnd,10);
	if (pEnd == argv[3] || *pEnd != '\0' || ((c == LONG_MIN || c == LONG_MAX) && errno == ERANGE)){
		fprintf(stderr, "Could not convert '%s' to long and leftover string is: '%s'\n", argv[3], pEnd);
		exit(EXIT_FAILURE);
	}

	const long leng = 5+b+(b/a)+(2*(b/c));
	std::ifstream input("output.txt");


	while(!input.eof()){
		int readLines = 0;
		std::vector<string> lines;

		//read one full block of size leng
		while(readLines < leng){
			string line;
			if(std::getline(input, line)){
				lines.push_back(line);
				readLines++;
			}
			else{ // no line read or no full block (truncation)
				std::cout << "Verified until logmessage nr. " << (blockNumber-1)*b<< std::endl;
				exit(EXIT_SUCCESS);
			}
		}

		// now: process the block
		std::cout <<  "=============> Message Block: " << blockNumber << std::endl;

		// read plaintext messages and concatenate
		std::vector<string> messages;
		string tmp;
		for (int i = 1; i <= b; ++i){
			string concat = tmp + lines.at(1+i) ;
			tmp = concat;
			if (i % a == 0){
				messages.push_back(tmp);
				tmp.clear();
			}
		}

		// read signatures of message blocks
		std::vector<std::string> auths;
		for (int i = 0; i <b/a; ++i){
			std::string atmp = lines.at(b+3+i);
			auths.push_back(atmp);
		}

		// read signatures of new public keys
		std::vector<std::string> signedKeys;
		for (int i = 0; i <b/c; ++i){
			std::string ctmp = lines.at(b+4+b/a+i);
			signedKeys.push_back(ctmp);
		}

		// read new public keys
		std::vector<std::string> unsignedKeys;
		for (int i = 0; i <b/c; ++i){
			std::string cctmp = lines.at(b+5+b/a+b/c+i);
			unsignedKeys.push_back(cctmp);
		}


		for (int i = 0; i < b/c; ++i){
			// verify blocks of messages until a new key has to be used
			for (int j = i*(c/a); j < i*(c/a)+(c/a); ++j){
				string message = messages.at(j);
				string signature = auths.at(j);

				string decodedSignature;
				StringSource ss2(signature, true,
					new HexDecoder(
						new StringSink(decodedSignature)
					)
				);

				DSA::Verifier verifier(publicKey);
				bool result = false;
				StringSource ss3(decodedSignature+message, true,
					new SignatureVerificationFilter(
						verifier, new ArraySink((byte*)&result, sizeof(result))
					)
				);

				std::cout <<  "Verirfying signature of authenticaction block ranging from message " << ((blockNumber-1)*(b/a)+j)*a+1<< " to " << ((blockNumber-1)*(b/a)+j+1)*a << std::endl;
				if(result){
					std::cout <<  " -> Authenticity verified" << std::endl;
				}
				else{
					std::cout << " -> Authenticity NOT verified, messages authentic until message " << ((blockNumber-1)*(b/a)+j)*a<< "!" << std::endl;
					exit(EXIT_FAILURE);
				}

			}

			// after b/c many messages update/verify new key
			string signedKey = signedKeys.at(i);
			string unsignedKey = unsignedKeys.at(i);

			string decodedSignature;
			StringSource ss0(signedKey, true,
				new HexDecoder(
					new StringSink(decodedSignature)
				)
			);

			DSA::Verifier verifier(publicKey);
			bool result = false;
			StringSource ss3(decodedSignature+unsignedKey, true,
				new SignatureVerificationFilter(
					verifier, new ArraySink((byte*)&result, sizeof(result))
				)
			);
			std::cout << "" << std::endl;
			std::cout <<  "Verirfying new Public Key " << (blockNumber-1)*b/c+i+1 << std::endl;
			if (result){
				std::cout <<  " -> Key verified" << std::endl;
				std::cout << "" << std::endl;
				DSA::PublicKey newkey;
				newkey.Load(StringSource(unsignedKey, true,
					new HexDecoder()).Ref());
				publicKey = newkey;
			}
			else{
				std::cout <<  " ->Key NOT verified,  messages authentic until message " << (blockNumber-1)*b+c*(i+1)<< "!" << std::endl;
				exit(EXIT_FAILURE);
			}

		}
		blockNumber++;
	}
	return 0;
}