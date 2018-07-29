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
	int a = atoi(argv[1]);
	int b = atoi(argv[2]);
	int c = atoi(argv[3]);
	const int leng = 5+b+(b/a)+(2*(b/c));
	std::ifstream input("output.txt");


	while(!input.eof()){
		int readLines = 0;
		std::vector<string> lines;

		//read one block
		while(readLines < leng){
			string line;
			if(std::getline(input, line)){
				lines.push_back(line);
				readLines++;
			}
			else{ // no line read
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

				std::cout <<  "Verirfying signature of authenticaction block " << (blockNumber-1)*(b/a)+j+1 << std::endl;
				if(result){
					std::cout <<  " -> Auth verified" << std::endl;
				}
				else{
					std::cout << " -> Auth NOT verified, messages authentic until block " << ((blockNumber-1)*(b/a)+j)<< std::endl;
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
				std::cout <<  " ->Key NOT verified,  messages authentic until message " << (blockNumber-1)*b+c*(i+1)<< std::endl;
				exit(EXIT_FAILURE);
			}

		}
		blockNumber++;
	}
	return 0;
}