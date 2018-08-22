#include "stdafx.h"
#include "simple_crypto.h"
#include <iostream>
#include <cstring>
#include <openssl/conf.h>


int main() {

    constexpr auto buffer_size = 2048;

    OpenSSL_add_all_algorithms();

    OPENSSL_config(nullptr);

    char text[] = "Hello, World!";
    char text_encrypted[buffer_size];
    char text_decrypted[buffer_size];
    char buffer[buffer_size];

    try {

        rsa_key rsa1(2048);

        std::cout << "original text: " << text << std::endl;


        // test 1
        {
            std::cout << "test 1: size of key is " << rsa1.size() << " bytes." << std::endl;

            auto len = rsa1.encrypt(text, text_encrypted, strlen(text) + 1, rsa_key::key_type::private_key);

            len = rsa1.decrypt(text_encrypted, text_decrypted, len, rsa_key::key_type::public_key);

            std::cout << "test 1: " << text_decrypted << std::endl;
        }


        // test 2
        {
            auto len = rsa1.output(buffer);
            rsa_key rsa2(buffer, len);

            std::cout << "test 2: size of key is " << rsa2.size() << " bytes." << std::endl;

            len = rsa2.encrypt(text, text_encrypted, strlen(text) + 1, rsa_key::key_type::public_key);
            len = rsa1.decrypt(text_encrypted, text_decrypted, len, rsa_key::key_type::private_key);

            std::cout << "test 2: " << text_decrypted << std::endl;
        }


        // test 3
        {
            char pw[] = "fasfasfasf";

            auto len = rsa1.output(buffer, pw, strlen(pw) /* without the '\0' */);
            rsa_key rsa3(buffer, len, pw);

            std::cout << "test 3: size of key is " << rsa3.size() << " bytes." << std::endl;

            len = rsa3.encrypt(text, text_encrypted, strlen(text) + 1, rsa_key::key_type::private_key);
            len = rsa1.decrypt(text_encrypted, text_decrypted, len, rsa_key::key_type::public_key);

            std::cout << "test 3: " << text_decrypted << std::endl;

            len = rsa3.encrypt(text, text_encrypted, strlen(text) + 1, rsa_key::key_type::public_key);
            len = rsa1.decrypt(text_encrypted, text_decrypted, len, rsa_key::key_type::private_key);

            std::cout << "test 3: " << text_decrypted << std::endl;
        }


        // test 4
        {
            aes_key<256> aes(aes_mode::cbc);
            auto len = aes.encrypt(text, text_encrypted, strlen(text) + 1);
            aes.decrypt(text_encrypted, text_decrypted, len);

            std::cout << "test 4: " << text_decrypted << std::endl;
        }


        // test 5
        {
            unsigned char key[aes_key<256>::AES_KEY_MAX_SIZE];
            unsigned char ivec[AES_BLOCK_SIZE];

            aes_key<192> aes(aes_mode::ecb);
            aes.output(key, ivec);

            aes_key<192> aes1(aes_mode::ecb, key, ivec);

            auto len = aes1.encrypt(text, text_encrypted, strlen(text) + 1);
            aes.decrypt(text_encrypted, text_decrypted, len);

            std::cout << "test 5: " << text_decrypted << std::endl;

            len = aes.encrypt(text, text_encrypted, strlen(text) + 1);
            aes1.decrypt(text_encrypted, text_decrypted, len);

            std::cout << "test 5: " << text_decrypted << std::endl;
        }

    }
    catch (const std::exception & e) {
        std::cout << e.what() << std::endl;
    }

    EVP_cleanup();

    CRYPTO_cleanup_all_ex_data();

	getchar();

    return 0;
}