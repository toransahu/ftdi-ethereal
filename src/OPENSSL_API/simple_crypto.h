#if !defined(_SIMPLE_CRYPTO_H_)

#define _SIMPLE_CRYPTO_H_

#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rand.h>




class rsa_key
{
public:


    using bits_type = unsigned short;
    using size_type = unsigned int;
    using buffer_type = void *;


    enum class key_type
    {
        public_key,
        private_key,
    };


    rsa_key(const rsa_key &) = delete;
    rsa_key & operator=(const rsa_key &) = delete;

    
    explicit rsa_key(bits_type bits)
    {
        assert(bits >= 512);

        evp_rsa_keygen keygen;

        auto key = keygen.genarate(bits);

        if (!(_key = EVP_PKEY_get1_RSA(key))) {
            EVP_PKEY_free(key);
            throw std::runtime_error("failed to EVP_PKEY_get1_RSA");
        }
        EVP_PKEY_free(key);
        _private_key = _key;
        _public_key = _key;
    }


    rsa_key(const buffer_type key_buff, size_type key_len)
            : _private_key(nullptr)
    {
        assert(key_buff != nullptr);
        assert(key_len > 0 && key_len <= INT_MAX);

        mem_bio bio;

        bio.write(key_buff, key_len);
        bio.read_public_key(&_key);
        _public_key = _key;
    }


    rsa_key(const buffer_type key_buff, size_type key_len, buffer_type password)
    {
        assert(key_buff != nullptr);
        assert(key_len > 0 && key_len <= INT_MAX);
        assert(password != nullptr);

        mem_bio bio;

        bio.write(key_buff, key_len);
        bio.read_private_key(&_key, password);
        _private_key = _key;
        _public_key = _key;
    }


    ~rsa_key()
    {
        RSA_free(_key);
    }


    size_type size() const noexcept
    {
        return static_cast<size_type>(RSA_size(_key));
    }


    size_type plaintext_max_len(key_type type) const noexcept
    {
        assert(size() > RSA_PKCS1_OAEP_PADDING_SIZE);

        auto s = size();
        return type == key_type::public_key ? s - RSA_PKCS1_PADDING_SIZE : s - RSA_PKCS1_OAEP_PADDING_SIZE;
    }


    key_type type() const noexcept
    {
        return _private_key ? key_type::private_key : key_type::public_key;
    }


    size_type encrypt(
            const buffer_type plaintext,
            buffer_type ciphertext,
            size_type plaintext_len,
            key_type type
    ) const
    {
        assert(plaintext != nullptr);
        assert(ciphertext != nullptr);
        assert(plaintext_len > 0 && plaintext_len <= plaintext_max_len(type));

        int result;

        if (type == key_type::public_key) {

            assert(_public_key != nullptr);

            result = RSA_public_encrypt(
                    static_cast<int>(plaintext_len),
                    static_cast<const unsigned char *>(plaintext),
                    static_cast<unsigned char *>(ciphertext),
                    _public_key,
                    RSA_PKCS1_OAEP_PADDING);

            if (result <= 0) {
                throw std::runtime_error("failed to RSA_public_encrypt");
            }
        }
        else {

            assert(_private_key != nullptr);

            result = RSA_private_encrypt(
                    static_cast<int>(plaintext_len),
                    static_cast<const unsigned char *>(plaintext),
                    static_cast<unsigned char *>(ciphertext),
                    _private_key,
                    RSA_PKCS1_PADDING);

            if (result <= 0) {
                throw std::runtime_error("failed to RSA_private_encrypt");
            }
        }

        return static_cast<size_type>(result);
    }


    size_type decrypt(
            const buffer_type ciphertext,
            buffer_type plaintext,
            size_type ciphertext_len,
            key_type type
    ) const
    {
        assert(ciphertext != nullptr);
        assert(plaintext != nullptr);
        assert(ciphertext_len > 0 && ciphertext_len <= size());

        int result;

        if (type == key_type::public_key) {

            assert(_public_key != nullptr);

            result = RSA_public_decrypt(
                    static_cast<int>(ciphertext_len),
                    static_cast<const unsigned char *>(ciphertext),
                    static_cast<unsigned char *>(plaintext),
                    _public_key,
                    RSA_PKCS1_PADDING);

            if (result <= 0) {
                throw std::runtime_error("failed to RSA_public_decrypt");
            }
        }
        else {

            assert(_private_key != nullptr);

            result = RSA_private_decrypt(
                    static_cast<int>(ciphertext_len),
                    static_cast<const unsigned char *>(ciphertext),
                    static_cast<unsigned char *>(plaintext),
                    _private_key,
                    RSA_PKCS1_OAEP_PADDING);

            if (result <= 0) {
                throw std::runtime_error("failed to RSA_private_decrypt");
            }
        }

        return static_cast<size_type>(result);
    }


    size_type output(buffer_type key_buff) const
    {
        assert(key_buff != nullptr);
        assert(_public_key != nullptr);

        mem_bio bio;
        bio.write_public_key(_public_key);
        auto bio_len = bio.pending();
        bio.read(key_buff, bio_len);

        return static_cast<size_type>(bio_len);
    }


    size_type output(
            buffer_type key_buff,
            buffer_type password,
            size_type pw_len,
            const EVP_CIPHER * enc = EVP_des_ede3_cfb8()
    ) const
    {
        assert(key_buff != nullptr);
        assert(_private_key != nullptr);
        assert(password != nullptr);
        assert(pw_len > 0 && pw_len <= INT_MAX);
        assert(enc != nullptr);

        mem_bio bio;
        bio.write_private_key(_private_key, enc, password, pw_len);
        auto bio_len = bio.pending();
        bio.read(key_buff, bio_len);

        return static_cast<size_type>(bio_len);
    }


private:


    enum{ RSA_PKCS1_OAEP_PADDING_SIZE = 41 };


    class evp_rsa_keygen
    {
    public:
        evp_rsa_keygen()
                : _ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr))
        {
            if (!_ctx) {
                throw std::bad_alloc();
            }
        }
        ~evp_rsa_keygen()
        {
            EVP_PKEY_CTX_free(_ctx);
        }
        EVP_PKEY * genarate(bits_type bits) const
        {
            if (EVP_PKEY_keygen_init(_ctx) != 1) {
                throw std::runtime_error("failed to EVP_PKEY_keygen_init");
            }

            if (EVP_PKEY_CTX_set_rsa_keygen_bits(_ctx, static_cast<int>(bits)) != 1) {
                throw std::runtime_error("failed to EVP_PKEY_CTX_set_rsa_keygen_bits");
            }

            EVP_PKEY * key = nullptr;

            if (EVP_PKEY_keygen(_ctx, &key) != 1) {
                throw std::runtime_error("failed to EVP_PKEY_keygen");
            }

            return key;
        }
    private:
        EVP_PKEY_CTX * _ctx;
    };


    class mem_bio
    {
    public:
        mem_bio()
                : _bio(BIO_new(BIO_s_mem()))
        {
            if (!_bio) {
                throw std::bad_alloc();
            }
        }
        ~mem_bio()
        {
            BIO_free_all(_bio);
        }
        void read(const buffer_type buffer, size_type size) const
        {
            if (BIO_read(_bio, buffer, size) <= 0) {
                throw std::runtime_error("failed to BIO_read");
            }
        }
        void write(buffer_type buffer, size_type size) const
        {
            if (BIO_write(_bio, buffer, size) <= 0) {
                throw std::runtime_error("failed to BIO_write");
            }
        }
        int pending() const noexcept
        {
            return BIO_pending(_bio);
        }
        void read_public_key(RSA ** key) const
        {
            if (!(*key = PEM_read_bio_RSAPublicKey(_bio, nullptr, nullptr, nullptr))) {
                throw std::runtime_error("failed to PEM_read_bio_RSAPublicKey");
            }
        }
        void read_private_key(RSA ** key, buffer_type password) const
        {
            if (!(*key = PEM_read_bio_RSAPrivateKey(_bio, nullptr, nullptr, password))) {
                throw std::runtime_error("failed to PEM_read_bio_RSAPrivateKey");
            }
        }
        void write_public_key(RSA * key) const
        {
            if (PEM_write_bio_RSAPublicKey(_bio, key) != 1) {
                throw std::runtime_error("failed to PEM_write_bio_RSAPublicKey");
            }
        }
        void write_private_key(RSA * key, const EVP_CIPHER * enc, buffer_type password, size_type pw_len) const
        {
            if (PEM_write_bio_RSAPrivateKey(_bio,
                                            key,
                                            enc,
                                            static_cast<unsigned char *>(password),
                                            static_cast<int>(pw_len),
                                            nullptr,
                                            nullptr) != 1) {
                throw std::runtime_error("failed to PEM_write_bio_RSAPrivateKey");
            }
        }
    private:
        BIO * _bio;
    };




    RSA * _key;
    RSA * _public_key;
    RSA * _private_key;
};




enum class aes_mode
{
    cbc,
    cfb,
    cfb1,
    cfb8,
    cfb128,
    ofb,
    ecb,
    ctr,


    // FIXME: invalid mode
    //warp,
    //xts,
    //ccm,
    //gcm,
};


template <std::uint16_t bits>
class aes_key
{
public:


    static_assert(bits == 128 || bits == 192 || bits == 256, "invalid bits of aes key!");


    enum { AES_KEY_MAX_SIZE = bits / 8 };


    using size_type = std::size_t;
    using buffer_type = void *;


    aes_key(const aes_key &) = delete;
    aes_key & operator=(const aes_key &) = delete;


    explicit aes_key(aes_mode mode)
    {
        RAND_bytes(_key, sizeof(_key));
        RAND_bytes(_iv, sizeof(_iv));
        init(get_cipher(mode));
    }


    aes_key(aes_mode mode, const buffer_type key_buff, const buffer_type iv_buff)
    {
        assert(key_buff != nullptr);
        assert(iv_buff != nullptr);

        std::memcpy(_key, key_buff, sizeof(_key));
        std::memcpy(_iv, iv_buff, sizeof(_iv));

        init(get_cipher(mode));
    }


    size_type encrypt(const buffer_type plaintext, buffer_type ciphertext, size_type plaintext_len) const
    {
        return _encryptContext.encrypt(plaintext, ciphertext, plaintext_len);
    }


    size_type decrypt(const buffer_type ciphertext, buffer_type plaintext, size_type ciphertext_len) const
    {
        return _decryptContext.decrypt(ciphertext, plaintext, ciphertext_len);
    }


    void output(buffer_type key_buff, buffer_type iv_buff) const noexcept
    {
        std::memcpy(key_buff, _key, sizeof(_key));
        std::memcpy(iv_buff, _iv, sizeof(_iv));
    }


private:


    void init(const EVP_CIPHER * cipher)
    {
        _encryptContext.init_encrypt(cipher, _key, _iv);
        _decryptContext.init_decrypt(cipher, _key, _iv);
    }


    const EVP_CIPHER * get_cipher(aes_mode mode) const noexcept
    {
        assert(false);
    }


    class evp_cipher_context
    {
    public:
        evp_cipher_context()
                : _ctx(EVP_CIPHER_CTX_new())
        {
            if (!_ctx) {
                throw std::bad_alloc();
            }
        }
        ~evp_cipher_context()
        {
            EVP_CIPHER_CTX_free(_ctx);
        }
        void init_encrypt(const EVP_CIPHER * cipher, const unsigned char * key, const unsigned char * iv) const
        {
            if(EVP_EncryptInit_ex(_ctx, cipher, nullptr, key, iv) != 1) {
                throw std::runtime_error("failed to EVP_EncryptInit_ex");
            }
        }
        void init_decrypt(const EVP_CIPHER * cipher, const unsigned char * key, const unsigned char * iv) const
        {
            if(EVP_DecryptInit_ex(_ctx, cipher, nullptr, key, iv) != 1) {
                throw std::runtime_error("failed to EVP_DecryptInit_ex");
            }
        }
        size_type encrypt(const buffer_type plaintext, buffer_type ciphertext, size_type plaintext_len) const
        {
            int len;
            size_type ciphertext_len = 0;

            if (EVP_EncryptUpdate(
                    _ctx,
                    static_cast<unsigned char *>(ciphertext),
                    &len,
                    static_cast<const unsigned char *>(plaintext),
                    plaintext_len) != 1) {
                throw std::runtime_error("failed to EVP_EncryptUpdate");
            }

            ciphertext_len = len;

            if (EVP_EncryptFinal_ex(_ctx, static_cast<unsigned char *>(ciphertext) + len, &len) != 1) {
                throw std::runtime_error("failed to EVP_EncryptFinal_ex");
            }

            return static_cast<size_type>(ciphertext_len + len);
        }
        size_type decrypt(const buffer_type ciphertext, buffer_type plaintext, size_type ciphertext_len) const
        {
            int len;
            size_type plaintext_len = 0;

            if (EVP_DecryptUpdate(
                    _ctx,
                    static_cast<unsigned char *>(plaintext),
                    &len,
                    static_cast<const unsigned char *>(ciphertext),
                    ciphertext_len) != 1) {
                throw std::runtime_error("failed to EVP_DecryptUpdate");
            }

            plaintext_len = len;

            if (EVP_DecryptFinal_ex(_ctx, static_cast<unsigned char *>(plaintext) + len, &len) != 1) {
                throw std::runtime_error("failed to EVP_DecryptFinal_ex");
            }

            return static_cast<size_type>(plaintext_len + len);
        }
    private:
        EVP_CIPHER_CTX * _ctx;
    };


    evp_cipher_context _encryptContext;
    evp_cipher_context _decryptContext;
    unsigned char _iv[AES_BLOCK_SIZE];
    unsigned char _key[AES_KEY_MAX_SIZE];
};


template <>
inline const EVP_CIPHER *
aes_key<128>::get_cipher(aes_mode mode) const noexcept
{
    switch (mode) {
        case aes_mode::cbc:
            return EVP_aes_128_cbc();
        case aes_mode::cfb:
            return EVP_aes_128_cfb();
        case aes_mode::cfb1:
            return EVP_aes_128_cfb1();
        case aes_mode::cfb8:
            return EVP_aes_128_cfb8();
        case aes_mode::cfb128:
            return EVP_aes_128_cfb128();
        case aes_mode::ctr:
            return EVP_aes_128_ctr();
        case aes_mode::ecb:
            return EVP_aes_128_ecb();
        case aes_mode::ofb:
            return EVP_aes_128_ofb();
        default:
            assert(false);
    }
}


template <>
inline const EVP_CIPHER *
aes_key<192>::get_cipher(aes_mode mode) const noexcept
{
    switch (mode) {
        case aes_mode::cbc:
            return EVP_aes_192_cbc();
        case aes_mode::cfb:
            return EVP_aes_192_cfb();
        case aes_mode::cfb1:
            return EVP_aes_192_cfb1();
        case aes_mode::cfb8:
            return EVP_aes_192_cfb8();
        case aes_mode::cfb128:
            return EVP_aes_192_cfb128();
        case aes_mode::ctr:
            return EVP_aes_192_ctr();
        case aes_mode::ecb:
            return EVP_aes_192_ecb();
        case aes_mode::ofb:
            return EVP_aes_192_ofb();
        default:
            assert(false);
    }
}


template <>
inline const EVP_CIPHER *
aes_key<256>::get_cipher(aes_mode mode) const noexcept
{
    EVP_CIPHER * cipher = nullptr;

    switch (mode) {
        case aes_mode::cbc:
            return EVP_aes_256_cbc();
        case aes_mode::cfb:
            return EVP_aes_256_cfb();
        case aes_mode::cfb1:
            return EVP_aes_256_cfb1();
        case aes_mode::cfb8:
            return EVP_aes_256_cfb8();
        case aes_mode::cfb128:
            return EVP_aes_256_cfb128();
        case aes_mode::ctr:
            return EVP_aes_256_ctr();
        case aes_mode::ecb:
            return EVP_aes_256_ecb();
        case aes_mode::ofb:
            return EVP_aes_256_ofb();
        default:
            assert(false);
    }
}


#endif // _SIMPLE_CRYPTO_H_