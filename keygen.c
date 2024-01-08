#include <openssl/rsa.h>
#include <openssl/pem.h>

int generate_rsa_key_pair(const char *private_key_path, const char *public_key_path, int key_size) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    // Generate RSA key pair
    RSA *rsa_key = RSA_new();
    
    // Set RSA key parameters, including the public exponent (65537)
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa_key, key_size, e, NULL);
    
    // Cleanup the public exponent BIGNUM
    BN_free(e);
    
    if (!rsa_key) {
        fprintf(stderr, "Error generating RSA key pair\n");
        return 1;
    }

    // Save private key to file
    FILE *private_key_file = fopen(private_key_path, "w");
    if (!private_key_file) {
        perror("Error opening private key file");
        RSA_free(rsa_key);
        return 1;
    }
    PEM_write_RSAPrivateKey(private_key_file, rsa_key, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    // Save public key to file
    FILE *public_key_file = fopen(public_key_path, "w");
    if (!public_key_file) {
        perror("Error opening public key file");
        RSA_free(rsa_key);
        return 1;
    }
    PEM_write_RSAPublicKey(public_key_file, rsa_key);
    fclose(public_key_file);

    // Cleanup
    RSA_free(rsa_key);
    EVP_cleanup();

    return 0;
}

int main() {
    char * private_key_path = "private_key.pem";
    char * public_key_path  = "public_key.pem" ;
    int res = generate_rsa_key_pair(private_key_path, public_key_path, 1024);
    return res;
}
