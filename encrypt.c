#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int encrypt_message(const char *message, const char *public_key_path, unsigned char **encrypted_data, size_t *encrypted_len) {
    RSA *rsa_key = NULL;
    FILE *public_key_file = fopen(public_key_path, "r");

    if (!public_key_file) {
        perror("Error opening public key file");
        return 1;
    }

    // Use BIO to read the public key
    BIO *bio = BIO_new_fp(public_key_file, BIO_CLOSE);
    rsa_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    fclose(public_key_file);
    //BIO_free(bio);

    if (!rsa_key) {
        fprintf(stderr, "Error loading public key\n");
        return 1;
    }

    *encrypted_data = (unsigned char *)malloc(RSA_size(rsa_key));
    *encrypted_len = RSA_public_encrypt(strlen(message), (const unsigned char *)message, *encrypted_data, rsa_key, RSA_PKCS1_PADDING);

    RSA_free(rsa_key);
    return 0;
}

int main() {
    const char *public_key_path = "public_key.pem";
    const char *original_message = "Hello, RSA!";

    unsigned char *encrypted_data;
    size_t encrypted_len;

    if (encrypt_message(original_message, public_key_path, &encrypted_data, &encrypted_len) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    FILE *encrypted_file = fopen("encrypted_data.bin", "wb");
    fwrite(encrypted_data, sizeof(unsigned char), encrypted_len, encrypted_file);
    fclose(encrypted_file);

    // Display the encrypted data (in hexadecimal)
    printf("Encrypted Message (Hex): ");
    for (size_t i = 0; i < encrypted_len; i++) {
        printf("%02x", encrypted_data[i]);
    }

    printf("\n");

    // Clean up
    free(encrypted_data);

    return 0;
}

