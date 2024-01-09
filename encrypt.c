#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int encrypt_message(const char *message, const char *private_key_path, unsigned char **encrypted_data, size_t *encrypted_len) {
    RSA *rsa_key = NULL;
    FILE *private_key_file = fopen(private_key_path, "r");

    if (!private_key_file) {
        perror("Error opening private key file");
        return 1;
    }

    // Use BIO to read the private key
    BIO *bio = BIO_new_fp(private_key_file, BIO_CLOSE);
    rsa_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    fclose(private_key_file);
    //BIO_free(bio);

    if (!rsa_key) {
        fprintf(stderr, "Error loading private key\n");
        return 1;
    }

    *encrypted_data = (unsigned char *)malloc(RSA_size(rsa_key));
    *encrypted_len = RSA_private_encrypt(strlen(message), (const unsigned char *)message, *encrypted_data, rsa_key, RSA_PKCS1_PADDING);

    RSA_free(rsa_key);
    return 0;
}

int main() {
    const char *private_key_path = "out/private_key.pem";
    const char *original_message = "Message from RSA!";

    unsigned char *encrypted_data;
    size_t encrypted_len;

    if (encrypt_message(original_message, private_key_path, &encrypted_data, &encrypted_len) != 0) {
        fprintf(stderr, "Encryption failed\n");
        return 1;
    }

    FILE *encrypted_file = fopen("out/encrypted_data.bin", "wb");

    fwrite(encrypted_data, sizeof(unsigned char), encrypted_len, encrypted_file);
    fclose(encrypted_file);

    // Display the encrypted data (in hexadecimal)
    printf("Encrypted message saved at: ./out/encrypted_data.bin (Hex): ");
    for (size_t i = 0; i < encrypted_len; i++) {
        printf("%02x", encrypted_data[i]);
    }

    printf("\n");

    // Clean up
    free(encrypted_data);

    return 0;
}

