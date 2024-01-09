// decrypt.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// decrypt.c

int decrypt_message(const unsigned char *encrypted_data, size_t encrypted_len, const char *public_key_path, char **decrypted_message) {
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

    *decrypted_message = (char *)malloc(encrypted_len);
    int decrypted_len = RSA_public_decrypt(encrypted_len, encrypted_data, (unsigned char *)(*decrypted_message), rsa_key, RSA_PKCS1_PADDING);

    if (decrypted_len == -1) {
        fprintf(stderr, "Error decrypting message\n");
        ERR_print_errors_fp(stderr);
        free(*decrypted_message);
        RSA_free(rsa_key);
        return 1;
    }

    RSA_free(rsa_key);
    return 0;
}

int main() {
    const char *public_key_path = "out/public_key.pem";
    FILE *encrypted_file = fopen("out/encrypted_data.bin", "rb");
    fseek(encrypted_file, 0, SEEK_END);
    size_t encrypted_file_size = ftell(encrypted_file);
    rewind(encrypted_file);
    
    unsigned char *encrypted_data = (unsigned char *)malloc(encrypted_file_size);
    fread(encrypted_data, sizeof(unsigned char), encrypted_file_size, encrypted_file);
    fclose(encrypted_file);

    char *decrypted_message;
    if (decrypt_message(encrypted_data, encrypted_file_size, public_key_path, &decrypted_message) != 0) {
        fprintf(stderr, "Decryption failed\n");
        return 1;
    }

    printf("Decrypted Message: %s\n", decrypted_message);

    // Clean up
    free(decrypted_message);

    return 0;
}

