/*
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar-firebase-edition/
https://github.com/Northstrix/Midbar-Firebase-Edition
Required libraries:
https://github.com/Northstrix/AES_in_CBC_mode_for_microcontrollers
https://github.com/ulwanski/sha512
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/mobizt/Firebase-ESP32
*/
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

unsigned int iterations = 20451;

// Function to perform PBKDF2 key derivation
int derive_key_with_pbkdf2(const char *password, size_t password_len,
                           const unsigned char *salt, size_t salt_len,
                           unsigned int iterations, size_t key_len,
                           unsigned char *output_key) {
    mbedtls_md_context_t ctx; // Declare mbedtls_md_context_t structure
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256; // Specify hash function type
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);

    if (md_info == NULL) {
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }

    // Initialize MD context
    mbedtls_md_init(&ctx);

    // Setup MD context
    int ret = mbedtls_md_setup(&ctx, md_info, 1); // 1 for HMAC

    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return ret;
    }

    // Perform PBKDF2 key derivation
    ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx,
                                     (const unsigned char *)password, password_len,
                                     salt, salt_len,
                                     iterations,
                                     key_len,
                                     output_key);

    // Free MD context
    mbedtls_md_free(&ctx);

    return ret;
}

// Function to print a binary buffer as a hexadecimal string
void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 16) {
            Serial.print("0");
        }
        Serial.print(buf[i], HEX);
    }
    Serial.println();
}

void setup() {
    Serial.begin(115200);
    while (!Serial) {
      ; // wait for serial port to connect.
    }
    Serial.println("Deriving the key:");
    unsigned long startTime = millis();
    String myString = "my_password";
    char* password = new char[myString.length() + 1]; // Allocate memory for the C-style string
    strcpy(password, myString.c_str());
    size_t password_len = strlen(password);
    const unsigned char salt[] = {'a', 'b', 'c'}; // Example salt
    size_t salt_len = sizeof(salt);
    
    size_t key_len = 80;
    unsigned char output_key[key_len];

    // Derive key using PBKDF2
    int ret = derive_key_with_pbkdf2(password, password_len,
                                     salt, salt_len,
                                     iterations,
                                     key_len,
                                     output_key);

    if (ret == 0) {
        Serial.println("Key derivation successful!");
        Serial.print("Key derived in ");
        Serial.println(millis() - startTime);
        // Print the derived key
        Serial.println("Derived Key (hex):");
        print_hex(output_key, key_len);
    } else {
        Serial.println("Key derivation failed!");
    }
}

void loop() {
    // Your main code here
}
