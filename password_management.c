//
// Created by johanna on 10.04.19.
//

#include <stdbool.h>
#include <stdio.h>
#include <sodium.h>
#include <memory.h>
#include "memory.c"
#include "base64.c"
#pragma once

const char* SALT_FILENAME = "salt.txt";
const char* MASTERPW_FILENAME = "masterPW.txt";
const char* ALLPW_FILENAME = "allPW.txt";
char* SEPARATOR = "\t";
const char* NEW_LINE = "\n";


bool masterPassword_storage(char* mpw) {
    // Allocation mémoire
    char* hashed_password = locked_allocation(crypto_pwhash_STRBYTES);

    printf("Please wait a little...\n");

    // Hachage du mot de passe
    if(crypto_pwhash_argon2id_str(hashed_password, mpw, strlen(mpw),
                                  1, crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE) != 0 ){
        // Si erreur, libération du pointeur
        free_buffer(hashed_password, crypto_pwhash_STRBYTES);
        return false;
    }

    // Écriture du master password haché dans un fichier
    FILE* masterPWhash = fopen(MASTERPW_FILENAME, "a+");
    fprintf(masterPWhash, "%s", hashed_password);
    fclose(masterPWhash);

    // Libération du pointeur
    free_buffer(hashed_password, crypto_pwhash_STRBYTES);

    return true;
}

bool masterPassword_verify(char* mpw) {
    // Allocation mémoire
    char* hashed_password = locked_allocation(crypto_pwhash_STRBYTES);

    // Récupération du master password
    FILE* masterPWhash = fopen(MASTERPW_FILENAME, "r");
    fscanf(masterPWhash, "%s", hashed_password);
    fclose(masterPWhash);

    printf("Please wait a little...\n");

    // Vérification de la similarité des mots de passe
    if(crypto_pwhash_argon2id_str_verify(hashed_password, mpw, strlen(mpw)) != 0) {
        // Si erreur, libération du pointeur
        free_buffer(hashed_password, crypto_pwhash_STRBYTES);
        return false;
    }

    // Libération du pointeur
    free_buffer(hashed_password, crypto_pwhash_STRBYTES);
    return true;
}

bool masterPWdefined() {
    // Allocation mémoie
    char* hashed_password = locked_allocation(crypto_pwhash_STRBYTES);

    // Récupération du potentiel master password
    FILE* masterPWhash = fopen(MASTERPW_FILENAME, "a+");
    fscanf(masterPWhash, "%s", hashed_password);

    // Récupère la longueur du contenu du fichier
    fseek(masterPWhash, 0, SEEK_END);
    unsigned long fileSize = (unsigned long)ftell(masterPWhash);

    fclose(masterPWhash);

    // Si le fichier est vide
    if (fileSize <= 0) {
        // Libération du pointeur
        free_buffer(hashed_password, crypto_pwhash_STRBYTES);
        return false;
    }

    // Libération du pointeur
    free_buffer(hashed_password, crypto_pwhash_STRBYTES);

    return true;
}


void password_storage(char* name, const unsigned char* password, unsigned char* key) {

    // Allocations mémoire
    char* buff = malloc(512*sizeof(char));

    // Génération d'un nonce
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // Variables utiles au chiffrement
    unsigned char ciphertext[strlen((char*)password) + crypto_aead_chacha20poly1305_ABYTES];
    unsigned long long ciphertext_len;


    // Chiffrement
    crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                         password, strlen((char*)password),
                                         NULL, 0,
                                         NULL, nonce, key);

    char* nonceB64 = malloc(300);
    char* cipherB64 = malloc(300);

    printf("NONCE: %s\n CIPHER: %s\n", nonce, ciphertext);

    /*
    unsigned long long password_len;
    char* result = malloc(300);

    (crypto_aead_chacha20poly1305_decrypt(result, &password_len,
                                             NULL,
                                             ciphertext, ciphertext_len,
                                             NULL,
                                             0,
                                             nonce, key) != 0);

    result[password_len] = 0;
    printf("décrypt: %s\n", result);

*/
    /*    char* nonceDecoded = malloc(crypto_aead_chacha20poly1305_NPUBBYTES);
       size_t len1;
   */
    sodium_bin2base64(nonceB64, 300, nonce, strlen((char*)nonce), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(cipherB64, 300, ciphertext, strlen((char*)ciphertext), sodium_base64_VARIANT_ORIGINAL);


    // Taille totale de la ligne stockée
    size_t strsize = strlen(NEW_LINE) + strlen(name) + strlen(SEPARATOR) + strlen(cipherB64) + strlen(SEPARATOR) + strlen(nonceB64);

    snprintf(buff, strsize, "%s%s%s%s%s%s", NEW_LINE, name, SEPARATOR, cipherB64, SEPARATOR, nonceB64);


    // Stockage dans un fichier
    FILE* allPW = fopen(ALLPW_FILENAME, "a+");
    fprintf(allPW, "%s", buff);
    fclose(allPW);

    //sodium_base642bin(nonceDecoded, crypto_aead_chacha20poly1305_NPUBBYTES, nonceB64, strlen(nonceB64), NULL, &len1, NULL, sodium_base64_VARIANT_ORIGINAL);

    // Libération des pointeurs
    free(buff);
    free(nonceB64);
    free(cipherB64);
}


unsigned char* password_recover(char* name, unsigned char* key) {

    // Allocations mémoire
    unsigned char* password = locked_allocation(300);
    unsigned long long password_len;

    unsigned char* const nonceDecoded = malloc(crypto_aead_chacha20poly1305_NPUBBYTES);
    unsigned char* const cipherDecoded = malloc(300);

    char* line = NULL;
    size_t len = 0;
    char* cipher = NULL;
    char* nonce = NULL;


// Récupération du mot de passe chiffré et du nonce correspondant
    FILE* allPW = fopen(ALLPW_FILENAME, "r");
    if(allPW == NULL) {
        return NULL;
    }


    // Parcours ligne par ligne
    while (getline(&line, &len, allPW) != -1) {
        // Si l'entrée demandée est trouvée
        if (strstr(line , name )!= NULL)
        {
            // Récupération du mot de passe chiffré et du nonce
            cipher = strtok(line, SEPARATOR);
            cipher = strtok(NULL, SEPARATOR);
            nonce = strtok(NULL, SEPARATOR);
            nonce = strtok(nonce, "\n");
            break;
        }
    }

    fclose(allPW);


    // Si aucune entrée trouvée
    if(nonce == NULL || cipher == NULL) {
        // Libération des pointeurs
        printf("NULL");
        free_buffer(password, 300);
        free(nonceDecoded);
        free(cipherDecoded);
        return NULL;
    }

    size_t lenDecodedNonce;
    size_t lenDecodedCipher;


    printf("cipher: %s\n nonce: %s\n", cipher, nonce);


    sodium_base642bin(nonceDecoded, crypto_aead_chacha20poly1305_NPUBBYTES, nonce, strlen(nonce), NULL, &lenDecodedNonce, NULL, sodium_base64_VARIANT_ORIGINAL);
    sodium_base642bin(cipherDecoded, 400, cipher, strlen(cipher), NULL, &lenDecodedCipher, NULL, sodium_base64_VARIANT_ORIGINAL);

    printf("taille nonce %zu\n taille cipher %zu\n", lenDecodedNonce, lenDecodedCipher);

    nonceDecoded[crypto_aead_chacha20poly1305_NPUBBYTES] = 0;
    cipherDecoded[lenDecodedCipher] = 0;

    printf("decoded nonce: %s\n decoded cipher: %s\n", nonceDecoded, cipherDecoded);

    // Déchiffrement
    if (crypto_aead_chacha20poly1305_decrypt(password, &password_len,
                                             NULL,
                                             cipherDecoded, lenDecodedCipher,
                                             NULL,
                                             0,
                                             nonceDecoded, key) != 0) {
        // Si échec, libération des pointeurs
        free_buffer(password, 300);
        free(nonceDecoded);
        free(cipherDecoded);
        printf("Error!\n");
        return NULL;
    }
    password[password_len] = 0;


    // Libération mémoire
    free(nonceDecoded);
    free(cipherDecoded);

    return password;

}

char* get_key(char* masterPW) {
    unsigned char* key = locked_allocation(crypto_aead_chacha20poly1305_KEYBYTES);
    unsigned char* salt = malloc(crypto_pwhash_SALTBYTES);

    // Récupération du sel
    FILE* saltFile = fopen(SALT_FILENAME, "r");
    fscanf(saltFile, "%s", salt);
    if(saltFile == NULL) {
        printf("No salt!\n");
        free(salt);
        return NULL;
    }
    fclose(saltFile);

    // Dérivation du master password
    if (crypto_pwhash
                (key, crypto_aead_chacha20poly1305_KEYBYTES, masterPW, strlen(masterPW), salt,
                 crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                 crypto_pwhash_ALG_DEFAULT) != 0) {
        free(salt);
        free_buffer(key, crypto_aead_chacha20poly1305_KEYBYTES);
        return NULL;
    }else {
        printf("Got your key!\n");
    }

    // Libération
    free(salt);

    return (char*)key;
}

char* key_derivation_and_storage(char* masterPW) {

    remove(SALT_FILENAME);

    // Allocation mémoire
    unsigned char* key = locked_allocation(crypto_aead_chacha20poly1305_KEYBYTES);
    unsigned char* salt = malloc(crypto_pwhash_SALTBYTES);

    // Génération du sel
    randombytes_buf(salt, sizeof(salt));

    // Dérivation du master password
    if (crypto_pwhash
                (key, crypto_aead_chacha20poly1305_KEYBYTES, masterPW, strlen(masterPW), salt,
                 crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                 crypto_pwhash_ALG_DEFAULT) != 0) {
        free(salt);
        free_buffer(key, crypto_aead_chacha20poly1305_KEYBYTES);
        return NULL;
    }else {
        printf("Key successfully generated!\n");
    }

    // Écriture du sel dans un fichier
    FILE* saltFile = fopen(SALT_FILENAME, "a+");
    if(saltFile == NULL) {
        printf("No file\n");
        free(salt);
        free_buffer(key, crypto_aead_chacha20poly1305_KEYBYTES);
        return NULL;
    }
    fprintf(saltFile, "%s", salt);
    fclose(saltFile);

    // Libération
    free(salt);

    return (char*)key;

    /*
    // Allocation mémoire
    unsigned char* hashed_password = locked_allocation(crypto_pwhash_STRBYTES);

    // Buffer qui contiendra la clé
    unsigned char* subkey1 = sodium_malloc(64*sizeof(char));


    // Récupération du master password
    FILE* masterPWhash = fopen(MASTERPW_FILENAME, "r");
    if(masterPWhash == NULL) {
        printf("No file\n");
        return;
    }
    fscanf(masterPWhash, "%s", hashed_password);
    fclose(masterPWhash);

    // Dérivation du master password
    crypto_kdf_derive_from_key(subkey1, strlen((char*) subkey1), 1, CONTEXT, hashed_password);

    // Écriture de la master key dans un fichier
    FILE* masterKey = fopen(MASTERKEY_FILENAME, "a+");
    if(masterKey == NULL) {
        printf("No file\n");
        return;
    }
    fprintf(masterKey, "%s", subkey1);
    fclose(masterKey);

    // Libération du pointeur
    free_buffer(hashed_password, crypto_pwhash_STRBYTES);
    sodium_free(subkey1);

     */
}

