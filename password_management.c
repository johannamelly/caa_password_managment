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
#define CONTEXT "Pencrypt"

const char* MASTERKEY_FILENAME = "masterKey.txt";
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


void password_storage(char* name, const unsigned char* password) {

    // Allocations mémoire
    unsigned char* key = locked_allocation(crypto_pwhash_STRBYTES);
    char* buff = locked_allocation(512*sizeof(char));
    unsigned char* pw = malloc(300*sizeof(char));
    char* nonceB64 = malloc(300);
    char* cipherB64 = malloc(300);

    // Récupération de la master key
    FILE* masterKey = fopen(MASTERKEY_FILENAME, "r");
    fscanf(masterKey, "%s", key);
    fclose(masterKey);

    // Génération et stockage d'un nonce
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

    sodium_bin2base64(nonceB64, 300, nonce, strlen((char*)nonce), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(cipherB64, 300, ciphertext, strlen((char*)ciphertext), sodium_base64_VARIANT_ORIGINAL);
    //Base64encode(nonceB64, nonce, strlen(nonce));
    //Base64encode(cipherB64, ciphertext, strlen(ciphertext));


    // Taille totale de la ligne stockée
    size_t strsize = strlen(NEW_LINE) + strlen(name) + strlen(SEPARATOR) + strlen(cipherB64) + strlen(SEPARATOR) + strlen(nonceB64);

    // Stockage dans un fichier
    snprintf(buff, strsize, "%s%s%s%s%s%s", NEW_LINE, name, SEPARATOR, cipherB64, SEPARATOR, nonceB64);
    FILE* allPW = fopen(ALLPW_FILENAME, "a+");
    fprintf(allPW, "%s", buff);
    fclose(allPW);


    // Libération des pointeurs
    free_buffer(key, crypto_pwhash_STRBYTES);
    free_buffer(buff, 512* sizeof(char));
    free(cipherB64);
    free(nonceB64);
    free(pw);

}


unsigned char* password_recover(char* name) {

    // Allocations mémoire
    unsigned char* key = locked_allocation(crypto_pwhash_STRBYTES);
    unsigned char* password = malloc(300*sizeof(char) + crypto_aead_chacha20poly1305_ABYTES);

    // Récupération de la master key
    FILE* masterKey = fopen(MASTERKEY_FILENAME, "r");
    fscanf(masterKey, "%s", key);
    fclose(masterKey);

    unsigned long long password_len;
    char* line = NULL;
    size_t len = 0;
    char* cipher = NULL;
    char* nonce = NULL;
    unsigned char* const nonceDecoded = malloc(400);
    unsigned char* const cipherDecoded = malloc(400);

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

    if(nonce == NULL || cipher == NULL) {
        printf("NULL");
        free_buffer(key, crypto_pwhash_STRBYTES);
        free(password);
        free(nonceDecoded);
        free(cipherDecoded);
        return NULL;
    }

    fclose(allPW);

    size_t len1;
    size_t len2;

    printf("%s -> %s", cipher, nonce);
    sodium_base642bin(nonceDecoded, 400, nonce, strlen(nonce), NULL, &len1, NULL, sodium_base64_VARIANT_ORIGINAL);
    sodium_base642bin(cipherDecoded, 400, cipher, strlen(cipher), NULL, &len2, NULL, sodium_base64_VARIANT_ORIGINAL);
    //Base64decode(nonceDecoded, nonce);
    //Base64decode(cipherDecoded, cipher);

    // Déchiffrement
    if (crypto_aead_chacha20poly1305_decrypt(password, &password_len,
                                             NULL,
                                             cipherDecoded, strlen((char*)cipherDecoded),
                                             NULL,
                                             0,
                                             nonceDecoded, key) != 0) {
        // Si échec, libération des pointeurs
        free_buffer(key, crypto_pwhash_STRBYTES);
        free(password);
        free(nonceDecoded);
        free(cipherDecoded);
        printf("Error!\n");
        return NULL;
    }

    password[password_len] = 0;
    // Libération des pointeurs
    //free(password);
    free_buffer(key, crypto_pwhash_STRBYTES);
    free(nonceDecoded);
    free(cipherDecoded);
    //free(nonce);
    //free(cipher);

    return password;

}


void key_derivation_and_storage() {

    // Allocation mémoire
    unsigned char* hashed_password = locked_allocation(crypto_pwhash_STRBYTES);

    // Buffer qui contiendra la clé
    unsigned char* subkey1 = locked_allocation(64);



    // Récupération du master password
    FILE* masterPWhash = fopen(MASTERPW_FILENAME, "r");
    fscanf(masterPWhash, "%s", hashed_password);
    fclose(masterPWhash);

    // Dérivation du master password
    crypto_kdf_derive_from_key(subkey1, sizeof(subkey1), 1, CONTEXT, hashed_password);

    // Écriture de la master key dans un fichier
    FILE* masterKey = fopen(MASTERKEY_FILENAME, "a+");
    fprintf(masterKey, "%s", subkey1);
    fclose(masterKey);

    // Libération du pointeur
    free_buffer(hashed_password, crypto_pwhash_STRBYTES);
}

