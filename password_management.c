//
// Created by Johanna
//

#include <stdbool.h>
#include <stdio.h>
#include <sodium.h>
#include <memory.h>
#include "memory.c"
#include "base64.h"
#pragma once

const char* SALT_FILENAME = "salt.txt";
const char* MASTERPW_FILENAME = "masterPW.txt";
const char* ALLPW_FILENAME = "allPW.txt";
const char* TEMPORARY_FILE = "tmp.txt";
char* SEPARATOR = "\t";
const char* NEW_LINE = "\n";


/**
 * Hash et stocke le master password
 * @param mpw le master password non chiffré
 * @return un booléen indiquant le succès de l'opération
 */
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

/**
 * Compare un master password donné avec le master password stocké
 * @param mpw le master password donné non chiffré
 * @return un booléen indiquant le succès le l'opération
 */
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

/**
 * Vérifie s'il y a un master password défini ou non
 * @return false s'il n'y a pas de master password, true sinon
 */
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


/**
 * Chiffre et stocke un mot de passe
 * @param name nom de l'entrée
 * @param password mot de passe non chiffré
 * @param key clé de chiffrement
 */
void password_storage(char* name, const unsigned char* password, unsigned char* key, const char* file) {

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

    //printf("NONCE: %s\n CIPHER: %s\n", nonce, ciphertext);


    sodium_bin2base64(nonceB64, 300, nonce, strlen((char*)nonce), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(cipherB64, 300, ciphertext, strlen((char*)ciphertext), sodium_base64_VARIANT_ORIGINAL);


    // Taille totale de la ligne stockée
    size_t strsize = strlen(NEW_LINE) + strlen(name) + strlen(SEPARATOR) + strlen(cipherB64) + strlen(SEPARATOR) + strlen(nonceB64);

    snprintf(buff, strsize, "%s%s%s%s%s%s", NEW_LINE, name, SEPARATOR, cipherB64, SEPARATOR, nonceB64);


    // Stockage dans un fichier
    FILE* allPW = fopen(file, "a+");
    fprintf(allPW, "%s", buff);
    fclose(allPW);

    // Libération des pointeurs
    free(buff);
    free(nonceB64);
    free(cipherB64);
}


/**
 * Retrouve et déchiffre un mot de passe
 * @param name nom de l'entrée à retrouver
 * @param key clé de déchiffrement
 * @return le mot de passe déchiffré
 */
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


    // Récupération des mots de passe
    FILE* allPWFile = fopen(ALLPW_FILENAME, "r");
    if(allPWFile == NULL) {
        printf("No file!\n");
        return NULL;
    }

    name = strcat(name, SEPARATOR);

    // Parcours ligne par ligne
    while (getline(&line, &len, allPWFile) != -1) {
        // Si l'entrée demandée est trouvée
        if (strstr(line , name )!= NULL)
        {
            // Récupération du mot de passe chiffré et du nonce
            cipher = strtok(line, SEPARATOR);
            cipher = strtok(NULL, SEPARATOR);
            nonce = strtok(NULL, SEPARATOR);
            break;
        }
    }

    fclose(allPWFile);


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



    //printf("cipher: %s\n nonce: %s\n", cipher, nonce);


    sodium_base642bin(nonceDecoded, crypto_aead_chacha20poly1305_NPUBBYTES, nonce, strlen(nonce), NULL, &lenDecodedNonce, NULL, sodium_base64_VARIANT_ORIGINAL);
    sodium_base642bin(cipherDecoded, 300, cipher, strlen(cipher), NULL, &lenDecodedCipher, NULL, sodium_base64_VARIANT_ORIGINAL);

    //printf("taille nonce %zu\n taille cipher %zu\n", lenDecodedNonce, lenDecodedCipher);

    nonceDecoded[crypto_aead_chacha20poly1305_NPUBBYTES] = 0;
    cipherDecoded[lenDecodedCipher] = 0;

    //printf("decoded nonce: %s\n decoded cipher: %s\n", nonceDecoded, cipherDecoded);

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

/**
 * Récupère la clé de chiffrement et déchiffrement
 * @param masterPW master password non chiffré
 * @return la clé de chiffrement et déchiffrement
 */
char* get_key(char* masterPW) {
    unsigned char* key = locked_allocation(crypto_aead_chacha20poly1305_KEYBYTES);
    long len;
    // Récupération du sel
    FILE* saltFile = fopen(SALT_FILENAME, "r");
    if(saltFile == NULL) {
        printf("No salt!\n");
        return NULL;
    }
    fseek (saltFile, 0, SEEK_END);
    len = ftell (saltFile);
    fseek (saltFile, 0, SEEK_SET);
    unsigned char* salt = malloc((size_t)len);

    fread (salt, 1, (size_t )len, saltFile);
    fclose(saltFile);

    printf("%s", salt);
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

/**
 * Dérive une clé de chiffrement et déchiffrement et stocke son sel
 * @param masterPW master password non chiffré
 * @return
 */
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
    printf("%s", salt);

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

}

/**
 * Change le master password
 * @param masterPW master password non chiffré
 * @param oldKey clé de chiffrement et déchiffrement actuellement utilisée
 * @return la nouvelle clé de chiffrement et déchiffrement
 */
char* change_masterPW(char* masterPW, unsigned char* oldKey) {

    remove(MASTERPW_FILENAME);
    masterPassword_storage(masterPW);


    char* newKey = key_derivation_and_storage(masterPW);

    char* line = NULL;
    size_t len = 0;
    char* name = NULL;
    char* cipher = NULL;
    char* nonce = NULL;


// Récupération du mot de passe chiffré et du nonce correspondant
    FILE* allPW = fopen(ALLPW_FILENAME, "r");
    if(allPW == NULL) {
        return NULL;
    }

    // Parcours ligne par ligne
    while (getline(&line, &len, allPW) != -1) {

            // Récupération du nom de l'entrée
        name = strtok(line, SEPARATOR);
        unsigned char* password = password_recover(name, oldKey);
        if(password != NULL){
            printf("%s %s\n", name, password);
            password_storage(name, password, (unsigned char*)newKey, TEMPORARY_FILE);
            //free(password);
        }


    }

    remove(ALLPW_FILENAME);
    rename(TEMPORARY_FILE, ALLPW_FILENAME);

    fclose(allPW);

    return newKey;

}