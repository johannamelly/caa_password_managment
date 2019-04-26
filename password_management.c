//
// Created by johanna on 10.04.19.
//

#include <stdbool.h>
#include <stdio.h>
#include <sodium.h>
#include <memory.h>
#include "memory.c"

#define CONTEXT "Pencrypt"

const char* MASTERKEY_FILENAME = "masterKey.txt";
const char* MASTERPW_FILENAME = "masterPW.txt";
const char* ALLPW_FILENAME = "allPW.txt";
const char* SEPARATOR = "\t";
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


bool password_storage(char* name, char* password) {

    // Allocations mémoire
    unsigned char* key = locked_allocation(crypto_pwhash_STRBYTES);
    char* buff = locked_allocation(512*sizeof(char));
    unsigned char* pw = malloc(300);

    // Récupération de la master key
    FILE* masterKey = fopen(MASTERKEY_FILENAME, "r");
    fscanf(masterKey, "%s", key);
    fclose(masterKey);

    // Génération et stockage d'un nonce
    unsigned char nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // Variables utiles au chiffrement
    unsigned char ciphertext[strlen(password) + crypto_aead_chacha20poly1305_ABYTES];
    unsigned long long ciphertext_len;
    unsigned long long password_len;

    // Chiffrement
    crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                         password, strlen(password),
                                         NULL, 0,
                                         NULL, nonce, key);

    // Taille totale de la ligne stockée
    size_t strsize = strlen(name) + strlen(SEPARATOR) + strlen((char*)key) + strlen(NEW_LINE) + strlen((char*)nonce);

    // Stockage dans un fichier
    snprintf(buff, strsize, "%s%s%s%s%s%s", NEW_LINE, name, SEPARATOR, ciphertext, SEPARATOR, nonce);
    FILE* allPW = fopen(ALLPW_FILENAME, "a+");
    fprintf(allPW, "%s", buff);
    fclose(allPW);


    // Libération des pointeurs
    free_buffer(key, crypto_pwhash_STRBYTES);
    free_buffer(buff, 512* sizeof(char));
    free(pw);
    return true;

}


unsigned char* password_recover(char* name) {

    // Allocations mémoire
    unsigned char* key = locked_allocation(crypto_pwhash_STRBYTES);
    unsigned char* password = malloc(256*sizeof(char));

    // Récupération de la master key
    FILE* masterKey = fopen(MASTERKEY_FILENAME, "r");
    fscanf(masterKey, "%s", key);
    fclose(masterKey);

    unsigned long long password_len;
    char* line = NULL;
    size_t len = 0;
    char* cipher = malloc(256);
    char* nonce = malloc(256);

    // Récupération du mot de passe chiffré et du nonce correspondant
    FILE* allPW = fopen(ALLPW_FILENAME, "r");

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

    // Déchiffrement
    if (crypto_aead_chacha20poly1305_decrypt(password, &password_len,
                                             NULL,
                                             cipher, strlen(cipher),
                                             NULL,
                                             0,
                                             nonce, key) != 0) {
        // Si échec, libération des pointeurs
        free_buffer(key, crypto_pwhash_STRBYTES);
        free(password);
        printf("Error!\n");
        return NULL;
    }

    // Libération des pointeurs
    //free(password);
    free_buffer(key, crypto_pwhash_STRBYTES);

    return password;

}


void key_derivation_and_storage() {

    // Allocation mémoire
    unsigned char* hashed_password = locked_allocation(crypto_pwhash_STRBYTES);

    // Buffer qui contiendra la clé
    uint8_t subkey1[64];

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

