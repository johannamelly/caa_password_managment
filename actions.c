//
// Created by Johanna
//

#pragma once
#include <stdio.h>
#include "memory.c"
#include "password_management.c"

/**
 * Contrôle que le master password utilisateur soit correct ou, si 1ere utilisation, lui demande d'en créer un
 * @return La clé de chiffrement et déchiffrement de mots de passes
 */
char* login() {
    char* masterKey = locked_allocation(crypto_aead_chacha20poly1305_KEYBYTES);

    // S'il n'y a pas de master password
    if(!masterPWdefined()) {

        // Destruction du fichier de mot de passe
        remove(ALLPW_FILENAME);

        // Allocation mémoire pour le master password
        char* mpw = locked_allocation(36*(sizeof(char*)));
        printf("You haven't defined a master password yet. Please provide a master password: ");
        scanf("%35s", mpw);

        // Stockage du master password dans un fichier
        if(masterPassword_storage(mpw)){
            printf("Successfully created your master password!!\n");
            // Création d'une clé correspondante
            masterKey = key_derivation_and_storage(mpw);

            // Si la génération de clé s'est mal passée
            if(masterKey == NULL) {
                printf("Sorry, we were not able to generate a key.\n");

                // Libération de la mémoire
                free_buffer(masterKey, crypto_aead_chacha20poly1305_KEYBYTES);
                free_buffer(mpw, 36* sizeof(char*));
                return NULL;
            }

            // Libéraion de la mémoire
            free_buffer(mpw, 36* sizeof(char*));
            return masterKey;
        } else {
            printf("Sorry, we were not able to create your password.\n");

            // Libération de la mémoire
            free_buffer(mpw, 36* sizeof(char*));
            return NULL;
        }
    } else {

        // Allocation mémoire
        char* mpw = locked_allocation(36*(sizeof(char*)));
        printf("Please provide your master password: ");
        scanf("%35s", mpw);

        // Vérification du master password
        if(masterPassword_verify(mpw)) {
            printf("Successful login.\n\n");

            // Dérivation de la clé correspondante
            masterKey = get_key(mpw);

            // Si la génération s'est mal passée
            if(masterKey == NULL) {
                printf("Sorry, we were not able to get your key.\n");

                // Libération de la mémoire
                free_buffer(masterKey, crypto_aead_chacha20poly1305_KEYBYTES);
                free_buffer(mpw, 36* sizeof(char*));
                return NULL;
            }

            // Libération de la mémoire
            free_buffer(mpw, 36* sizeof(char*));
            return masterKey;
        } else {
            printf("Failed to login.\n\n");

            // Libération de la mémoire
            free_buffer(masterKey, crypto_aead_chacha20poly1305_KEYBYTES);
            free_buffer(mpw, 36* sizeof(char*));
            return NULL;
        }
    }
}

/**
 * Liste les entrées de mots de passe
 */
void list_names() {
    char* line = NULL;
    size_t len = 0;

    // Ouverture du fichier
    FILE* allPW = fopen(ALLPW_FILENAME, "r");
    if(allPW == NULL) {
        printf("nothing at all!\n");
        return;
    }

    // Lecture des noms
    while (getline(&line, &len, allPW) != -1) {
        printf("%s\n", strtok(line, SEPARATOR));
    }

    fclose(allPW);
}


/**
 * Retrouve et déchiffre un mot de passe à partir de son nom
 * @param key la clé de déchiffrement
 */
void get_password(unsigned char* key) {

    // Allocation mémoire
    char* name = malloc(300*sizeof(char));

    // Récupération du nom auprès de l'utilisateur
    printf("What's the name of the password you'd like to get? ");
    scanf("%s", name);

    // Récupération du mot de passe correspondant
    unsigned char* password = password_recover(name, key);
    if(password == NULL) {
        printf("Sorry, we could not get your password.\n"
                       "You might have provided a wrong name.\n"
                       "Consider having a look at the list of entries.\n\n");
    } else {
        printf("Your password is:\n%s\n\n", password);
    }

    // Libérations mémoire
    if(password != NULL) {
        free_buffer(password, 300);
    }

    free(name);
}

/**
 * Chiffre et stocke un mot de passe
 * @param key la clé de chiffrement
 */
void add_password(unsigned char* key) {

    // Allocations mémoire
    char* name = malloc(300*sizeof(char));
    char* password = locked_allocation(300*sizeof(char));

    // Récupération de nom auprès de l'utilisateur
    printf("Please give the name of your password. For what will you use it (i.e. facebook, outlook, ...)? ");
    scanf("%s", name);

    // Récupération du mot de passe auprès de l'utilisateur
    printf("Good. Now please type your password. ");
    scanf("%s", password);

    // Stockage du mot de passe
    password_storage(name, (unsigned char*)(password), key, ALLPW_FILENAME);
    printf("Your password has been saved!\n\n");

    // Libérations mémoire
    free_buffer(password, 300*sizeof(char));
    free(name);

}

/**
 * Change le master password
 * @param key la clé de chiffrement et déchiffrement
 */
void change_mwp(unsigned char* key) {
    // Allocarions mémoire
    char* mpw = locked_allocation(36*(sizeof(char*)));

    // Récupération du nouveau mot de passe
    printf("Please type your new password: ");
    scanf("%35s", mpw);

    // Changement du mot de passe
    change_masterPW(mpw, key);

    // Libération mémoire
    free_buffer(mpw, 36*sizeof(char*));

}