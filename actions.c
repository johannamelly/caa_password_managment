//
// Created by johanna on 26.04.19.
//

#pragma once
#include <stdio.h>
#include <stdbool.h>
#include "memory.c"
#include "password_management.c"

bool login() {
    if(!masterPWdefined()) {

        remove(ALLPW_FILENAME);
        remove(MASTERKEY_FILENAME);

        char* mpw = locked_allocation(36*(sizeof(char*)));

        printf("You haven't defined a master password yet. Please provide a master password: ");
        scanf("%36s", mpw);
        if(masterPassword_storage(mpw)){
            printf("Success!\n");
            key_derivation_and_storage();
            free_buffer(mpw, 36* sizeof(char*));
            return true;
        } else {
            printf("Sorry, we were not able to create your password.\n");
            free_buffer(mpw, 36* sizeof(char*));
            return false;
        }
    } else {
        char* mpw = locked_allocation(36*(sizeof(char*)));

        printf("Please provide your master password: ");
        scanf("%36s", mpw);
        if(masterPassword_verify(mpw)) {
            printf("Successful login.\n\n");
            free_buffer(mpw, 36* sizeof(char*));
            return true;
        } else {
            printf("Failed to login.\n\n");
            free_buffer(mpw, 36* sizeof(char*));
            return false;
        }
    }
}

void list_names() {
    char* line = NULL;
    size_t len = 0;

    FILE* allPW = fopen(ALLPW_FILENAME, "r");

    while (getline(&line, &len, allPW) != -1) {
        printf("%s\n", strtok(line, SEPARATOR));
    }
}


void get_password() {
    char* name = malloc(300*sizeof(char));
    printf("What's the name of the password you'd like to get? ");
    scanf("%s", name);
    unsigned char* password = password_recover(name);
    if(password == NULL) {
        printf("Sorry, we could not get your password.\n"
                       "You might have provided a wrong name. Consider having a look at the list of entered names.\n\n");
    } else {
        printf("Your password is:\n%s \n\n", password);
    }
    free(password);
}

void add_password() {
    char* name = malloc(300*sizeof(char));
    char* password = locked_allocation(300*sizeof(char));

    printf("Please give the name of your password. For what will you use it (i.e. facebook, outlook, ...)? ");
    scanf("%s", name);
    printf("Good. Now please type your password. ");
    scanf("%s", password);
    const unsigned char* p = (const unsigned char*)(password);
    password_storage(name, p);
    printf("Your password has been saved!\n\n");

    free_buffer(password, 300*sizeof(char));
    free(name);

}