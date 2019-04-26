#include <stdio.h>
#include <sodium.h>
#include <stdbool.h>
#include "memory.c"
#include "password_management.c"

enum state {
    NOT_RUNNING,
    LOCKED,
    UNLOCKED
};


enum state currentSate = NOT_RUNNING;

int main(int argc, char*argv[]) {

    if(sodium_init() < 0){
        printf("Couldn't initialize the library");
        return(-1);
    }

    printf("Welcome!\n");



        if(!masterPWdefined()) {
            char* mpw = locked_allocation(36*(sizeof(char*)));

            printf("You haven't defined a master password yet. Please provide a master password: ");
            scanf("%36s", mpw);
            if(masterPassword_storage(mpw)){
                printf("Success!\n");
                key_derivation_and_storage();
            } else {
                printf("Sorry, we were not able to create your password.\n");
                //TODO free buffer and terminate program
            }
            free_buffer(mpw, 36*(sizeof(char*)));
        } else {
            char* mpw = locked_allocation(36*(sizeof(char*)));

            printf("Please provide your master password: ");
            scanf("%36s", mpw);
            if(masterPassword_verify(mpw)) {
                printf("Successful login.");
            } else {
                printf("Failed to login.");
            }
            free_buffer(mpw, 36* sizeof(char*));
        }


    printf("%s", password_recover("johanna"));
   /*
        char* name = malloc(36*(sizeof(char*)));
        char* password = locked_allocation(36*(sizeof(char*)));
        printf("For what website or software would you like to store your password? ");
        scanf("%36s", name);
        printf("Now please type your password: ");
        scanf("%36s", password);

        if(password_storage(name, password)) {
            printf("oui\n");
        } else {
            printf("non\n");
        }
        free_buffer(password, 36* sizeof(char*));

*/
        //password_recover("telegram");
/*

        char buf[20];
        randombytes_buf(buf, 20);
        printf("%s",buf);
*/
        currentSate = LOCKED;




    return 0;
}

