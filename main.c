#include <stdio.h>
#include <sodium.h>
#include <stdbool.h>
#include "memory.c"
#include "actions.c"
#include "password_management.c"
#include "base64.h"

enum state {
    NOT_RUNNING,
    LOCKED,
    UNLOCKED
};


enum state currentSate = NOT_RUNNING;

int main(int argc, char*argv[]) {
    //const char* lou = "PANTALONDEMAMANààà3éà3à3ààà";

    //char* encoded = malloc(300);
    //char* decoded = malloc(300);
    //sodium_bin2base64(encoded, 300, lou, strlen(lou), sodium_base64_VARIANT_ORIGINAL);
    //printf("%s", encoded);
    //((sodium_base642bin(decoded, 300, encoded, strlen(encoded), NULL, strlen(decoded), NULL, sodium_base64_VARIANT_ORIGINAL);
    //printf("%s", decoded);

    currentSate = LOCKED;

    int choice;

    if(sodium_init() < 0){
        printf("Couldn't initialize the library");
        return(-1);
    }

    printf("Welcome!\n");

    while(currentSate == LOCKED) {
        if(login()){
            currentSate = UNLOCKED;

            while(currentSate == UNLOCKED) {
                printf("What's your choice?\n");
                printf("1 - Add password\n");
                printf("2 - Find password\n");
                printf("3 - List all entries\n");
                printf("4 - Change master password\n");
                printf("5 - Lock\n");
                printf("6 - Quit\n");


                scanf("%d", &choice);
                switch(choice){
                    case 1:
                        add_password();
                        break;
                    case 2:
                        get_password();
                        break;
                    case 3:
                        printf("You store passwords for: ");
                        list_names();
                        printf("\n");
                        break;
                    case 5:
                        printf("Session locked.\n");
                        currentSate = LOCKED;
                        break;
                    case 6:
                        currentSate = NOT_RUNNING;
                        return 0;
                    default:
                        currentSate = NOT_RUNNING;
                        return 0;
                }
            }
        }
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

    return 0;
}
