/*
 * Created by Johanna
 */

#include <stdio.h>
#include <sodium.h>
#include "memory.c"
#include "actions.c"

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

    currentSate = LOCKED;
    int choice;
    char* masterKey;

    printf("Welcome!\n");

    while(currentSate == LOCKED) {
        if((masterKey = login()) != NULL){
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
                        add_password((unsigned char*)masterKey);
                        break;
                    case 2:
                        get_password((unsigned char*)masterKey);
                        break;
                    case 3:
                        printf("You store passwords for: ");
                        list_names();
                        printf("\n");
                        break;
                    case 4:
                        change_mwp((unsigned char*)masterKey);
                        currentSate = LOCKED;
                        break;
                    case 5:
                        free_buffer(masterKey, crypto_aead_chacha20poly1305_KEYBYTES);
                        printf("Session locked.\n");
                        currentSate = LOCKED;
                        break;
                    case 6:
                        free_buffer(masterKey, crypto_aead_chacha20poly1305_KEYBYTES);
                        currentSate = NOT_RUNNING;
                        return 0;
                    default:
                        free_buffer(masterKey, crypto_aead_chacha20poly1305_KEYBYTES);
                        currentSate = NOT_RUNNING;
                        return 0;
                }
                choice = 0;
            }
        } else {
            if(masterKey != NULL) {
                free_buffer(masterKey, crypto_aead_chacha20poly1305_KEYBYTES);
            }
        }
    }

    return 0;
}
