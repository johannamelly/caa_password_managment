//
// Created by Johanna
//
#pragma once

#include <stdio.h>
#include <sodium.h>
#include <memory.h>
#include <errno.h>

/**
 * Alloue de la mémoire de manière sécurisée
 * @param nb_bytes nombre de bytes à allouer
 * @return pointeur sur la mémoire allouée
 */
void* locked_allocation(size_t nb_bytes){

    void* mem = sodium_malloc(nb_bytes);

    if(mem == NULL){
        printf("Something went wrong %s\n", strerror(errno));
        return NULL;
    }
    if(sodium_mlock(mem, nb_bytes)){
        printf("Something went wrong %s\n", strerror(errno));
        sodium_free(mem);
        return NULL;
    }
    return mem;
}

/**
 * Libère la mémoire
 * @param mem pointeur sur la mémoire à libérer
 * @param nb_bytes nombre de bytes à libérer
 * @return
 */
void * free_buffer(void* mem, size_t nb_bytes) {
    sodium_munlock(mem, nb_bytes);
    sodium_free(mem);
}