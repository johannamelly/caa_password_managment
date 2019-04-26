//
// Created by johanna on 10.04.19.
//
#pragma once

#include <stdio.h>
#include <sodium.h>
#include <memory.h>
#include <errno.h>

void* locked_allocation(size_t nb_bytes){
    if(sodium_init() < 0){
        printf("Couldn't initialize the library");
        return NULL;
    }
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

void * free_buffer(void* mem, size_t nb_bytes) {
    sodium_munlock(mem, nb_bytes);
    sodium_free(mem);
}