#include <list.h>
#include <time.h>
#include <openssl/sha.h>

PMList* generatePortsFromSecret(char* secret) {
    PMList* ports = list_new();
    int i;
    for(i = 0; i < strlen(secret); i+=8) {
        list_add(ports, (void*)secret[i]);
    }
    return ports;
}

int* htop(int key, int offset){

}

