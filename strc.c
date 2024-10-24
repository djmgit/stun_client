#include<stdio.h>
#include<string.h>
#include<stdlib.h>

int main() {
    char *ch1 = (char *)malloc(sizeof(char) * 5);
    char *ch2 = (char *)malloc(sizeof(char) * 7);

    ch1 = "hello";
    ch2 = "hells";

    int i = strcmp(ch1, ch2);
    printf("%d\n", i);
}
