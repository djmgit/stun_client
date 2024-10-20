#include <stdio.h>	//printf
#include <string.h> //memset
#include <stdlib.h> //exit(0);
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

#define STUN_SERVER "216.93.246.18"
#define STUN_SERVER_PORT "3478"
#define REQ_LEN 20
#define BUFLEN 512	//Max length of buffer

#define exitWithError(msg)    do {perror(msg); exit(EXIT_FAILURE);} while (0)

void stunRequest() {
    struct sockaddr_in stunServerAddr;
    int sock, stunServerAddrLen = sizeof(stunServerAddr);
    uint8_t stunRequest[REQ_LEN];
    uint8_t stunResponse[BUFLEN];

    if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        exitWithError("socket could not be created");
    }

    memset((uint8_t *)&stunServerAddr, 0, sizeof(stunServerAddr));
    stunServerAddr.sin_family = AF_INET;
    stunServerAddr.sin_port = htons(STUN_SERVER_PORT);
    if (inet_aton(STUN_SERVER, &stunServerAddr.sin_addr) == 0) {
        exitWithError("inet_pton failed");
    }

    printf("Sending bind request to stun server\n");

    *(short *)(&stunRequest[0]) = htons(0x0001);
	*(short *)(&stunRequest[2]) = htons(0x0000);
	*(int *)(&stunRequest[4])   = htonl(0x11111111);
	*(int *)(&stunRequest[8]) = htonl(0x22222222);
	*(int *)(&stunRequest[12])= htonl(0x33333333);
	*(int *)(&stunRequest[16])= htonl(0x44444444);

    int r = sendto(sock, stunRequest, sizeof(stunRequest), 0, (struct sockaddr *)&stunServerAddr, stunServerAddrLen);
    if (r == -1) {
        exitWithError("send failed");
    }

    memset(stunResponse, '\0', BUFLEN);
    r = recvfrom(sock, stunResponse, BUFLEN, 0, NULL, 0);
    if (r == -1) {
        exitWithError("Failed to receive");
    }

    uint16_t rtype = *(uint16_t *)(&stunResponse[0]);
    printf("%x\n", rtype);
}

int main() {
    stunRequest();
}