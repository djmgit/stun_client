#include <stdio.h>	//printf
#include <string.h> //memset
#include <stdlib.h> //exit(0);
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

#define STUN_SERVER "216.93.246.18"
#define STUN_SERVER_PORT 3478
#define REQ_LEN_BASE 20
#define BUFLEN 200	//Max length of buffer
#define MAX_IP_LENGTH_STR 16 // 3*4 + 3 + 1

#define exitWithError(msg)    do {perror(msg); exit(EXIT_FAILURE);} while (0)

void stunRequest(char *stunHost, uint16_t stunPort, uint8_t *stunData, uint8_t stunDataLen, char *extHost, uint16_t *extPort,
                 char *changedHost, uint16_t *changedPort) {
    struct sockaddr_in stunServerAddr;
    struct sockaddr_in clientAddr;
    int sock, stunServerAddrLen = sizeof(stunServerAddr);
    uint8_t *stunRequest = (uint8_t *)malloc((REQ_LEN_BASE + stunDataLen) * sizeof(uint8_t));
    uint8_t stunResponse[BUFLEN];

    memset(stunRequest, 0, REQ_LEN_BASE + stunDataLen);
    if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        exitWithError("socket could not be created");
    }

    memset((uint8_t *)&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(54320);
    clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&clientAddr, sizeof(clientAddr)) == -1) {
        exitWithError("bind failed");
    }

    memset((uint8_t *)&stunServerAddr, 0, sizeof(stunServerAddr));
    stunServerAddr.sin_family = AF_INET;
    stunServerAddr.sin_port = htons(stunPort);
    if (inet_aton(stunHost, &stunServerAddr.sin_addr) == 0) {
        exitWithError("inet_pton failed");
    }

    printf("Sending bind request to stun server\n");

    *(short *)(&stunRequest[0]) = htons(0x0001);
	*(short *)(&stunRequest[2]) = htons(stunDataLen);
	*(int *)(&stunRequest[4])   = htonl(0x11111111);
	*(int *)(&stunRequest[8]) = htonl(0x22222222);
	*(int *)(&stunRequest[12])= htonl(0x33333333);
	*(int *)(&stunRequest[16])= htonl(0x44444444);
    if (stunDataLen == 0x0008 && stunData != NULL){
        //*(uint16_t *)(&stunRequest[20])= htons(0x0003);
        //*(short *)(&stunRequest[22])= htons(0x0004);
        //*(int *)(&stunRequest[24])= htons(0x00000006);
        *(uint64_t *)(&stunRequest[20]) = *(uint64_t *)stunData;
    }

    int r = sendto(sock, stunRequest, REQ_LEN_BASE + stunDataLen, 0, (struct sockaddr *)&stunServerAddr, stunServerAddrLen);
    if (r == -1) {
        exitWithError("send failed");
    }

    memset(stunResponse, '\0', BUFLEN);
    r = recvfrom(sock, stunResponse, BUFLEN, 0, NULL, 0);
    if (r == -1) {
        exitWithError("Failed to receive");
    }

    uint16_t rtype = *(uint16_t *)(&stunResponse[0]);
    printf("Recived message type: %x\n", rtype);

    uint16_t len = htons(*(uint16_t *)(&stunResponse[2]));
    printf("Received message length: %d\n", len);

    int i = 20;
    uint16_t attrType;
    uint16_t attrLen;
    while(i < sizeof(stunResponse)) {
        attrType = htons(*(uint16_t *)&stunResponse[i]);
        //printf("attrType: %x\n", attrType);
        attrLen = htons(*(uint16_t *)&stunResponse[i+2]);
        //printf("attrLen: %x\n", attrLen);
        if (attrType == 0x0001) {
            uint16_t port = ntohs(*(uint16_t *)&stunResponse[i+6]);
            printf("external port: %d\n", port);
            *extPort = port;

            uint8_t ip1 = stunResponse[i+8];
            uint8_t ip2 = stunResponse[i+9];
            uint8_t ip3 = stunResponse[i+10];
            uint8_t ip4 = stunResponse[i+11];
            snprintf(extHost, MAX_IP_LENGTH_STR, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
            printf("external IP: %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
        }
        if (attrType == 0x0005) {
            uint16_t port = ntohs(*(uint16_t *)&stunResponse[i+6]);
            printf("changed port: %d\n", port);
            *changedPort = port;

            uint8_t ip1 = stunResponse[i+8];
            uint8_t ip2 = stunResponse[i+9];
            uint8_t ip3 = stunResponse[i+10];
            uint8_t ip4 = stunResponse[i+11];
            snprintf(changedHost, MAX_IP_LENGTH_STR, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
            printf("changed IP: %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);
        }
        i += (4 + attrLen);
    }
}

int main() {
    char *extHost = (char *)malloc(16 * sizeof(char));
    uint16_t extPort = 0;
    char *changedHost = (char *)malloc(16 * sizeof(char));
    uint16_t changedPort = 0;
    stunRequest(STUN_SERVER, STUN_SERVER_PORT, NULL, 0, extHost, &extPort, changedHost, &changedPort);
    printf("IP : %s\n", extHost);
}
