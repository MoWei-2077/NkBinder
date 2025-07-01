#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
 
int main() {
    int skfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    int len = 0;
    struct sockaddr_un addr;
    char buffer[128];
    if (skfd < 0) {
        printf("socket failed\n");
        return -1;
    }
 
    addr.sun_family  = AF_LOCAL;
    addr.sun_path[0]  = 0;  
    memcpy(addr.sun_path  + 1, "nkbinder", strlen("nkbinder") + 1);
 
    len = 1 + strlen("nkbinder") + offsetof(struct sockaddr_un, sun_path);
 
    if (connect(skfd, (struct sockaddr*)&addr, len) < 0) {
        printf("connect failed\n");
        close(skfd);
        return -1;
    }

    while (true) {
        recv(skfd, buffer, sizeof(buffer), 0);

        #if DEBUG_DURATION
            printf("NkBinder: %s\n", buffer);
        #endif

        auto ptr = strstr(buffer, "from_uid=");

        if (ptr != nullptr) {
            const int uid = atoi(ptr + 9);
            printf("uid: %d\n", uid);
        }

    }
 
    close(skfd);
    return 0;
}
