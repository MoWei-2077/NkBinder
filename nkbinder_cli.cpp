#include <android-base/macros.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <bpf/BpfMap.h>
#include <bpf/BpfUtils.h>
#include <libbpf.h>
#include <libbpf_android.h>
#include "nkbinder.h"

constexpr const char tp_prog_path[] = "/sys/fs/bpf/prog_nkbinder_tracepoint_binder_binder_transaction";
constexpr const char tp_map_path[] = "/sys/fs/bpf/map_nkbinder_binder_transaction_map";

constexpr const char* SOCKET_NAME = "nkbinder";
constexpr int MESSAGE_LENGTH = 128;

struct sockaddr_un addr;


int setup_socket_server() {
    int server_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }

    addr.sun_path[0] = 0;
    strcpy(addr.sun_path + 1, SOCKET_NAME);
    int nameLen = strlen(SOCKET_NAME);
    addr.sun_family = AF_LOCAL;
    int len = 1 + nameLen + offsetof(struct sockaddr_un, sun_path);

    unlink(addr.sun_path);

    if (bind(server_fd, (struct sockaddr*)&addr, len) < 0) {
        perror("bind");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }

    int flags = fcntl(server_fd, F_GETFL, 0);
    fcntl(server_fd, F_SETFL, flags | O_NONBLOCK);

    return server_fd;
}

int main() {
    int server_fd = setup_socket_server();
    if (server_fd < 0) {
        exit(EXIT_FAILURE);
    }
    int client_fd = -1;
    int mProgFd = bpf_obj_get(tp_prog_path);
    bpf_attach_tracepoint(mProgFd, "binder", "binder_transaction");
    sleep(4);
    android::bpf::BpfMap<int, binder_transaction_event> binder_transaction_map(tp_map_path);

    const auto iterFunc = [&](const int &key, const binder_transaction_event &value,
                            android::bpf::BpfMap<int, binder_transaction_event> &) {
        binder_transaction_map.deleteValue(key);

        if (value.flags & TF_ONE_WAY) {
            return android::base::Result<void>();
        }

        // 格式化固定长度消息
        char buffer[MESSAGE_LENGTH];
        snprintf(buffer, sizeof(buffer), "type=syncBinder from_uid=%d from_pid=%d to_pid=%d",
                value.from_uid, value.from_pid, value.to_pid);

        // 固定长度处理
        size_t len = strnlen(buffer, MESSAGE_LENGTH - 1);
        memset(buffer + len, ' ', MESSAGE_LENGTH - len - 1);
        buffer[MESSAGE_LENGTH - 1] = '\n';

        // 发送到客户端
        if (client_fd != -1) {
            ssize_t sent = send(client_fd, buffer, MESSAGE_LENGTH, MSG_NOSIGNAL);
            if (sent < 0) {
                close(client_fd);
                client_fd = -1;
            }
        }

        printf("debug_id:%d,from_uid:%d,from_pid:%d,to_pid:%d,code:%d,flags:%d\n",
              key, value.from_uid, value.from_pid, value.to_pid, value.code, value.flags);
        return android::base::Result<void>();
    };

    while (true) {
        // 处理新连接
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        int new_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);

        if (new_fd > 0) {
            if (client_fd != -1) {
                close(client_fd);
                std::cout << "Closing previous connection" << std::endl;
            }
            client_fd = new_fd;
            std::cout << "New client connected" << std::endl;
        }

        // 处理BPF事件
        usleep(40000);
        binder_transaction_map.iterateWithValue(iterFunc);
    }

    close(server_fd);
    unlink(addr.sun_path);
    exit(EXIT_SUCCESS);
}
