#include "Ipc.h"
#include "Cli.h"

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace cli {

std::string defaultSocketPath() {
    return cacheDir() + "/comfy.sock";
}

bool connectDaemon(const std::string &path, int &fdOut, std::string &errOut) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        errOut = strerror(errno);
        return false;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        close(fd);
        errOut = strerror(errno);
        return false;
    }
    fdOut = fd;
    return true;
}

bool writeLine(int fd, const std::string &line) {
    std::string data = line + "\n";
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool readLine(int fd, std::string &lineOut) {
    static constexpr size_t kMax = 16 * 1024 * 1024;
    lineOut.clear();
    char c;
    while (true) {
        ssize_t n = ::read(fd, &c, 1);
        if (n <= 0) return false;
        if (c == '\n') return true;
        if (lineOut.size() >= kMax) return false;
        lineOut.push_back(c);
    }
}

} // namespace cli
