#include "oauth.h"

// Cross-Platform Socket Headers & Macros
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <windows.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    using socket_t = SOCKET;
    #define CLOSE_SOCKET(s) closesocket(s)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    using socket_t = int;
    #define INVALID_SOCKET -1
    #define CLOSE_SOCKET(s) close(s)
#endif

#include <iostream>
#include <string>
#include <cstring>
#include <vector>

#include <Geode/utils/web.hpp>
#include <Geode/loader/Event.hpp>

using namespace geode::async;
using namespace geode::utils;

extern std::string CLIENT_ID;
extern std::string CLIENT_SECRET;

namespace helpers {
    extern std::function<void(web::WebResponse)> webHandler;
}

size_t writeCallback(void* data, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)data, size * nmemb);
    return size * nmemb;
}

void oauth::serverThread() {

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return;
    }
#endif

    // Listen socket
    socket_t lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock == INVALID_SOCKET) {
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    int reuse = 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8000);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(lsock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        CLOSE_SOCKET(lsock);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    listen(lsock, 1);

    // Client socket
    socket_t csock = accept(lsock, nullptr, nullptr);
    if (csock == INVALID_SOCKET) {
        CLOSE_SOCKET(lsock);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    // Set 10-second receive timeout
#ifdef _WIN32
    int timeout = 10000;
    setsockopt(csock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(csock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif

    char buffer[4096] = {};
    if (recv(csock, buffer, sizeof(buffer) - 1, 0) <= 0) {
        CLOSE_SOCKET(csock);
        CLOSE_SOCKET(lsock);
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    std::string request(buffer);

    std::string response =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "<h2 style='font-family:sans-serif'>There may be an error?</h2>"
        "<p style='font-family:sans-serif'>There's no oauth code, but also no error from discord. Something went wrong.</p>";

    size_t pos = request.find("GET /?code=");
    size_t posBad = request.find("GET /?error=");

    if (pos != std::string::npos) {

        auto start = pos + 11;
        auto end = request.find(' ', start);
        std::string oauth_code = request.substr(start, end - start);

        std::string params =
            "client_id=" + CLIENT_ID +
            "&client_secret=" + CLIENT_SECRET +
            "&grant_type=authorization_code" +
            "&code=" + oauth_code +
            "&redirect_uri=http://localhost:8000";

        static TaskHolder<web::WebResponse> listener;

        auto req = web::WebRequest();
        req.header("Content-Type", "application/x-www-form-urlencoded");
        req.body(std::vector<uint8_t>(params.begin(), params.end()));

        geode::prelude::log::info("sending auth");

        listener.spawn(
            req.post("https://discord.com/api/oauth2/token"),
            helpers::webHandler
        );

        geode::prelude::log::info("sent auth");

        response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<h2 style='font-family:sans-serif'>All set!</h2>"
            "<p style='font-family:sans-serif'>You can close this tab and go back to Geometry dash!</p>";

    } else if (posBad != std::string::npos) {

        response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<h2 style='font-family:sans-serif'>Discord Returned an OAuth error</h2>"
            "<p style='font-family:sans-serif'>Check this page's url for a (somewhat) more detailed description. Try the troubleshooting steps on the tutorial site.</p>";
    }

    send(csock, response.c_str(), static_cast<int>(response.length()), 0);

    CLOSE_SOCKET(csock);
    CLOSE_SOCKET(lsock);

#ifdef _WIN32
    WSACleanup();
#endif
}