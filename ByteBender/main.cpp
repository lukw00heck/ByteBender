#include <iostream>
#include <folly/Memory.h>
#include <folly/io/async/EventBaseManager.h>
#include <proxygen/httpserver/HTTPServer.h>
#include "ContentHandler.h"

using namespace ContentService;
using namespace proxygen;
using folly::SocketAddress;

class MessageHandlerFactory : public RequestHandlerFactory {
public:
    void onServerStart(folly::EventBase* evb) noexcept override {
        sequenceNumber = 0;
        std::cout << "Server is running" << std::endl;
    }

    void onServerStop() noexcept override {
        sequenceNumber = 0;
    }

    RequestHandler* onRequest(RequestHandler*, HTTPMessage* httpMessage) noexcept override {
        httpMessage->dumpMessage(-1);
        return new ContentHandler(sequenceNumber, messsageHandlerMutex);
    }

private:
    int sequenceNumber = 0;
    std::mutex messsageHandlerMutex;
};

int main(int argc, char* argv[]){


//    switch (fork()) {
//        case -1:
//            return -1;
//        case 0:
//            break;
//        default:
//            _exit(EXIT_SUCCESS);
//    }
//
//    if (setsid() == -1) {
//        return -1;
//    }
//
//    switch (fork()) {
//        case -1:
//            return -1;
//        case 0:
//            break;
//        default:
//            _exit(EXIT_SUCCESS);
//    }
//
//    umask(0);
//    chdir("/");
//
//    long maxfd = sysconf(_SC_OPEN_MAX);
//    if (maxfd == -1) {
//        maxfd = 64;
//    }
//
//    for (int fd = 0; fd < maxfd; ++fd) {
//        close(fd);
//    }
//
//    close(STDIN_FILENO);
//
//    int fd = open("/dev/null", O_RDWR);
//
//    if (fd != STDIN_FILENO) {
//        return -1;
//    }
//
//    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) {
//        return -1;
//    }
//
//    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
//        return -1;
//    }

    google::InitGoogleLogging(argv[0]);

    std::vector<HTTPServer::IPConfig> IPs = {
            {SocketAddress("127.0.0.1", 22000, true), HTTPServer::Protocol::HTTP}
    };

    HTTPServerOptions options;
    options.idleTimeout = std::chrono::milliseconds(60000);
    options.shutdownOn = {SIGINT, SIGTERM};
    options.enableContentCompression = false;
    options.handlerFactories = RequestHandlerChain()
            .addThen<MessageHandlerFactory>()
            .build();

    HTTPServer server(std::move(options));
    server.bind(IPs);

    // Start HTTPServer mainloop in a separate thread
    std::thread t([&] () {
        server.start();
    });

    t.join();
    return 0;
}

