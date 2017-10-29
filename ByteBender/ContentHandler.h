//
// Created by drich on 6/3/17.
//

#pragma once

#include <folly/Memory.h>
#include <proxygen/httpserver/RequestHandler.h>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <pcap.h>
#include <netinet/if_ether.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void store_type(std::string packetData);

namespace ContentService {
    class ContentHandler : public proxygen::RequestHandler {
    public:
        explicit ContentHandler(int sequenceNumber, std::mutex& contentHandlerMutex);

        void onRequest(std::unique_ptr<proxygen::HTTPMessage> headers)
        noexcept override;

        void onBody(std::unique_ptr<folly::IOBuf> body) noexcept override;

        void onEOM() noexcept override;

        void onUpgrade(proxygen::UpgradeProtocol proto) noexcept override;

        void requestComplete() noexcept override;

        void onError(proxygen::ProxygenError err) noexcept override;


    private:
        std::unique_ptr<proxygen::HTTPMessage> httpMessage_;
        std::unique_ptr<folly::IOBuf> body_;
    };
}