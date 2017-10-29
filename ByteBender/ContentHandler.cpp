//
// Created by drich on 6/3/17.
//

#include "ContentHandler.h"
#include <iostream>
#include <fstream>
#include <proxygen/httpserver/ResponseBuilder.h>
#include <folly/dynamic.h>
#include <folly/json.h>
#include <regex>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include <cstdint>
#include <iostream>
#include <vector>
#include <bsoncxx/json.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/stdx.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/instance.hpp>
#include <pcap.h>

using bsoncxx::builder::stream::close_array;
using bsoncxx::builder::stream::close_document;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_array;
using bsoncxx::builder::stream::open_document;
using folly::dynamic;
using namespace proxygen;


namespace ContentService {
    static mongocxx::instance inst;

    ContentHandler::ContentHandler(int sequenceNumber, std::mutex &contentHandlerMutex) {}

    void ContentHandler::onRequest(std::unique_ptr<proxygen::HTTPMessage> httpMessage) noexcept {
        HTTPHeaders headers = httpMessage->getHeaders();
        std::string path = httpMessage->getPath();
        httpMessage_ = std::move(httpMessage);
    }

    void ContentHandler::onBody(std::unique_ptr<folly::IOBuf> body) noexcept {
        if (body_) {
            body_->prependChain(std::move(body));
        } else {
            body_ = std::move(body);
        }
    }

    static const char *_mk_NA(const char *p) {
        return p ? p : "N/A";
    }

    void ContentHandler::onEOM() noexcept {

        std::string path = httpMessage_->getPath();
        if (path.find("/location") == 0) {
            GeoIP *gi;
            GeoIPRecord *gir;
            char host[50];
            const char *time_zone = NULL;
            char **ret;

//            folly::fbstring contents = body_->moveToFbString();
//            const char *ipAddr = contents.c_str();
            const char *ipAddr = "71.39.50.134";
            gi = GeoIP_open("/home/drich/Desktop/GeoLiteCity.dat", GEOIP_INDEX_CACHE);
            if (gi == NULL) {
                fprintf(stderr, "Error opening database\n");
                exit(1);
            }

            gir = GeoIP_record_by_name(gi, (const char *) ipAddr);

            if (gir != NULL) {
                ret = GeoIP_range_by_ip(gi, (const char *) ipAddr);
                time_zone =
                        GeoIP_time_zone_by_country_and_region(gir->country_code,
                                                              gir->region);
                printf("%s\t%s\t%s\t%s\t%s\t%s\t%f\t%f\t%d\t%d\t%s\t%s\t%s\n", host,
                       _mk_NA(gir->country_code), _mk_NA(gir->region),
                       _mk_NA(GeoIP_region_name_by_code
                                      (gir->country_code,
                                       gir->region)), _mk_NA(gir->city),
                       _mk_NA(gir->postal_code), gir->latitude, gir->longitude,
                       gir->metro_code, gir->area_code, _mk_NA(time_zone), ret[0],
                       ret[1]);
                GeoIP_range_by_ip_delete(ret);
                GeoIPRecord_delete(gir);
            }
            GeoIP_delete(gi);
            return;
        } else if (path.find("/write") == 0) {
            mongocxx::client client{mongocxx::uri{}};
            mongocxx::database db = client["testing"];
            mongocxx::collection coll = db["testCollection"];
            document document{};
            document << "name" << "testDoc2";
            document << "thing2" << "uhhhhh Ice Age!";
            document << "thing3" << "Do the thing Jouly!";
            coll.insert_one(document.view());
        } else if (path.find("/read") == 0) {
            mongocxx::client client{mongocxx::uri{}};
            mongocxx::database db = client["testing"];
            mongocxx::collection coll = db["testCollection"];
            document document{};
            document << "name" << "testDoc2";

            mongocxx::stdx::optional<bsoncxx::document::value> readResponse = coll.find_one(document.view());
            if (readResponse) {
                auto accountView = readResponse.value().view();
                auto optionalElement = accountView["thing2"];
                if (optionalElement) {
                    std::cout << optionalElement.get_utf8().value.to_string() << std::endl;
                }
            }
        } else if (path.find("/update") == 0) {
            mongocxx::client client{mongocxx::uri{}};
            mongocxx::database db = client["testing"];
            mongocxx::collection coll = db["testCollection"];
            document filter{};
            filter << "name" << "testDoc2";

            coll.update_one(filter.view(),
                            document{} << "$set" << open_document <<
                                       "thing2" << "Hobbes was here" << close_document << finalize);
        } else if (path.find("/delete") == 0) {
            mongocxx::client client{mongocxx::uri{}};
            mongocxx::database db = client["testing"];
            mongocxx::collection coll = db["testCollection"];
            document filter{};
            filter << "name" << "Cafe Con Leche";

            mongocxx::stdx::optional<mongocxx::result::delete_result> result = coll.delete_one(filter.view());

            if (result) {
                std::cout << result->deleted_count() << std::endl;
            }

        } else if (path.find("/pcap") == 0) {
            pcap_t *handle;			/* Session handle */
            char *dev;			/* The device to sniff on */
            char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
            struct bpf_program fp;		/* The compiled filter */
            char filter_exp[] = "port 80";	/* The filter expression */
            bpf_u_int32 mask;		/* Our netmask */
            bpf_u_int32 net;		/* Our IP */
            struct pcap_pkthdr header; /* The header that pcap gives us */
            const u_char *packet;		/* The actual packet */

            /* Define the device */
            dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return;
            }
            /* Find the properties for the device */
            if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
                net = 0;
                mask = 0;
            }
            /* Open the session in promiscuous mode */
            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return;
            }
            /* Compile and apply the filter */
            if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return;
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return;
            }
            /* Grab a packet */
//            packet = pcap_next(handle, &header);
//            /* Print its length */
//            printf("Jacked a packet with length of [%d]\n", header.len);
            /* And close the session */
            pcap_loop(handle, -1, got_packet, nullptr);
            pcap_close(handle);
            return;
        }
    }

    void ContentHandler::onUpgrade(proxygen::UpgradeProtocol protocol) noexcept {}

    void ContentHandler::requestComplete() noexcept {
        delete this;
    }

    void ContentHandler::onError(proxygen::ProxygenError err) noexcept {
        delete this;
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (packet == nullptr) {
        printf("got null packet\n");
    } else {
        printf("got a packet of %u bytes!\n", header->len);
        ether_header *etherHeader = (ether_header *) packet;
        printf("ethernet type is %04x\n", ntohs(etherHeader->ether_type));
        printf("dest MAC is %02x:%02x:%02x %02x:%02x:%02x\n", etherHeader->ether_dhost[0], etherHeader->ether_dhost[1],
               etherHeader->ether_dhost[2], etherHeader->ether_dhost[3], etherHeader->ether_dhost[4], etherHeader->ether_dhost[5]);
        printf("source MAC is %02x:%02x:%02x %02x:%02x:%02x\n", etherHeader->ether_shost[0], etherHeader->ether_shost[1],
               etherHeader->ether_shost[2], etherHeader->ether_shost[3], etherHeader->ether_shost[4], etherHeader->ether_shost[5]);
        if (ntohs(etherHeader->ether_type) == ETHERTYPE_IP) {
            store_type("IPV4");
            printf("IPv4\n");
        } else if (ntohs(etherHeader->ether_type) == ETHERTYPE_ARP) {
            store_type("ARP");
            printf("ARP\n");
        } else if (ntohs(etherHeader->ether_type) == ETHERTYPE_IPV6) {
            store_type("IPV6");
            printf("IPv6\n");
        }
    }
}

void store_type(std::string packetData) {

    printf("Packet Stored\n");
    time_t currentTime = std::time(0);
    std::stringstream currentTimeString;
    currentTimeString << std::put_time(std::localtime(&currentTime), "%a %d %b %Y %H:%M:%S %z");

    mongocxx::client client{mongocxx::uri{}};
    mongocxx::database db = client["testing"];
    mongocxx::collection coll = db["packetType"];

    document document{};
    document << "captureDate" << currentTimeString.str();
    document << "data" << packetData;

    coll.insert_one(document.view());
}