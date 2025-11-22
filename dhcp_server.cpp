#include <tins/tins.h>
#include <iostream>
#include <csignal>
using namespace Tins;
using namespace std;

class DHCP_Server_Interface {
private:
    string name;
    string IP;
    HWAddress<6> MAC;

public:
    DHCP_Server_Interface(string name) : name(name) {}
    void Set_Info();
    void Scan_Packet();
    void Packet_Handle(PDU &pdu);
};

void DHCP_Server_Interface::Set_Info() {
    NetworkInterface iface(name);
    IP = iface.ipv4_address().to_string();
    MAC = iface.hw_address();
    cout << "Interface: " << name << " | IP: " << IP << " | MAC: " << MAC << endl;
}

void DHCP_Server_Interface::Packet_Handle(PDU &pdu) {

    // 2. Lấy RawPDU – DÙNG CON TRỎ + KIỂM TRA NULL
    const RawPDU raw = pdu.rfind_pdu<RawPDU>();
    if (raw.payload().empty()) {
        return;
    }

    const auto& payload = raw.payload();

    // 3. Parse DHCP – BẮT BUỘC CÓ TRY-CATCH!
    DHCP dhcp;
    try {
        dhcp = DHCP(payload.data(), static_cast<uint32_t>(payload.size()));
    } catch (...) {
        return;  // Bỏ qua gói lỗi → không crash!
    }

    // 4. XỬ LÝ DISCOVER
    if (dhcp.type() == DHCP::DISCOVER) {
        cout << "DHCP DISCOVER from " << dhcp.chaddr() << endl;

        DHCP offer;
        offer.opcode(DHCP::BOOTREPLY);        // BẮT BUỘC!
        offer.type(DHCP::OFFER);
        offer.yiaddr("192.168.10.120");
        offer.siaddr("192.168.10.1");
        offer.chaddr(dhcp.chaddr());
        offer.htype(1);
        offer.hlen(6);
        offer.xid(dhcp.xid());
        offer.server_identifier("192.168.10.1");
        offer.subnet_mask("255.255.255.0");
        offer.routers({"192.168.10.1"});
        offer.lease_time(86400);
        

        EthernetII pkt = EthernetII(dhcp.chaddr(), MAC) /
                         Tins::IP("255.255.255.255", "192.168.10.1") /
                         UDP(68, 67) /
                         RawPDU(offer.serialize());

        PacketSender sender;
        sender.send(pkt, name);
        cout << "--- OFFER sent to " << dhcp.chaddr() << endl;
    }

    // 5. XỬ LÝ REQUEST → GỬI ACK
    else if (dhcp.type() == DHCP::REQUEST) {
        cout << "DHCP REQUEST from " << dhcp.chaddr() << endl;

        // Kiểm tra client có chọn server của mình không (Option 54)
        auto opt = dhcp.search_option(DHCP::DHCP_SERVER_IDENTIFIER);
        if (opt) {
            uint32_t selected = *(uint32_t*)opt->data_ptr();
            if (IPv4Address(selected) != IPv4Address("192.168.10.1")) {
                cout << "Client chọn server khác → bỏ qua" << endl;
                return;
            }
        }

        DHCP ack;
        ack.opcode(DHCP::BOOTREPLY);
        ack.type(DHCP::ACK);
        ack.yiaddr("192.168.10.120");
        ack.siaddr("192.168.10.1");
        ack.chaddr(dhcp.chaddr());
        ack.htype(1);
        ack.hlen(6);
        ack.xid(dhcp.xid());
        ack.server_identifier("192.168.10.1");
        ack.subnet_mask("255.255.255.0");
        ack.routers({"192.168.10.1"});
        ack.lease_time(86400);

        EthernetII pkt = EthernetII(dhcp.chaddr(), MAC) /
                         Tins::IP("255.255.255.255", "192.168.10.1") /
                         UDP(68, 67) /
                         RawPDU(ack.serialize());

        PacketSender sender;
        sender.send(pkt, name);
        cout << "--- ACK sent to " << dhcp.chaddr() << " → IP cấp thành công!" << endl;
    }
}

void DHCP_Server_Interface::Scan_Packet() {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("udp port 67 or udp port 68");

    Sniffer sniffer(name, config);
    cout << "[START] Listening on " << name << endl;

    while (true) {
        PDU* pdu = sniffer.next_packet();
        if (!pdu) continue;

        Packet_Handle(*pdu);
        delete pdu;  // BẮT BUỘC – TRÁNH MEMORY LEAK!
    }
}

int main() {
    DHCP_Server_Interface server("eth0");
    server.Set_Info();
    server.Scan_Packet();
    return 0;
}