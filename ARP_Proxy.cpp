#include <tins/tins.h>
#include <iostream>
#include <unordered_map>
#include <thread>
#include <vector>
#include <csignal>

using namespace Tins;
using namespace std;


//Giao dien VLAN tr
vector <string> interfaces = {"eth0.10", "eth0.20"};
vector <string> vlan_ips = {"192.168.10.254", "192.168.20.254"};
unordered_map <string, HWAddress<6>> ip_to_mac;

bool running = true;
void signal_handler(int sig) {
    running = false;
}

class ARP_Proxy_Iface {
    private:
        string Iface_name;
    public:
        ARP_Proxy_Iface (string ifa) {
            this->Iface_name = ifa;
        }
        void Send_ARP_Reply (const string &, const HWAddress<6>&, const string&, const HWAddress<6>&, const string &);
        void Packet_Handle (PDU &);
        void Sniffer_Interface();
};

void ARP_Proxy_Iface :: Send_ARP_Reply (const string &src_ip, const HWAddress<6>& src_mac, 
                    const string &dst_ip, const HWAddress<6>& dst_mac, string const &out_if) {
    ARP arp;
    EthernetII packet = arp.make_arp_reply(dst_ip, src_ip, dst_mac, src_mac);
    PacketSender sender;
    sender.send(packet, out_if);
}

void ARP_Proxy_Iface :: Packet_Handle (PDU &pdu) {
    string out_if;
    HWAddress<6> proxy_mac;
    bool is_local = false;


    const ARP& arp = pdu.rfind_pdu<ARP>();

    if (arp.opcode() != ARP::REQUEST) return;
    string source_ip = arp.sender_ip_addr().to_string();
    string des_ip = arp.target_ip_addr().to_string();
    
    NetworkInterface in_interface(this->Iface_name);
    string my_ip = in_interface.ipv4_address().to_string();
    if (my_ip == source_ip) {
        return ;
    }

    for (int i = 0; i < interfaces.size(); i++) {
        if (source_ip.compare(0, 9, vlan_ips.at(i), 0, 9)) {
            out_if = interfaces.at(i);
            NetworkInterface out_interface (out_if);
            proxy_mac = out_interface.hw_address();
            is_local = true;
            break;
        }
    }

    if (!is_local) {
        return ;
    }
    cout << "ARP Proxy Reply" << "in " << out_if << "IP Source: " << des_ip << " - IP Des: " << source_ip 
                << " MAC Source: " << proxy_mac << " - MAC Des: " << arp.sender_hw_addr().to_string() << endl;
    
    Send_ARP_Reply (des_ip, proxy_mac, source_ip, arp.sender_hw_addr(), out_if);    
}

void ARP_Proxy_Iface ::Sniffer_Interface() {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("arp");
        
    Sniffer my_Sniffer (this->Iface_name, config);
    while(running) {
        PDU *pdu = my_Sniffer.next_packet();
        this->Packet_Handle(const_cast<PDU&>(*pdu));
    }
}

class ARP_Proxy_Pi4 : public ARP_Proxy_Iface {
    private:
        vector <ARP_Proxy_Iface*> Pi4_Interface;
    public:
        ARP_Proxy_Pi4() : ARP_Proxy_Iface("Lio") {};
        void Add_Interface (ARP_Proxy_Iface *);
        void ARP_Proxy_Handle_Full();
};

void ARP_Proxy_Pi4 ::Add_Interface (ARP_Proxy_Iface *iface) {
    Pi4_Interface.push_back(iface);
}

void ARP_Proxy_Pi4::ARP_Proxy_Handle_Full() {
    vector <thread> ARP_Handle_Threads;
    for (auto* iface : Pi4_Interface) {
        thread t([iface]() {
            iface->Sniffer_Interface();
        });
        ARP_Handle_Threads.push_back(std::move(t));  
    }
    cout << "ARP Proxy running... Press Ctrl+C to stop.\n";
    for (auto& t : ARP_Handle_Threads) t.join();     
}

int main() {
    signal(SIGINT, signal_handler);
    ARP_Proxy_Pi4 Pi4;
    ARP_Proxy_Iface Interface1(interfaces.at(0));
    ARP_Proxy_Iface Interface2(interfaces.at(1));
    Pi4.Add_Interface(&Interface1);
    Pi4.Add_Interface(&Interface2);    

    Pi4.ARP_Proxy_Handle_Full();
    return 0;
}
