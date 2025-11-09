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

// Get networkinterface ID
int Get_if_Index (const string &ifname) {
    NetworkInterface i_face(ifname);
    return i_face.id();
}

// Send ARP Reply
void Send_ARP_Reply(const string &src_ip, const HWAddress<6>& src_mac, 
                    const string &dst_ip, const HWAddress<6>& dst_mac, string const &out_if) {    
                        ARP arp;
                        EthernetII packet = arp.make_arp_reply(dst_ip, src_ip, dst_mac, src_mac);
                        PacketSender sender;
                        sender.send(packet, out_if);
                    }


// Packet handle
void Packet_Handle (PDU &pdu, const string &in_if) {
    try {
        cout << "=== Checking in Packet_Handle function Start===" << endl;

        const ARP& arp = pdu.rfind_pdu<ARP>();
        if (arp.opcode() != ARP::REQUEST) return;
        cout << "=== Checking in Packet_Handle function found ARP Request " << endl;

        string target_ip = arp.target_ip_addr().to_string();
        string source_ip = arp.sender_ip_addr().to_string();
        cout << "=== Checking in Packet_Handle function found IP nguon: " << source_ip << "_ IP dich: " << target_ip<< endl;
        bool is_local = false;
        string out_if;
        HWAddress<6> proxy_mac;
        string my_ip;
        NetworkInterface in_interface(in_if);
        my_ip = in_interface.ipv4_address().to_string();
        if ( my_ip == source_ip) {
            cout << "IGNORE mine packet" << endl;
            return ;
        }

        for (int i = 0; i < vlan_ips.size(); i++) {
            if (target_ip == vlan_ips.at(i)) continue;
            if (source_ip.compare(0, 9, vlan_ips.at(i), 0, 9) == 0) {
                cout << "=== Checking in Packet_Handle function found same range with " << vlan_ips.at(i) << endl;                
                out_if = interfaces.at(i);
                NetworkInterface out_interface(out_if);
                proxy_mac = out_interface.hw_address();
                is_local = true;
                break;
            }
        }

        if (!is_local) return;

        // Send ARP Reply
        // cout << "[PROXY] " << source_ip << " asking for " << target_ip
        //           << " → reply with " << proxy_mac << " via " << out_if << endl;
        cout << "ARP Proxy Reply" << "in " << out_if << "IP Source: " << target_ip << " - IP Des: " << source_ip 
                << " MAC Source: " << proxy_mac << " - MAC Des: " << arp.sender_hw_addr().to_string() << endl;
        
        Send_ARP_Reply (target_ip, proxy_mac, source_ip, arp.sender_hw_addr(), out_if);
    } catch (...) {};
}

// Sniffer thread
void sniff_interface(const std::string& ifname) {
    try {
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("arp");

        Sniffer sniffer(ifname, config);

        while (running) {
            PDU *pdu = sniffer.next_packet();
            if (pdu) {
                // Truyền PDU& → dùng const_cast
                Packet_Handle(const_cast<PDU&>(*pdu), ifname);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] Sniffer on " << ifname << ": " << e.what() << std::endl;
    }
}

int main() {
    signal(SIGINT, signal_handler);

        // Lấy MAC của các interface
    for (const auto& iface : interfaces) {
        try {
            auto mac = NetworkInterface(iface).hw_address();
            ip_to_mac[vlan_ips[&iface - &interfaces[0]]] = mac;
            std::cout << iface << " MAC: " << mac << std::endl;
        } catch (...) {}
    }

    // vector <thread> threads ;
    // for (auto iface : interfaces) {
    //     thread t(sniff_interface, iface);
    //     threads.push_back(std::move(t));
    // }

    // std::cout << "ARP Proxy running... Press Ctrl+C to stop.\n";
    // for (auto& t : threads) t.join();   
    sniff_interface("eth0.20"); 
    return 0;
}