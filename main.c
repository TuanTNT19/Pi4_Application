#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char ssid[32];
    char signal[16];
    char protocol[16];
} Network;

int Scan_wifi (Network *networks, int max_networks){
    FILE *fp = popen("iw dev wlan0 scan", "r");
    if (!fp) {
        printf(">>> ERROR: Cannot run iw scan\n");
        return 0;
    }

    char line[256];
    int count = 0;
    Network current ={0};

    while (fgets(line, sizeof(line), fp) && count < max_networks)
    {
        line[strcspn(line, "\n")] = 0;

        if (strstr(line, "BSS")) {
            if (strlen(current.ssid) && strlen(current.signal)) {
                networks[count++] = current;
                memset(&current, 0, sizeof(current));
            }
        }
        else if (strstr(line, "SSID:")) {
            sscanf(line, " SSID: %31[^\n]", current.ssid);
        } else if (strstr(line, "signal:")) {
            sscanf(line, " signal: %15[^\n]", current.signal);
        } else if (strstr(line, "802.11")) {
            if (strstr(line, "ax")) strcpy(current.protocol, "802.11ax (Wi-Fi 6)");
            else if (strstr(line, "ac")) strcpy(current.protocol, "802.11ac (Wi-Fi 5)");
            else if (strstr(line, "n")) strcpy(current.protocol, "802.11n (Wi-Fi 4)");
            else strcpy(current.protocol, "Unknown");
        }
    }

    pclose(fp);
    return count;
}

int main() {
    Network networks[10]; // Giới hạn 10 mạng
    while (1) {
        int count = Scan_wifi(networks, 10);
        printf("\nWi-Fi Networks Scanned: %d\n", count);
        printf("----------------------------------------\n");
        printf("%-20s %-15s %s\n", "SSID", "Signal (dBm)", "Protocol");
        printf("----------------------------------------\n");
        for (int i = 0; i < count; i++) {
            printf("%-20s %-15s %s\n", networks[i].ssid, networks[i].signal, networks[i].protocol);
        }
        sleep(10); // Cập nhật mỗi 10 giây
    }
    return 0;
}