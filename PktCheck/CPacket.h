#pragma once


#include <pcap.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// CMake�� vcpkg �������� ��ũ ó���ϹǷ� pragma comment ����
// �ʿ�� CMakeLists.txt�� ���� �߰�:
// find_package(PkgConfig REQUIRED)
// pkg_check_modules(PCAP REQUIRED libpcap)
// target_link_libraries(your_target ${PCAP_LIBRARIES})

// �̴��� �������� ����
#define ETHERTYPE_PUP       0x0200      /* PUP protocol */
#define ETHERTYPE_IP        0x0800      /* IP protocol */
#define ETHERTYPE_ARP       0x0806      /* Address resolution protocol */
#define ETHERTYPE_TRAIL     0x1000      /* Trailer packet */
#define ETHERTYPE_NTRAILER  16

#define ETHERMTU            1500
#define ETHERMIN            (60-14)

// �������� Ÿ�� ���� (ǥ�� ������ ����)
#define _PACKET_TYPE_DEFAULT_   0x0
#define _PACKET_TYPE_ICMP       0x1     // ��Ÿ ����: PAKCET -> PACKET
#define _PACKET_TYPE_IGMP       0x2
#define _PACKET_TYPE_IP         0x4
#define _PACKET_TYPE_TCP        0x6
#define _PACKET_TYPE_UDP        0x11
#define _PACKET_TYPE_IPV6       0x29

// 1����Ʈ ���ķ� ����ü ��ŷ
#pragma pack(push, 1)

// �̴��� ��� ����ü
struct ether_header
{
    uint8_t  ether_dhost[6];    // ������ MAC �ּ�
    uint8_t  ether_shost[6];    // ����� MAC �ּ�
    uint16_t ether_type;        // �̴��� Ÿ��
};

// IP ��� ����ü (Windows ����Ʈ ������ �°� ��Ʈ�ʵ� ���� ����)
struct ip_header
{
#if defined(__LITTLE_ENDIAN__) || defined(_WIN32)
    uint8_t  ip_header_len : 4;   // ��� ����
    uint8_t  ip_version : 4;      // IP ����
#else
    uint8_t  ip_version : 4;      // IP ����
    uint8_t  ip_header_len : 4;   // ��� ����
#endif
    uint8_t  ip_tos;            // ���� Ÿ��
    uint16_t ip_total_length;   // ��ü ����
    uint16_t ip_id;             // �ĺ���
#if defined(__LITTLE_ENDIAN__) || defined(_WIN32)
    uint8_t  ip_frag_offset : 5;  // ����ȭ ������
    uint8_t  ip_more_fragment : 1;// �� ���� ����ȭ
    uint8_t  ip_dont_fragment : 1;// ����ȭ ����
    uint8_t  ip_reserved_zero : 1;// ���� ��Ʈ
#else
    uint8_t  ip_reserved_zero : 1;// ���� ��Ʈ
    uint8_t  ip_dont_fragment : 1;// ����ȭ ����
    uint8_t  ip_more_fragment : 1;// �� ���� ����ȭ
    uint8_t  ip_frag_offset : 5;  // ����ȭ ������
#endif
    uint8_t  ip_frag_offset1;   // ����ȭ ������ ���� ����Ʈ
    uint8_t  ip_ttl;            // ���� �ð�
    uint8_t  ip_protocol;       // ��������
    uint16_t ip_checksum;       // üũ��
    struct in_addr ip_srcaddr;  // ����� IP
    struct in_addr ip_destaddr; // ������ IP
};

// TCP ��� ����ü (Windows ����Ʈ ������ �°� ��Ʈ�ʵ� ���� ����)
struct tcp_header
{
    uint16_t source_port;       // ����� ��Ʈ
    uint16_t dest_port;         // ������ ��Ʈ
    uint32_t sequence;          // ������ ��ȣ (DWORD -> uint32_t)
    uint32_t acknowledge;       // Ȯ�� ��ȣ (DWORD -> uint32_t)
#if defined(__LITTLE_ENDIAN__) || defined(_WIN32)
    uint8_t  ns : 1;              // NS �÷���
    uint8_t  reserved_part1 : 3;  // ���� ����
    uint8_t  data_offset : 4;     // ������ ������
    uint8_t  fin : 1;             // FIN �÷���
    uint8_t  syn : 1;             // SYN �÷���
    uint8_t  rst : 1;             // RST �÷���
    uint8_t  psh : 1;             // PSH �÷���
    uint8_t  ack : 1;             // ACK �÷���
    uint8_t  urg : 1;             // URG �÷���
    uint8_t  ecn : 1;             // ECN �÷���
    uint8_t  cwr : 1;             // CWR �÷���
#else
    uint8_t  data_offset : 4;     // ������ ������
    uint8_t  reserved_part1 : 3;  // ���� ����
    uint8_t  ns : 1;              // NS �÷���
    uint8_t  cwr : 1;             // CWR �÷���
    uint8_t  ecn : 1;             // ECN �÷���
    uint8_t  urg : 1;             // URG �÷���
    uint8_t  ack : 1;             // ACK �÷���
    uint8_t  psh : 1;             // PSH �÷���
    uint8_t  rst : 1;             // RST �÷���
    uint8_t  syn : 1;             // SYN �÷���
    uint8_t  fin : 1;             // FIN �÷���
#endif
    uint16_t window;            // ������ ũ��
    uint16_t checksum;          // üũ��
    uint16_t urgent_pointer;    // ��� ������
};

// UDP ��� ����ü
struct udp_header
{
    uint16_t sport;             // ����� ��Ʈ
    uint16_t dport;             // ������ ��Ʈ
    uint16_t len;               // ����
    uint16_t crc;               // üũ��
};

// ��Ŷ ���� ����ü
struct _PACKET_INFO
{
    char szSrcIP[16];           // ����� IP ���ڿ� (1<<4 = 16)
    uint16_t nSrcPort;          // ����� ��Ʈ (u_short -> uint16_t)
    char szDstIP[16];           // ������ IP ���ڿ�
    uint16_t nDstPort;          // ������ ��Ʈ
    uint32_t nPacketLength;     // ��Ŷ ���� (DWORD -> uint32_t)
    uint8_t bytProtocolType;    // �������� Ÿ�� (u_char -> uint8_t)
};

#pragma pack(pop)  // ����ü ��ŷ ����

// ��Ŷ ĸó Ŭ����
class C_PACKET
{
protected:
    bool bCaptureStart{ false };    // ĸó ���� �÷���

    pcap_t* fp{ nullptr };          // pcap �ڵ�
    pcap_if_t* alldevs{ nullptr };  // ��Ʈ��ũ ����̽� ����Ʈ

public:
    C_PACKET() = default;
    virtual ~C_PACKET() = default;

    long Init();        // �ʱ�ȭ
    long Create();      // ����
    long Calculate();   // ���/ó��

    bool check_start_game(const u_char* pkt_data, const size_t pkt_len);
};
