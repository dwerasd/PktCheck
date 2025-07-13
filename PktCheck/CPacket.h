#pragma once


#include <pcap.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// CMake나 vcpkg 설정에서 링크 처리하므로 pragma comment 제거
// 필요시 CMakeLists.txt에 다음 추가:
// find_package(PkgConfig REQUIRED)
// pkg_check_modules(PCAP REQUIRED libpcap)
// target_link_libraries(your_target ${PCAP_LIBRARIES})

// 이더넷 프로토콜 정의
#define ETHERTYPE_PUP       0x0200      /* PUP protocol */
#define ETHERTYPE_IP        0x0800      /* IP protocol */
#define ETHERTYPE_ARP       0x0806      /* Address resolution protocol */
#define ETHERTYPE_TRAIL     0x1000      /* Trailer packet */
#define ETHERTYPE_NTRAILER  16

#define ETHERMTU            1500
#define ETHERMIN            (60-14)

// 프로토콜 타입 정의 (표준 값으로 수정)
#define _PACKET_TYPE_DEFAULT_   0x0
#define _PACKET_TYPE_ICMP       0x1     // 오타 수정: PAKCET -> PACKET
#define _PACKET_TYPE_IGMP       0x2
#define _PACKET_TYPE_IP         0x4
#define _PACKET_TYPE_TCP        0x6
#define _PACKET_TYPE_UDP        0x11
#define _PACKET_TYPE_IPV6       0x29

// 1바이트 정렬로 구조체 패킹
#pragma pack(push, 1)

// 이더넷 헤더 구조체
struct ether_header
{
    uint8_t  ether_dhost[6];    // 목적지 MAC 주소
    uint8_t  ether_shost[6];    // 출발지 MAC 주소
    uint16_t ether_type;        // 이더넷 타입
};

// IP 헤더 구조체 (Windows 바이트 순서에 맞게 비트필드 순서 조정)
struct ip_header
{
#if defined(__LITTLE_ENDIAN__) || defined(_WIN32)
    uint8_t  ip_header_len : 4;   // 헤더 길이
    uint8_t  ip_version : 4;      // IP 버전
#else
    uint8_t  ip_version : 4;      // IP 버전
    uint8_t  ip_header_len : 4;   // 헤더 길이
#endif
    uint8_t  ip_tos;            // 서비스 타입
    uint16_t ip_total_length;   // 전체 길이
    uint16_t ip_id;             // 식별자
#if defined(__LITTLE_ENDIAN__) || defined(_WIN32)
    uint8_t  ip_frag_offset : 5;  // 단편화 오프셋
    uint8_t  ip_more_fragment : 1;// 더 많은 단편화
    uint8_t  ip_dont_fragment : 1;// 단편화 금지
    uint8_t  ip_reserved_zero : 1;// 예약 비트
#else
    uint8_t  ip_reserved_zero : 1;// 예약 비트
    uint8_t  ip_dont_fragment : 1;// 단편화 금지
    uint8_t  ip_more_fragment : 1;// 더 많은 단편화
    uint8_t  ip_frag_offset : 5;  // 단편화 오프셋
#endif
    uint8_t  ip_frag_offset1;   // 단편화 오프셋 하위 바이트
    uint8_t  ip_ttl;            // 생존 시간
    uint8_t  ip_protocol;       // 프로토콜
    uint16_t ip_checksum;       // 체크섬
    struct in_addr ip_srcaddr;  // 출발지 IP
    struct in_addr ip_destaddr; // 목적지 IP
};

// TCP 헤더 구조체 (Windows 바이트 순서에 맞게 비트필드 순서 조정)
struct tcp_header
{
    uint16_t source_port;       // 출발지 포트
    uint16_t dest_port;         // 목적지 포트
    uint32_t sequence;          // 시퀀스 번호 (DWORD -> uint32_t)
    uint32_t acknowledge;       // 확인 번호 (DWORD -> uint32_t)
#if defined(__LITTLE_ENDIAN__) || defined(_WIN32)
    uint8_t  ns : 1;              // NS 플래그
    uint8_t  reserved_part1 : 3;  // 예약 영역
    uint8_t  data_offset : 4;     // 데이터 오프셋
    uint8_t  fin : 1;             // FIN 플래그
    uint8_t  syn : 1;             // SYN 플래그
    uint8_t  rst : 1;             // RST 플래그
    uint8_t  psh : 1;             // PSH 플래그
    uint8_t  ack : 1;             // ACK 플래그
    uint8_t  urg : 1;             // URG 플래그
    uint8_t  ecn : 1;             // ECN 플래그
    uint8_t  cwr : 1;             // CWR 플래그
#else
    uint8_t  data_offset : 4;     // 데이터 오프셋
    uint8_t  reserved_part1 : 3;  // 예약 영역
    uint8_t  ns : 1;              // NS 플래그
    uint8_t  cwr : 1;             // CWR 플래그
    uint8_t  ecn : 1;             // ECN 플래그
    uint8_t  urg : 1;             // URG 플래그
    uint8_t  ack : 1;             // ACK 플래그
    uint8_t  psh : 1;             // PSH 플래그
    uint8_t  rst : 1;             // RST 플래그
    uint8_t  syn : 1;             // SYN 플래그
    uint8_t  fin : 1;             // FIN 플래그
#endif
    uint16_t window;            // 윈도우 크기
    uint16_t checksum;          // 체크섬
    uint16_t urgent_pointer;    // 긴급 포인터
};

// UDP 헤더 구조체
struct udp_header
{
    uint16_t sport;             // 출발지 포트
    uint16_t dport;             // 목적지 포트
    uint16_t len;               // 길이
    uint16_t crc;               // 체크섬
};

// 패킷 정보 구조체
struct _PACKET_INFO
{
    char szSrcIP[16];           // 출발지 IP 문자열 (1<<4 = 16)
    uint16_t nSrcPort;          // 출발지 포트 (u_short -> uint16_t)
    char szDstIP[16];           // 목적지 IP 문자열
    uint16_t nDstPort;          // 목적지 포트
    uint32_t nPacketLength;     // 패킷 길이 (DWORD -> uint32_t)
    uint8_t bytProtocolType;    // 프로토콜 타입 (u_char -> uint8_t)
};

#pragma pack(pop)  // 구조체 패킹 해제

// 패킷 캡처 클래스
class C_PACKET
{
protected:
    bool bCaptureStart{ false };    // 캡처 시작 플래그

    pcap_t* fp{ nullptr };          // pcap 핸들
    pcap_if_t* alldevs{ nullptr };  // 네트워크 디바이스 리스트

public:
    C_PACKET() = default;
    virtual ~C_PACKET() = default;

    long Init();        // 초기화
    long Create();      // 생성
    long Calculate();   // 계산/처리

    bool check_start_game(const u_char* pkt_data, const size_t pkt_len);
};
