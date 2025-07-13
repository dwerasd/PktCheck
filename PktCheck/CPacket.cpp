#include "stdafx.h"
#include "CPacket.h"
#include "CMain.h"


#define _VIEW_PACKET_DETAIL_

// 문자열 검색 함수 (안전성 개선)
char* FindStr(char* pszSrc, const char* pszDst, size_t nSize)
{
    if (!pszSrc || !pszDst || nSize == 0) return nullptr;

    size_t nDstLen = strlen(pszDst);
    if (nDstLen == 0 || nDstLen > nSize) return nullptr;

    for (size_t i = 0; i <= nSize - nDstLen; ++i)
    {
        bool bMatch = true;
        for (size_t j = 0; j < nDstLen; ++j)
        {
            if (pszSrc[i + j] != pszDst[j])
            {
                bMatch = false;
                break;
            }
        }
        if (bMatch)
        {
            return pszSrc + i;
        }
    }
    return nullptr;
}

long C_PACKET::Init()
{
    // 네트워크 어댑터 정보 얻기
    alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap_findalldevs 사용법은 동일
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        WRITELOG("네트워크 어댑터를 찾을 수 없음: %s", errbuf);
        return -1;
    }

    if (alldevs == nullptr)
    {
        WRITELOG("네트워크 어댑터가 없음");
        return -1;
    }

    // 첫 번째 네트워크 어댑터 선택
    pcap_if_t* d = alldevs;

    // pcap_open_live 사용법 변경: PCAP_OPENFLAG_PROMISCUOUS -> 1 (프로미스큐어스 모드)
    fp = pcap_open_live(d->name, 65536, 1, 20, errbuf);
    if (fp == nullptr)
    {
        WRITELOG("pcap open failed: %s", errbuf);
        pcap_freealldevs(alldevs);
        return -1;
    }

    // 디바이스 리스트 해제
    pcap_freealldevs(alldevs);
    alldevs = nullptr;

    WRITELOG("--- Start PCap (libpcap) ---");
    return 0;
}

long C_PACKET::Create()
{
    struct bpf_program fcode;

    // 필터 컴파일: port 81 패킷만 캡처
    if (pcap_compile(fp, &fcode, "port 81", 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        WRITELOG("pcap compile failed: %s", pcap_geterr(fp));
        return -1;
    }

    // 필터 설정
    if (pcap_setfilter(fp, &fcode) < 0)
    {
        WRITELOG("pcap setfilter failed: %s", pcap_geterr(fp));
        pcap_freecode(&fcode);
        return -1;
    }

    // 필터 코드 해제
    pcap_freecode(&fcode);

    return 0;
}

bool C_PACKET::check_start_game(const u_char* pkt_data, const size_t pkt_len)
{
	bool bResult = false;
    LPSTR pszStart = FindStr((char*)pkt_data, "StartGame", pkt_len);
    if (!pszStart) { return(bResult); }
    WRITELOG("Found StartGame: %u", pkt_len);
    // 패킷 데이터 출력
#if defined(_VIEW_PACKET_DETAIL_)
    {
        char szBuffer[MAX_LOG_BUFFER] = { "StartGame: " };
        for (uint16_t i = 0; i < pkt_len; ++i)
        {
            char szBuf[8] = { 0 };
            sprintf_s(szBuf, "%c", pkt_data[i]);
            strcat_s(szBuffer, szBuf);
        }
        WRITELOG("%s", szBuffer);
    }
#endif
    // 패킷 내용에서 게임서버 IP/포트 추출
	LPSTR pszConnectIPEnd = strchr(pszStart, ':');  // ":" 다음 위치 찾기
    if (pszConnectIPEnd)
    {
		LPCSTR pszConnectIP = strchr(pszConnectIPEnd - 16, ',');    // "," 이전에 있는 IP 주소 찾기
        if (pszConnectIP)
        {
            pszConnectIP += 2;  // ", 다음 시작
            LPCSTR pszPort = pszConnectIPEnd + 1;
            LPCSTR pszPortEnd = strchr(pszPort, '\"');

            if (pszPortEnd != nullptr)
            {
				// IP 문자열 추출
                char szConnectIP[16] = { 0 };
                strncpy_s(szConnectIP, pszConnectIP, pszConnectIPEnd - pszConnectIP);
				// 포트 문자열 추출
                char szConnectPort[8] = { 0 };
                strncpy_s(szConnectPort, pszPort, pszPortEnd - pszPort);

                WRITELOG("GameServer: %s:%s", szConnectIP, szConnectPort);

                // 새로운 필터 설정
                char szParam[256];
				sprintf_s(szParam, "host %s or port 81", szConnectIP);  // IP 주소와 포트 81을 포함하는 필터
                bpf_program fcode;
				if (pcap_compile(fp, &fcode, szParam, 1, PCAP_NETMASK_UNKNOWN) >= 0)    // 필터 컴파일
                {
					if (pcap_setfilter(fp, &fcode) >= 0)    // 필터 설정
                    {
                        bResult = true;                     // 게임이 시작되었고 필터 시작함.
                    }
					pcap_freecode(&fcode);                  // 필터 코드 해제
                }
            }
        }
    }
    return(bResult);
}

long C_PACKET::Calculate()
{
    const uint8_t* pkt_data;
    struct pcap_pkthdr* header;

    // 패킷 캡처 (사용법 동일)
    int res = pcap_next_ex(fp, &header, &pkt_data);
    if (res > 0)
    {
        const size_t offset = sizeof(ether_header);  // 이더넷 헤더 크기 (14바이트)

        // 이더넷 헤더 분석
        const ether_header* pEtherHeader = (const ether_header*)pkt_data;
        const uint16_t nEtherType = ntohs(pEtherHeader->ether_type);

        // IP 패킷인지 확인
        if (ETHERTYPE_IP == nEtherType) { pkt_data += offset; }
        else { return 0; }   // IP 패킷이 아니면 무시

        // IP 헤더 분석
        const ip_header* pIpHeader = (const ip_header*)pkt_data;

        // 패킷 크기 검증
        uint32_t nPacketSize = ntohs(pIpHeader->ip_total_length) + offset;
        if (nPacketSize > header->caplen)
        {
            WRITELOG("nPacketSize(%u) > header->caplen(%u)", nPacketSize, header->caplen);
            return 1;
        }

        // 패킷 정보 구조체 초기화
        _PACKET_INFO packet_info{};
        // IP 주소 변환 (inet_ntoa 사용법 동일)
        strcpy_s(packet_info.szSrcIP, sizeof(packet_info.szSrcIP), inet_ntoa(pIpHeader->ip_srcaddr));
        strcpy_s(packet_info.szDstIP, sizeof(packet_info.szDstIP), inet_ntoa(pIpHeader->ip_destaddr));
        packet_info.nPacketLength = nPacketSize;
        packet_info.bytProtocolType = pIpHeader->ip_protocol;

        // IP 헤더 길이만큼 이동
        pkt_data += ((pIpHeader->ip_header_len & 0x0f) * 4);

        // TCP/UDP 헤더 분석
        const tcp_header* pTcpHeader = (const tcp_header*)pkt_data;
        const udp_header* pUdpHeader = (const udp_header*)pkt_data;

        // 프로토콜별 처리
        switch (packet_info.bytProtocolType)
        {
        case _PACKET_TYPE_TCP:
            {
                packet_info.nSrcPort = ntohs(pTcpHeader->source_port);
                packet_info.nDstPort = ntohs(pTcpHeader->dest_port);

                // TCP 헤더 크기만큼 이동
                pkt_data += (pTcpHeader->data_offset * 4);

                // 실제 데이터 길이 계산
                packet_info.nPacketLength = ntohs(pIpHeader->ip_total_length) + 14 -
                    (offset + ((pIpHeader->ip_header_len & 0x0f) * 4) + (pTcpHeader->data_offset * 4));
            }
            break;
        case _PACKET_TYPE_UDP:
            {
                packet_info.nSrcPort = ntohs(pUdpHeader->sport);
                packet_info.nDstPort = ntohs(pUdpHeader->dport);

                const size_t nUdpHeaderSize = sizeof(udp_header);
                pkt_data += nUdpHeaderSize;

                // UDP 데이터 길이 계산
                packet_info.nPacketLength = header->caplen -
                    (offset + ((pIpHeader->ip_header_len & 0x0f) * 4) + nUdpHeaderSize);
            }
            break;
        default:
			return 0;  // 체크할 프로토콜이 아니면 무시
        }
        if (!bCaptureStart)
        {   // 포트 81 패킷 처리
            if (packet_info.nSrcPort == 81 || packet_info.nDstPort == 81)
            {
                // pkt_data 는 이제 패킷 데이터 부분을 가리킨다.
                bCaptureStart = check_start_game(pkt_data, packet_info.nPacketLength);
            }
		}
        else
        {   // 게임 시작 후 패킷 처리
            // 기타 패킷 처리
            bool bRecv = (strcmp(packet_info.szDstIP, "192.168.0.4") == 0);
            if (bRecv)
            {
                // TCP 플래그 분석
                if (packet_info.bytProtocolType == _PACKET_TYPE_TCP)
                {
#if defined(_VIEW_PACKET_DETAIL_)
                    char szBuffer[MAX_LOG_BUFFER] = { "TCP Flags:" };

                    if (pTcpHeader->fin) strcat_s(szBuffer, " FIN");
                    if (pTcpHeader->syn) strcat_s(szBuffer, " SYN");
                    if (pTcpHeader->rst) strcat_s(szBuffer, " RST");
                    if (pTcpHeader->psh) strcat_s(szBuffer, " PSH");
                    if (pTcpHeader->ack) strcat_s(szBuffer, " ACK");
                    if (pTcpHeader->urg) strcat_s(szBuffer, " URG");
                    if (pTcpHeader->ecn) strcat_s(szBuffer, " ECN");
                    if (pTcpHeader->cwr) strcat_s(szBuffer, " CWR");

                    WRITELOG("[R] Size: %u / %s", packet_info.nPacketLength, szBuffer);

                    // 패킷 데이터 출력 (제한적으로)
                    if (packet_info.nPacketLength > 0 && packet_info.nPacketLength < 1000)
                    {
                        memset(szBuffer, 0, sizeof(szBuffer));
                        strcpy_s(szBuffer, "TCP Data: ");

                        for (uint16_t i = 0; i < packet_info.nPacketLength; ++i)
                        {
                            char szBuf[8] = { 0 };
                            sprintf_s(szBuf, "%c", pkt_data[i]);
                            strcat_s(szBuffer, szBuf);
                        }
                        WRITELOG("%s", szBuffer);
                    }
#endif
                }
            }
            else if (packet_info.nPacketLength == 44)  // 위치 정보 패킷
            {
#if defined(_VIEW_PACKET_DETAIL_)
                char szBuffer[MAX_LOG_BUFFER] = { "MyXYZ: " };
                for (uint16_t i = 0; i < 44; ++i)
                {
                    char szBuf[8] = { 0 };
                    sprintf_s(szBuf, "%c", pkt_data[i]);
                    strcat_s(szBuffer, szBuf);
                }
                WRITELOG("%s", szBuffer);
#endif
            }
        }
    }
    else if (res < 0)
    {
        WRITELOG("pcap_next_ex 에러: %d - %s", res, pcap_geterr(fp));
        return 1;
    }
    // res == 0은 타임아웃으로 정상
    return 0;
}
