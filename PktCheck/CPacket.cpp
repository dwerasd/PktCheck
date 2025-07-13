#include "stdafx.h"
#include "CPacket.h"
#include "CMain.h"


#define _VIEW_PACKET_DETAIL_

// ���ڿ� �˻� �Լ� (������ ����)
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
    // ��Ʈ��ũ ����� ���� ���
    alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap_findalldevs ������ ����
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        WRITELOG("��Ʈ��ũ ����͸� ã�� �� ����: %s", errbuf);
        return -1;
    }

    if (alldevs == nullptr)
    {
        WRITELOG("��Ʈ��ũ ����Ͱ� ����");
        return -1;
    }

    // ù ��° ��Ʈ��ũ ����� ����
    pcap_if_t* d = alldevs;

    // pcap_open_live ���� ����: PCAP_OPENFLAG_PROMISCUOUS -> 1 (���ι̽�ť� ���)
    fp = pcap_open_live(d->name, 65536, 1, 20, errbuf);
    if (fp == nullptr)
    {
        WRITELOG("pcap open failed: %s", errbuf);
        pcap_freealldevs(alldevs);
        return -1;
    }

    // ����̽� ����Ʈ ����
    pcap_freealldevs(alldevs);
    alldevs = nullptr;

    WRITELOG("--- Start PCap (libpcap) ---");
    return 0;
}

long C_PACKET::Create()
{
    struct bpf_program fcode;

    // ���� ������: port 81 ��Ŷ�� ĸó
    if (pcap_compile(fp, &fcode, "port 81", 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        WRITELOG("pcap compile failed: %s", pcap_geterr(fp));
        return -1;
    }

    // ���� ����
    if (pcap_setfilter(fp, &fcode) < 0)
    {
        WRITELOG("pcap setfilter failed: %s", pcap_geterr(fp));
        pcap_freecode(&fcode);
        return -1;
    }

    // ���� �ڵ� ����
    pcap_freecode(&fcode);

    return 0;
}

bool C_PACKET::check_start_game(const u_char* pkt_data, const size_t pkt_len)
{
	bool bResult = false;
    LPSTR pszStart = FindStr((char*)pkt_data, "StartGame", pkt_len);
    if (!pszStart) { return(bResult); }
    WRITELOG("Found StartGame: %u", pkt_len);
    // ��Ŷ ������ ���
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
    // ��Ŷ ���뿡�� ���Ӽ��� IP/��Ʈ ����
	LPSTR pszConnectIPEnd = strchr(pszStart, ':');  // ":" ���� ��ġ ã��
    if (pszConnectIPEnd)
    {
		LPCSTR pszConnectIP = strchr(pszConnectIPEnd - 16, ',');    // "," ������ �ִ� IP �ּ� ã��
        if (pszConnectIP)
        {
            pszConnectIP += 2;  // ", ���� ����
            LPCSTR pszPort = pszConnectIPEnd + 1;
            LPCSTR pszPortEnd = strchr(pszPort, '\"');

            if (pszPortEnd != nullptr)
            {
				// IP ���ڿ� ����
                char szConnectIP[16] = { 0 };
                strncpy_s(szConnectIP, pszConnectIP, pszConnectIPEnd - pszConnectIP);
				// ��Ʈ ���ڿ� ����
                char szConnectPort[8] = { 0 };
                strncpy_s(szConnectPort, pszPort, pszPortEnd - pszPort);

                WRITELOG("GameServer: %s:%s", szConnectIP, szConnectPort);

                // ���ο� ���� ����
                char szParam[256];
				sprintf_s(szParam, "host %s or port 81", szConnectIP);  // IP �ּҿ� ��Ʈ 81�� �����ϴ� ����
                bpf_program fcode;
				if (pcap_compile(fp, &fcode, szParam, 1, PCAP_NETMASK_UNKNOWN) >= 0)    // ���� ������
                {
					if (pcap_setfilter(fp, &fcode) >= 0)    // ���� ����
                    {
                        bResult = true;                     // ������ ���۵Ǿ��� ���� ������.
                    }
					pcap_freecode(&fcode);                  // ���� �ڵ� ����
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

    // ��Ŷ ĸó (���� ����)
    int res = pcap_next_ex(fp, &header, &pkt_data);
    if (res > 0)
    {
        const size_t offset = sizeof(ether_header);  // �̴��� ��� ũ�� (14����Ʈ)

        // �̴��� ��� �м�
        const ether_header* pEtherHeader = (const ether_header*)pkt_data;
        const uint16_t nEtherType = ntohs(pEtherHeader->ether_type);

        // IP ��Ŷ���� Ȯ��
        if (ETHERTYPE_IP == nEtherType) { pkt_data += offset; }
        else { return 0; }   // IP ��Ŷ�� �ƴϸ� ����

        // IP ��� �м�
        const ip_header* pIpHeader = (const ip_header*)pkt_data;

        // ��Ŷ ũ�� ����
        uint32_t nPacketSize = ntohs(pIpHeader->ip_total_length) + offset;
        if (nPacketSize > header->caplen)
        {
            WRITELOG("nPacketSize(%u) > header->caplen(%u)", nPacketSize, header->caplen);
            return 1;
        }

        // ��Ŷ ���� ����ü �ʱ�ȭ
        _PACKET_INFO packet_info{};
        // IP �ּ� ��ȯ (inet_ntoa ���� ����)
        strcpy_s(packet_info.szSrcIP, sizeof(packet_info.szSrcIP), inet_ntoa(pIpHeader->ip_srcaddr));
        strcpy_s(packet_info.szDstIP, sizeof(packet_info.szDstIP), inet_ntoa(pIpHeader->ip_destaddr));
        packet_info.nPacketLength = nPacketSize;
        packet_info.bytProtocolType = pIpHeader->ip_protocol;

        // IP ��� ���̸�ŭ �̵�
        pkt_data += ((pIpHeader->ip_header_len & 0x0f) * 4);

        // TCP/UDP ��� �м�
        const tcp_header* pTcpHeader = (const tcp_header*)pkt_data;
        const udp_header* pUdpHeader = (const udp_header*)pkt_data;

        // �������ݺ� ó��
        switch (packet_info.bytProtocolType)
        {
        case _PACKET_TYPE_TCP:
            {
                packet_info.nSrcPort = ntohs(pTcpHeader->source_port);
                packet_info.nDstPort = ntohs(pTcpHeader->dest_port);

                // TCP ��� ũ�⸸ŭ �̵�
                pkt_data += (pTcpHeader->data_offset * 4);

                // ���� ������ ���� ���
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

                // UDP ������ ���� ���
                packet_info.nPacketLength = header->caplen -
                    (offset + ((pIpHeader->ip_header_len & 0x0f) * 4) + nUdpHeaderSize);
            }
            break;
        default:
			return 0;  // üũ�� ���������� �ƴϸ� ����
        }
        if (!bCaptureStart)
        {   // ��Ʈ 81 ��Ŷ ó��
            if (packet_info.nSrcPort == 81 || packet_info.nDstPort == 81)
            {
                // pkt_data �� ���� ��Ŷ ������ �κ��� ����Ų��.
                bCaptureStart = check_start_game(pkt_data, packet_info.nPacketLength);
            }
		}
        else
        {   // ���� ���� �� ��Ŷ ó��
            // ��Ÿ ��Ŷ ó��
            bool bRecv = (strcmp(packet_info.szDstIP, "192.168.0.4") == 0);
            if (bRecv)
            {
                // TCP �÷��� �м�
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

                    // ��Ŷ ������ ��� (����������)
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
            else if (packet_info.nPacketLength == 44)  // ��ġ ���� ��Ŷ
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
        WRITELOG("pcap_next_ex ����: %d - %s", res, pcap_geterr(fp));
        return 1;
    }
    // res == 0�� Ÿ�Ӿƿ����� ����
    return 0;
}
