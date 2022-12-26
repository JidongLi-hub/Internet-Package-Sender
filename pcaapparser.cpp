#include "pcapparser.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "mainwindow.h"

//unsigned char转QString
QString uncharToQstring(unsigned char * id,int len)
{
    QString temp,msg;
    int j = 0;

    while (j<len)
    {
        temp = QString("%1").arg((int)id[j], 2, 16, QLatin1Char('0'));
        msg.append(temp);
        j++;
    }
    return msg;
}
//unsigned char转QString的mac地址带-
QString UncharToQstring(unsigned char * id,int len)
{
    QString temp,msg;
    int j = 0;

    while (j<len)
    {
        temp = QString("%1").arg((int)id[j], 2, 16, QLatin1Char('0'));
        msg.append(temp);
        msg.append("-");
        j++;
    }
    msg.chop(1);
    return msg;
}

//实现windows下的字节地址转IP地址
PCSTR WSAAPI inet_ntop(INT Family,const VOID *pAddr,PSTR pStringBuf, size_t  StringBufSize)
{
    if(pStringBuf ==NULL || StringBufSize == 0)
    {
       WSASetLastError(ERROR_INVALID_PARAMETER);
       return NULL;
    }
    if(Family == AF_INET6)
    {
        int ret=0;
        ret=WSAAddressToStringA((PSOCKADDR)pAddr,sizeof(PSOCKADDR),NULL,pStringBuf,(LPDWORD)&StringBufSize);
        if(ret!=0)
        {
            return NULL;
        }
    }
    else if(Family == AF_INET)//
    {
        struct in_addr a;
        memcpy(&a,pAddr,sizeof(struct in_addr));
        strcpy(pStringBuf,inet_ntoa(a));
    }
    else
    {
        WSASetLastError(WSAEAFNOSUPPORT);
        return NULL;
    }
    return pStringBuf;
}

void PcapParser::tcpDecode(const char* buf, int len)
{
    packs->protocol = "TCP";
    int offset = 0;
    TCPHeader_t* tcpHeader = (TCPHeader_t*)(buf + offset);
    offset += sizeof(TCPHeader_t);

    //uint16_t srcPort = tcpHeader->srcPort;
    //uint16_t dstPort = tcpHeader->dstPort;
    uint16_t srcPort = ntohs(tcpHeader->srcPort);
    uint16_t dstPort = ntohs(tcpHeader->dstPort);
    uint16_t win = ntohs(tcpHeader->WinSize);
    uint32_t seq = ntohl(tcpHeader->SeqNo);
    uint32_t ack = ntohl(tcpHeader->AckNo);
    //这里要注意网络字节顺序与X86字节顺序要做转换

    unsigned int s = srcPort;
    unsigned int d = dstPort;
    unsigned int se = seq;
    unsigned int ac = ack;
    unsigned int window = win;

    packs->sport = QString::number(s);
    packs->dport = QString::number(d);
    packs->seq = QString::number(se);
    packs->ack = QString::number(ac);
    packs->window = QString::number(window);

    // 用户数据长度
    uint16_t dataLen = len - sizeof(TCPHeader_t);

    if (0 != tcpFilter(srcPort, dstPort, dataLen))
    {
        // tcp过滤
        return;
    }

    printf("[%d]->[%d] len:%d\n", srcPort, dstPort, dataLen);

    // 存到缓存,用来做粘包,半包处理
    memcpy(mTcpData + mTcpLen, buf + offset, dataLen);
    mTcpLen += dataLen;

    char Data[500];
    memcpy(Data,buf+offset,dataLen);
    packs->data = QString(Data);

    // 用户数据
    int usedLen = onTcpMsg(mTcpData, mTcpLen);
    if (usedLen > 0)
    {
        memcpy(mTcpData, mTcpData + usedLen, usedLen);
        mTcpLen -= usedLen;
    }
     printf("the data is %s\n",mTcpData);
}

// udp协议解析
void PcapParser::udpDecode(const char* buf, int len)
{
    packs->protocol = "UDP";
    int offset = 0;
    UDPHeader_t* udpHeader = (UDPHeader_t*)(buf + offset);
    offset += sizeof(UDPHeader_t);

    uint16_t srcPort = ntohs(udpHeader->SrcPort);
    uint16_t dstPort = ntohs(udpHeader->DstPort);
    uint16_t packLen = ntohs(udpHeader->Length);

    unsigned int s = srcPort;
    unsigned int d = dstPort;

    packs->sport = QString::number(s);
    packs->dport = QString::number(d);

    // 用户数据长度
    uint16_t dataLen = packLen - sizeof(UDPHeader_t);

    if (0 != udpFilter(srcPort, dstPort, dataLen))
    {
        // udp过滤
        return;
    }

    // 存到缓存,用来做粘包,半包处理
    memcpy(mUdpData + mUdpLen, buf + offset, dataLen);

    char Data[500];
    memcpy(Data,buf+offset,dataLen);
    packs->data = QString(Data);

    mUdpLen += dataLen;
    printf("the data is %s\n",mUdpData);
    // 用户数据
    int usedLen = onUdpMsg(mUdpData, mUdpLen);
    if (usedLen > 0)
    {
        memcpy(mUdpData, mUdpData + usedLen, usedLen);
        mUdpLen -= usedLen;
    }
    //printf("the data is %d\n",mUdpData[0]);

}

// IP 协议解析
void PcapParser::ipDecode(const char* buf)
{
    int offset = 0;
    IPHeader_t* ipHeader = (IPHeader_t*)(buf + offset);
    offset += sizeof(IPHeader_t);

    char srcIp[32] = { 0 };
    char dstIp[32] = { 0 };

    inet_ntop(AF_INET, &ipHeader->SrcIP, srcIp, sizeof(srcIp));
    inet_ntop(AF_INET, &ipHeader->DstIP, dstIp, sizeof(dstIp));

    uint16_t ipPackLen = ntohs(ipHeader->TotalLen);
    //printf("%x",ipHeader->SrcIP);

    printf("[%s]->[%s] proto:%#x ipPackLen=%d packIdx=%d\n", srcIp, dstIp, ipHeader->Protocol, ipPackLen, mPackIndex);
    packs->srcIP = QString(srcIp);
    packs->dstIP = QString(dstIp);

    if (0 != ipFilter(srcIp, dstIp))
    {
        return;
    }

    switch (ipHeader->Protocol)
    {
        case 17:// UDP协议
            udpDecode(buf + offset, ipPackLen - sizeof(IPHeader_t));
            break;
        case 6: // TCP协议
            tcpDecode(buf + offset, ipPackLen - sizeof(IPHeader_t));
            break;
        case 1: //ICMP协议
            icmpDecode(buf + offset,ipPackLen - sizeof(IPHeader_t) );
        default:
            printf("[%s:%d]unsupported protocol %#x\n", __FILE__, __LINE__,
                   ipHeader->Protocol);
            break;
    }
}

void PcapParser::icmpDecode(const char* buf,int len)
{
    packs->protocol = "ICMP";
    int offset = 0;
    ICMPHeader_t* icmpHeader = (ICMPHeader_t*)(buf + offset);
    offset += sizeof(ICMPHeader_t);

    uint8_t type = icmpHeader->type;
    uint16_t code = ntohs(icmpHeader->code);
    uint16_t identifier = ntohs(icmpHeader->icmp_id);
    uint16_t seq = ntohs(icmpHeader->icmp_seq);

    // 用户数据长度
    uint16_t dataLen = 32;
    memcpy(mIcmpData + mIcmpLen, buf + offset, dataLen);
    mIcmpLen += dataLen;
    printf("the data is %s\n",mIcmpData);
    // 用户数据
    int usedLen = onUdpMsg(mIcmpData, mIcmpLen);
    if (usedLen > 0)
    {
        memcpy(mUdpData, mUdpData + usedLen, usedLen);
        mIcmpLen -= usedLen;
    }
}

void PcapParser::parse(const char* filename)
{
    struct stat st;
    if (stat(filename, &st))
    {
        printf("stat file %s failed, errno=%d errmsg=%s\n", filename, errno, strerror(errno));
        return;
    }

    size_t fileSize = st.st_size;

    if (!fileSize)
    {
        printf("file is empty!\n");
        return;
    }

    char *buf = (char*)malloc(fileSize + 1);

    FILE* fp = fopen(filename, "r");
    if (!fp)
    {
        printf("open file %s failed, errno=%d errmsg=%s\n", filename, errno, strerror(errno));
        return;
    }
    fread(buf, sizeof(char), fileSize, fp);
    fclose(fp);


    size_t offset = 0;
    // pcap 文件头
    Pcap_File_Header* fileHeader = (Pcap_File_Header*)(buf + offset);
    offset += sizeof(Pcap_File_Header);
    printf("pcap file - magic:%#x version:%d.%d\n", fileHeader->magic, fileHeader->version_major, fileHeader->version_minor);

    size_t proto_offset = 0;
    mPackIndex = 0;

    packs = new Pack_Node ;
    root = packs;
    packs->id = 0;
    while (offset < fileSize)
    {
        // pcap 包头
        Pcap_pkthdr* pcapHeader = (Pcap_pkthdr*)(buf + offset);
        proto_offset = offset + sizeof(Pcap_pkthdr);

        // 以太网协议头
        EthnetHeader_t* ethHeader = (EthnetHeader_t*)(buf + proto_offset);
        proto_offset += sizeof(EthnetHeader_t);

        packs->next = new Pack_Node;
        packs = packs->next;

        uint16_t protocol = ntohs(ethHeader->protoType);


        printf("[%02x:%02x:%02x:%02x:%02x:%02x]->[%02x:%02x:%02x:%02x:%02x:%02x] proto:%04x\n",
               ethHeader->srcMac[0], ethHeader->srcMac[1], ethHeader->srcMac[2], ethHeader->srcMac[3], ethHeader->srcMac[4], ethHeader->srcMac[5],
               ethHeader->dstMac[0], ethHeader->dstMac[1], ethHeader->dstMac[2], ethHeader->dstMac[3], ethHeader->dstMac[4], ethHeader->dstMac[5],
               protocol);

        packs->srcMAC=UncharToQstring(ethHeader->srcMac,6);
        packs->dstMAC=UncharToQstring(ethHeader->dstMac,6);
        // ip 协议
        if (protocol == 0x0800)
        {
            ipDecode(buf + proto_offset);
        }
        else if (protocol == 0x0806)//ARP协议未完成，这里还有待补充
        {
            packs->protocol = "ARP";
            printf("[%s:%d]unsupported protocol %#x\n", __FILE__, __LINE__,
                   protocol);
        }

        offset += (pcapHeader->caplen + sizeof(Pcap_pkthdr));
        mPackIndex++;
        packs->id = mPackIndex;
    }

    printf("total package count:%d\n", mPackIndex);

    if (buf)
    {
        free(buf);
        buf = NULL;
    }
}



