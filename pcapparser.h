#ifndef PCAPPARSER_H
#define PCAPPARSER_H
#include <stdint.h>

#pragma pack(1)
//pacp文件头结构体
struct Pcap_File_Header
{
    uint32_t magic;       /* 0xa1b2c3d4 */
    uint16_t version_major;   /* magjor Version 2 */
    uint16_t version_minor;   /* magjor Version 4 */
    uint32_t thiszone;      /* gmt to local correction */
    uint32_t sigfigs;     /* accuracy of timestamps */
    uint32_t snaplen;     /* max length saved portion of each pkt */
    uint32_t linktype;    /* data link type (LINKTYPE_*) */
};

//时间戳
struct time_val
{
    int tv_sec;         /* seconds 含义同 time_t 对象的值 */
    int tv_usec;        /* and microseconds */
};

//pcap数据包头结构体
struct Pcap_pkthdr
{
    struct time_val ts;  /* time stamp */
    uint32_t caplen; /* length of portion present */
    uint32_t len;    /* length this packet (off wire) */
};

// ethnet协议头
struct EthnetHeader_t
{
    unsigned char srcMac[6];
    unsigned char dstMac[6];
    uint16_t protoType;
};

//IP数据报头 20字节
struct IPHeader_t
{
    uint8_t Ver_HLen;       //版本+报头长度
    uint8_t TOS;            //服务类型
    uint16_t TotalLen;       //总长度
    uint16_t ID; //标识
    uint16_t Flag_Segment;   //标志+片偏移
    uint8_t TTL;            //生存周期
    uint8_t Protocol;       //协议类型
    uint16_t Checksum;       //头部校验和
    uint32_t SrcIP; //源IP地址
    uint32_t DstIP; //目的IP地址
};

// UDP头 (8字节)
struct UDPHeader_t
{
    uint16_t SrcPort;    // 源端口号16bit
    uint16_t DstPort;    // 目的端口号16bit
    uint16_t Length;     // 长度
    uint16_t CheckSum;   // 校验码
};

// TCP头 (20字节)
struct TCPHeader_t
{
    uint16_t srcPort;          // 源端口
    uint16_t dstPort;          // 目的端口
    uint32_t SeqNo;            // 序列号
    uint32_t AckNo;            // 确认号
    uint16_t headAndFlags;     // 首部长度即标志位
    uint16_t WinSize;          // 窗口大小
    uint16_t CheckSum;         // 校验和
    uint16_t UrgPtr;           // 紧急指针
};

struct ICMPHeader_t
{
    unsigned char type;
    unsigned char code;
    unsigned short CheckSum;
    unsigned short icmp_id;
    unsigned short icmp_seq;

};

#pragma pack()

class PcapParser
{
private:
    char mUdpData[4096];             // 4k缓存
    uint32_t mUdpLen;
    char mTcpData[4096];             // 4k缓存
    uint32_t mTcpLen;
    char mIcmpData[4096];             // 4k缓存
    uint32_t mIcmpLen;

    uint32_t mPackIndex;


    void ipDecode(const char* buf);
    void udpDecode(const char* buf, int len);
    void tcpDecode(const char* buf, int len);
    void icmpDecode(const char* buf,int len);
    void arpDecode(const char* buf, int len);

public:
    PcapParser() : mUdpLen(0), mTcpLen(0),mIcmpLen(0) { }
    ~PcapParser(){}
public:
    // 过滤Ip
    virtual int ipFilter(const char* srcIp, const char* dstIp){ return 0; }
    // 过滤端口
    virtual int tcpFilter(const uint16_t srcPort, const uint16_t dstPort, const uint32_t msgLen) { return 0; }
    virtual int udpFilter(const uint16_t srcPort, const uint16_t dstPort, const uint32_t msgLen) { return 0; }
    // udp消息回调
    virtual int onUdpMsg(const char* buf, int len){ return 0; }
    // tcp消息回调
    virtual int onTcpMsg(const char* buf, int len){ return 0; }

    // pcap文件解析
    void parse(const char* filename);
};

#endif // PCAPPARSER_H

