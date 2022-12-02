//
// Created by lijid on 2022/12/1.
//

#ifndef INTERNETPACKAGESENDER_PACKAGES_H
#define INTERNETPACKAGESENDER_PACKAGES_H

#pragma once
#define HAVE_REMOTE
#include "pcap.h"
#include <QtWidgets/QMainWindow>
#include "qstring.h"
#include "ui_QtGuiApplication5.h"
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")
#pragma comment(lib, "ws2_32.lib")
#define ETH_ARP         0x0806  //以太网帧协议类型，对于ARP协议，该值为0x0806
#define ARP_HARDWARE    1  //硬件类型字段，表示以太网地址
#define ETH_IP          0x0800  //以太网帧协议类型，0x0800表示IP协议
#define ARP_REQUEST     1   //ARP请求
#define ARP_RESPONSE       2      //ARP响应
#define PROTO_TCP 6   //TCP协议
#define PROTO_UDP 17  //UDP协议
#define MAX_BUFF_LEN 65500
using namespace std;


//14字节 以太网首部
struct EthernetHeader
{
    u_char DestMAC[6];    //目的MAC地址 6字节
    u_char SourMAC[6];   //源MAC地址 6字节
    u_short EthType;         //上层协议类型，0x0800表示IP协议，0x0806表示ARP协议 2字节
};

//28字节 ARP帧数据部分
struct ArpHeader
{
    unsigned short hdType;   //硬件类型
    unsigned short proType;   //协议类型
    unsigned char hdSize;   //硬件地址长度
    unsigned char proSize;   //协议地址长度
    unsigned short op;   //操作类型，ARP请求(1),ARP应答(2),RARP请求(3),RARP应答(4)
    u_char smac[6];   //源MAC地址
    unsigned char sip[4];   //源IP地址
    u_char dmac[6];   //目的MAC地址
    unsigned char dip[4];   //目的IP地址
};

//42字节 ARP报文包
struct ArpPacket {
    EthernetHeader ed;
    ArpHeader ah;
};

//IP头部
struct IpHeader
{
    unsigned char       h_verlen; //4位版本号，4位头部长度
    unsigned char       tos;//8位服务类型
    unsigned short      total_len;//16位总长度
    unsigned short      ident;//16位标识
    unsigned short      frag_and_flags;//3位标志位
    unsigned char       ttl;//8位生存时间
    unsigned char       proto;//8位协议
    unsigned short      checksum;//16位检验和
    unsigned int        sourceIP;//32源IP地址
    unsigned int        destIP;//32位目的IP地址
};

//TCP头部
struct TcpHeader
{
    unsigned short    th_sport;//16位源端口号
    unsigned short    th_dport;//16位目的端口号
    unsigned int    th_seq;//32序列号
    unsigned int    th_ack;//32确认号
    unsigned char    th_lenres;//4位头部长度，6位保留字之四
    unsigned char    th_flag;//6位保留字之二，6位标志位
    unsigned short    th_win;//16窗口大小
    unsigned short    th_sum;//16检验和
    unsigned short    th_urp;//16位紧急数据偏移量
};

//伪头部，用于计算校验和？
struct Psdhdr {
    unsigned long    saddr;
    unsigned long    daddr;
    char            mbz;
    char            ptcl;
    unsigned short    plen;
};

//UDP头部
struct UdpHeader
{
    u_short sport;		//16位源端口
    u_short dport;		//16位目的端口
    u_short len;			//16位数据报长度
    u_short check;		//16位检验和
};


#endif
