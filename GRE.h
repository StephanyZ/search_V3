/*************************************************************************
> File Name: GRE.h
> Author:xfzhang 
> Mail:923036400@qq.com 
> Created Time: 2017年07月11日 星期二 13时37分07秒
************************************************************************/

#ifndef _GRE_H
#define _GRE_H
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

typedef struct pcap_file_header_m{
        int magic;
        short version_major;
        short version_minjor;
        int thiszone;
        int sigfigs;
        int snaplen;
        int linktype;
}pcap_file_header_f;

typedef struct timestamp{
        int timestamp_sec;
        int timestamp_usec;
}timestamp;


typedef struct pcap_header{
        struct timestamp ts;
        int capture_len;    
        int len;           
}pcap_header;

typedef struct MACHeader{
    unsigned char Destin_MAC[6];
    unsigned char Source_MAC[6];
    short Type;       
}MACHeader_t;

typedef struct IPHeader{
    char Ver_and_HLen;
    char Type_Of_Service;
    short Len_Of_IPData;//IPhead+IPData
    short Packet_ID;
    short Flag_Segment;
    char TTL;
    char Protocol_Type;
    short Check_Sum;
    char Source_IP[4];
    char Destin_IP[4];
}IPHeader_t;

typedef struct UDPHeader{
    short Source_port;
    short Destin_port;
    short Len_of_UDPData;//UDPHeader_t+UDPData
}UDPHeader_t;

typedef struct GTP_t{
    char flag;
    char Message_Type;//total-4
    short Len_Of_GTPData;
    int TEID;
}GTP_t;
#pragma pack(push)
#pragma pack(1)
typedef struct IEHead{
    char IE_Type;
    short IE_Len; //Total=4+data
    short Flag;
}IEHead_t;
typedef struct _ie_info{
	u_char ie_type;
	u_short length;
	u_char cr_flag:4;
	u_char instance:4;
	u_char *ptr_value;
}ie_info;
#pragma pack(pop)

typedef struct _802_1Q_LAN{
    short Flag;
    short Type;
}_802_1Q_LAN_t;


//typedef unsigned long long uint64_t;
//typedef unsigned int uint32_t;
//typedef unsigned char uint8_t;



#endif

