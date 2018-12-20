/*************************************************************************
	> File Name: mi_gtpv2.h
	> Author:xfzhang 
	> Mail:923036400@qq.com 
	> Created Time: 2018年08月03日 星期五 11时27分28秒
 ************************************************************************/

#ifndef _MI_GTPV2_H
#define _MI_GTPV2_H
#include <stdio.h>
#include "GRE.h"
#include <sys/types.h>
#include <bits/types.h>
#include <ctype.h>

enum{
	HEAD = 0,	//head_teid+dst_ip
	S11_SGW,//interface type = 11
	S11_MME,//interface type = 10
	S1U_SGW,//interface type = 1
	S1U_ENB,
	S5_PGW,//interface type = 7
	S5_SGW,
	S5U_PGW,//interface type = 5
	S5U_SGW,//interface type = 4
	MAX,
	
};
enum{
	s1u_enb = 0,
	s1u_sgw = 1,
	s5u_sgw = 4,
	s5u_pgw = 5,
	s5c_sgw = 6,
	s5c_pgw = 7,
	s11c_mme = 10,
	s11c_sgw = 11,
	flag_max,
};
	
enum{
	HELP=1,
	SEARCH,
	CUT,
	CREATE,
	MODIFY,
	DEL_VLAN,
	ADD_VLAN,
};
enum{
	STRING = 1,
	UINT64_T = 2,
	UINT16_T = 3,
	TUNNEL = 4,
};
typedef struct _ipv4_addr
{
	union {
		unsigned int addr;
		unsigned char b[4];
	};
}ipv4_addr;
typedef struct _ipv6_addr
{
	union {
		unsigned long long addr64[2];
		unsigned int addr32[4];
		unsigned short addr16[8];
		unsigned char addr8[16];
	};
}ipv6_addr;
enum{
	ie_type_imsi = 1,
};
typedef struct m_value_type{
	char name[16];
	int value_type;
}modify_value_type;

typedef struct _CON_TEID_IP
{
    int teid;
    char ip[16];
} CON_TEID_IP;
typedef struct _tunnel
{
    uint32_t teid;
    ipv4_addr ip;
} tunnel_t;

typedef struct _save_CON
{
    CON_TEID_IP *con;
	int count;
	int sum_count;
	uint64_t *imsi;
	int imsi_count;
	int imsi_sum;
	uint64_t *msisdn;
	int msisdn_count;
	int msisdn_sum;
} save_CON;
typedef struct _gtpv2_pcap_info{
	int count;
	int msg_type;
	uint64_t imsi;
	uint64_t imei;
	uint64_t msisdn;
	uint32_t plmnid;
	uint32_t tac;
	uint32_t ci;
	tunnel_t tunnel[MAX];
	char apn[32];
}gtpv2_pcap_info;

typedef struct cur_con_in_pcap_t
{
    unsigned char Message_Type;
    unsigned char IMSI[16];
    unsigned char MSISDN[14];
	CON_TEID_IP con[MAX];
	CON_TEID_IP sip;
    int flag; //1.匹配上了查询的信息,转出. 0.未匹配上，不转出
} cur_con_in_pcap;
typedef struct singal_flag{
	int NUM;
	int T_IP_FLAG;
	int CIR_SIGNAL;
    int CIR_SIGNAL_START;
    int CIR_SIGNAL_LINE;
    int MESS_TYPE;
    int MESS_TYPE_CATCH;
    int IMSI;
	int MSISDN;
    char IMSI_CATCH[15];
    char MSISDN_CATCH[13];
	int NOT;
	int MUTI_CATCH;
	char CATCH_INFO[32];
}singal_flag_t;

//save_CON store_con;
//cur_con_in_pcap cur_con_in_p;
//struct _CON_TEID_IP *s_con;
//singal_flag_t S_Flag;
//long long int count;
#define N 1024
//int con_size = 0;
//int significant_con_size = 0;

typedef union ___uint64_{
	uint64_t value;
	uint8_t byte[8];
}uint64_t_byte;
//typedef uint64_t_byte_t uint64_t_byte;

#define DEBUG_LINE do{printf("%s:%d\n",__func__,__LINE__);}while(0)

#define PRINT_LINE(fmt, args...) do{printf("========================="); printf(fmt, ##args);printf("=========================\n");}while(0)
#define DEBUG_PRINT(fmt, args...) do{if(1){ printf(fmt, ##args);}}while(0)

int CON_Is_In(CON_TEID_IP teid_ip,CON_TEID_IP* con,int);
int CON_Is_Stored(CON_TEID_IP teid_ip,save_CON con);
int search_teid_in_head(GTP_t*,int *);
int search_teid_in_Data(const u_char *,int,int,int *);
int search_pcap_by_con_in_head(GTP_t* gtp_head,cur_con_in_pcap **cur_con_in_p);

int search_pcap_by_con_in_data(const u_char* ptkdata,int offset,int size,cur_con_in_pcap **cur_con_in_p);
int fgets_line(char *,int,FILE *,int);
void printf_cur_con(cur_con_in_pcap *);
int set_filter_flag(char *op,char *filter_flag,char *catch_info,singal_flag_t *Flag);
int gtp_parse_dissector(const      u_char *pktdata,cur_con_in_pcap **cur_con_in_p,long long count);
int pcap_cache_out(cur_con_in_pcap *cur_con_in_p,pcap_dumper_t **out_pfile,struct pcap_pkthdr *p_head,const u_char *pkt_data,save_CON **p2_store_con,singal_flag_t *p_singal_flag);
int store_con_init(save_CON **p2_store_con,CON_TEID_IP **p2_s_con,char* input_file,int T_P_FLAG);
int cat_usage();
int save_msisdn_in_store_con(uint64_t msisdn,save_CON **p2_store_con);
int save_imsi_in_store_con(uint64_t imsi,save_CON **p2_store_con);
int output_search_info(save_CON store_con,char *imsi_file,char *msisdn_file,char *con_file,char *CACHE_INFO,char *pathname);
void get_time(char *cur_time);
int filter(char *catch_info_file,char *ori_pcap_file,singal_flag_t Flag);

int read_modify_file(gtpv2_pcap_info *p_pkt_info,char *modify_file,int index);


#endif
