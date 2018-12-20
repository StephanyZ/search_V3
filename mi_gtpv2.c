/*************************************************************************
	> File Name: mi_gtpv2.c
	> Author:xfzhang
	> Mail:923036400@qq.com
	> Created Time: 2018年08月03日 星期五 11时27分13秒
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include "GRE.h"
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <bits/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "mi_gtpv2.h"
extern int FFLAG;
extern int g_debug;


int fgets_line(char *ss,int size,FILE *fp,int line_num)
{
    int i=0;
    while(fgets(ss,size,fp)!=NULL)
    {
        if(i==line_num)
        {
            return 1;
        }
        i++;
    }
    return 0;
}
void printf_cur_con(cur_con_in_pcap *c_con)
{
    printf("Message_Type:%d\n",(unsigned char)c_con->Message_Type);
    printf("IMSI:%s\n",c_con->IMSI);
    printf("MSISDN:%s\n",c_con->MSISDN);
    printf("sip:%s\n",c_con->sip.ip);
    for(int i = 0; i<MAX; i++)
    {
        printf("cur_info[%d]:%.4x ip:%s\n",i,c_con->con[i].teid,c_con->con[i].ip);
    }
    /*
    printf("head_teid:%.4x ip:%s\n",c_con->con[HEAD].teid,c_con->con[HEAD].ip);
    printf("s11_sgw_teid:%.4x ip:%s\n",c_con->con[S11_SGW].teid,c_con->con[S11_SGW].ip);
    printf("s11_mme_teid:%.4x ip:%s\n",c_con->con[S11_MME].teid,c_con->con[S11_MME].ip);
    printf("s1_u_sgw:%.4x ip:%s\n",c_con->con[S1U_SGW].teid,c_con->con[S1U_SGW].ip);
    printf("s1_u_enodeB:%.4x ip:%s\n",c_con->con[S1U_ENB].teid,c_con->con[S1U_ENB].ip);
    printf("s5_pgw:%.4x ip:%s\n",c_con->con[S5_PGW].teid,c_con->con[S5_PGW].ip);
    printf("s5_sgw:%.4x ip:%s\n",c_con->con[S5_SGW].teid,c_con->con[S5_SGW].ip);
    printf("s5_pgw_u:%.4x ip:%s\n",c_con->con[S5U_PGW].teid,c_con->con[S5U_PGW].ip);
    printf("s5_sgw_u:%.4x ip:%s\n",c_con->con[S5U_SGW].teid,c_con->con[S5U_SGW].ip);
    */
    printf("flag:%d\n",c_con->flag);
}

int search_pcap_by_con_in_head(struct GTP_t* gtp_head,cur_con_in_pcap **cur_con_in_p)
{
    cur_con_in_pcap *ptr = *cur_con_in_p;
    unsigned int teid=ntohl(gtp_head->TEID);
    ptr->con[HEAD].teid=teid;
    /*
    if(CON_Is_In(ptr->con[HEAD],CON,con_size)==1)
    {
        ptr->flag=1;
        return 1;
    }*/
    return 0;
}
int ne_type[flag_max]=
{
    [s1u_enb] = S1U_ENB,
    [s1u_sgw] = S1U_SGW,
    [s5u_sgw] = S5U_SGW,
    [s5u_pgw] = S5U_PGW,
    [s5c_sgw] = S5_SGW,
    [s5c_pgw] = S5_PGW,
    [s11c_mme] = S11_MME,
    [s11c_sgw] = S11_SGW,
};
char *str_type[MAX]=
{
    [S1U_ENB] = "s1u_enb",
    [S1U_SGW] = "s1u_sgw",
    [S5U_SGW] = "s5u_sgw",
    [S5U_PGW] = "s5u_pgw",
    [S5_SGW] = "s5c_sgw",
    [S5_PGW] = "s5c_pgw",
    [S11_MME] = "s11c_mme",
    [S11_SGW] = "s11c_sgw",
};
int ie_imsi_modify(const u_char* pktdata,ie_info *ie_head,gtpv2_pcap_info *modify_pkt_info)
{
    DEBUG_LINE;
    unsigned char *imsi_byte_ptr = NULL;
    uint64_t_byte imsi;
    imsi_byte_ptr = (unsigned char *)pktdata;
    printf("modify.imsi:%lx\n",modify_pkt_info->imsi);
    printf("ie_head.ptr = %p\n",ie_head->ptr_value);
    printf("pkt_data_ptr = %p\n",imsi_byte_ptr);
    imsi.value = modify_pkt_info->imsi;
    //sprintf(imsi,"%lx",modify_pkt_info.imsi);
    //memcpy(imsi,imsi_byte_ptr,8);
    printf("ori_pkt_byte (pktdata):%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x\n",imsi.byte[0],imsi.byte[1],imsi.byte[2],imsi.byte[3],imsi.byte[4],imsi.byte[5],imsi.byte[6],imsi.byte[7]);
    //printf("ori_pkt_byte (ie_ptr):%lx\n",*(long unsigned int *)ie_head->ptr_value);
	//memcpy(&imsi.value,)
	DEBUG_LINE;
    return 0;
}
typedef int (*ie_modify_func)(const u_char* pktdata,ie_info *ie_head,gtpv2_pcap_info modify_pkt_info);

ie_modify_func modify_ie_func[100] =
{
    [ie_type_imsi] = ie_imsi_modify,
};

int search_pcap_by_con_in_data(const u_char* ptkdata,int offset,int size,cur_con_in_pcap **cur_con_in_p)
{

    IEHead_t *ie_head;
    int plus_offset=offset;
    int FF=0;
    int *tid;
    char fflag=-1;
    int type = -1;
    ipv4_addr tmp_ip;
    tmp_ip.addr = 0;
    cur_con_in_pcap *cur_con_ptr = *cur_con_in_p;
    //char IP[16];
    CON_TEID_IP con;
    //printf("size:%d offset:%d\n",size,offset);
    while(plus_offset-offset<size-8)
    {
        fflag=-1;
        ie_head=(IEHead_t*)(ptkdata+plus_offset);
        if((unsigned char)ie_head->IE_Type==87)
        {
            plus_offset+=5;
            fflag=(unsigned char)ntohs(ie_head->Flag)&0x3f;
            tid=(int*)(ptkdata+plus_offset);
            plus_offset+=4;
            tmp_ip.addr = *(unsigned int*)(ptkdata+plus_offset);
            con.teid=(unsigned int)ntohl(*tid);
            sprintf(con.ip,"%d.%d.%d.%d",tmp_ip.b[0],tmp_ip.b[1],tmp_ip.b[2],tmp_ip.b[3]);
            //printf("%s:%d con.ip = %s\n", __func__,__LINE__,con.ip);
            type = ne_type[(int)fflag];
            if(cur_con_ptr->con[type].teid==0)
            {
                cur_con_ptr->con[type].teid=con.teid;
                strcpy(cur_con_ptr->con[type].ip,con.ip);
            }
            plus_offset-=9;
        }
        if((unsigned char)ie_head->IE_Type==1)
        {
            //printf("imsi:\n");
            plus_offset+=4;
            unsigned char *imsi_byte_ptr = NULL;
            imsi_byte_ptr = (unsigned char *)ptkdata+plus_offset;
            memset(cur_con_ptr->IMSI,0,sizeof(cur_con_ptr->IMSI));
            for(int i=0; i<8; i++)
            {
                sprintf((char *)cur_con_ptr->IMSI,"%s%02x",cur_con_ptr->IMSI,((*(imsi_byte_ptr)&0xf0)>>4)|((*(imsi_byte_ptr)&0xf)<<4));
                imsi_byte_ptr++;
            }
            memset(cur_con_ptr->IMSI+15,'\0',1);
            //printf("IMSI:%s\n",cur_con_ptr->IMSI);
            plus_offset-=4;
        }
#if 1
        if((unsigned char)ie_head->IE_Type==76)
        {
            //printf("msisdn:\n");
            plus_offset+=4;
            unsigned char *msisdn_byte_ptr = NULL;
            msisdn_byte_ptr = (unsigned char *)ptkdata+plus_offset;
            memset(cur_con_ptr->MSISDN,0,sizeof(cur_con_ptr->MSISDN));
            for(int i=0; i<7; i++)
            {
                sprintf((char *)cur_con_ptr->MSISDN,"%s%02x",cur_con_ptr->MSISDN,((*(msisdn_byte_ptr)&0xf0)>>4)|((*(msisdn_byte_ptr)&0xf)<<4));
                msisdn_byte_ptr++;
            }
            memset(cur_con_ptr->MSISDN+13,'\0',1);
            //printf("MSISDN:%s IMSI:%s\n",cur_con_ptr->MSISDN,cur_con_ptr->IMSI);
            plus_offset-=4;
        }
#endif
        if((unsigned char)ie_head->IE_Type==93)
        {
            //printf("bear plus_offset:%d\n",plus_offset);
            if(search_pcap_by_con_in_data(ptkdata,plus_offset+4,(unsigned short)ntohs(ie_head->IE_Len),cur_con_in_p)==1)
            {
                // FF=1;
            }
        }
        plus_offset+=4+(unsigned short)ntohs(ie_head->IE_Len);
    }
    if(FF==1)
    {
        cur_con_ptr->flag=1;
        return 1;
    }
    else
    {
        return 0;
    }
}


int modify_pcap_in_data(const u_char* ptkdata,int offset,int size,gtpv2_pcap_info modify_pkt_info)
{

    ie_info *ie_head;
    int plus_offset=offset;
    // int FF=0;
    //int *tid;
    //char fflag=-1;
    //int type = -1;
    //ipv4_addr tmp_ip;
    //tmp_ip.addr = 0;
    //cur_con_in_pcap *cur_con_ptr = *cur_con_in_p;
    //char IP[16];
    //CON_TEID_IP con;
    //printf("size:%d offset:%d\n",size,offset);
    DEBUG_LINE;
    while(plus_offset-offset<size-8)
    {
        //fflag=-1;
        ie_head=(ie_info*)(ptkdata+plus_offset);
        plus_offset += 4;
        printf("ie_type:%d\n",(unsigned char)ie_head->ie_type);
        if((unsigned char)ie_head->ie_type == 1)
        {
            printf("pktdata_ptr:%p\n",ptkdata+plus_offset);
			if(NULL != modify_ie_func[(unsigned char)ie_head->ie_type])
            	modify_ie_func[(unsigned char)ie_head->ie_type](ptkdata+plus_offset,ie_head,modify_pkt_info);
        }
        DEBUG_LINE;
        printf("plus_offset:%d\n",plus_offset);
#if 0
        if((unsigned char)ie_head->IE_Type==87)
        {
            plus_offset+=5;
            fflag=(unsigned char)ntohs(ie_head->Flag)&0x3f;
            tid=(int*)(ptkdata+plus_offset);
            plus_offset+=4;
            tmp_ip.addr = *(unsigned int*)(ptkdata+plus_offset);
            con.teid=(unsigned int)ntohl(*tid);
            sprintf(con.ip,"%d.%d.%d.%d",tmp_ip.b[0],tmp_ip.b[1],tmp_ip.b[2],tmp_ip.b[3]);
            //printf("%s:%d con.ip = %s\n", __func__,__LINE__,con.ip);
            type = ne_type[(int)fflag];
            if(cur_con_ptr->con[type].teid==0)
            {
                cur_con_ptr->con[type].teid=con.teid;
                strcpy(cur_con_ptr->con[type].ip,con.ip);
            }
            plus_offset-=9;
        }
        if((unsigned char)ie_head->IE_Type==1)
        {
            //printf("imsi:\n");
            plus_offset+=4;
            unsigned char *imsi_byte_ptr = NULL;
            imsi_byte_ptr = (unsigned char *)ptkdata+plus_offset;
            memset(cur_con_ptr->IMSI,0,sizeof(cur_con_ptr->IMSI));
            for(int i=0; i<8; i++)
            {
                sprintf((char *)cur_con_ptr->IMSI,"%s%02x",cur_con_ptr->IMSI,((*(imsi_byte_ptr)&0xf0)>>4)|((*(imsi_byte_ptr)&0xf)<<4));
                imsi_byte_ptr++;
            }
            memset(cur_con_ptr->IMSI+15,'\0',1);
            //printf("IMSI:%s\n",cur_con_ptr->IMSI);
            plus_offset-=4;
        }
#if 1
        if((unsigned char)ie_head->IE_Type==76)
        {
            //printf("msisdn:\n");
            plus_offset+=4;
            unsigned char *msisdn_byte_ptr = NULL;
            msisdn_byte_ptr = (unsigned char *)ptkdata+plus_offset;
            memset(cur_con_ptr->MSISDN,0,sizeof(cur_con_ptr->MSISDN));
            for(int i=0; i<7; i++)
            {
                sprintf((char *)cur_con_ptr->MSISDN,"%s%02x",cur_con_ptr->MSISDN,((*(msisdn_byte_ptr)&0xf0)>>4)|((*(msisdn_byte_ptr)&0xf)<<4));
                msisdn_byte_ptr++;
            }
            memset(cur_con_ptr->MSISDN+13,'\0',1);
            //printf("MSISDN:%s IMSI:%s\n",cur_con_ptr->MSISDN,cur_con_ptr->IMSI);
            plus_offset-=4;
        }
#endif
#endif
        if((unsigned char)ie_head->ie_type==93)
        {
            //printf("bear plus_offset:%d\n",plus_offset);
            if(modify_pcap_in_data(ptkdata,plus_offset,(unsigned short)ntohs(ie_head->length),modify_pkt_info)==1)
            {
                // FF=1;
            }
        }
        plus_offset+=(unsigned short)ntohs(ie_head->length);
    }
    return 0;
}

void print_hex(char *buf,int size)
{
    printf("\n");
    for(int i=0; i<size; i++)
    {
        printf("%.2x ",(unsigned char)buf[i]);
        if((i+1)%16==0)
        {
            printf("\n");
        }
        else if((i+1)%8==0)
        {
            printf(" ");
        }
    }
    printf("\n");
}
int CON_Is_In(CON_TEID_IP con,CON_TEID_IP *TEID_IP,int count_size)
{
    int i=0;
    while(i<count_size)
    {
        if(FFLAG==0x10)
        {
            if(TEID_IP[i].teid==con.teid)
            {
                return 1;
            }
        }
        else if(FFLAG==0x11)
        {
            if(TEID_IP[i].teid==con.teid&&strcmp(TEID_IP[i].ip,con.ip)==0)
            {
                return 1;
            }
        }
        i++;
    }
    return 0;
}
int IMSI_Is_Stored(uint64_t imsi,save_CON store_con)
{
    int i = 0;
    //printf("store_con.imsi_count:%d\n",store_con.imsi_count);
    while(i<store_con.imsi_count)
    {
        if(store_con.imsi[i] == imsi)
        {
            return 1;
        }
        i++;
    }
    return 0;
}
int MSISDN_Is_Stored(uint64_t msisdn,save_CON store_con)
{
    int i = 0;
    //printf("store_con.msisdn_count:%d\n",store_con.msisdn_count);
    while(i<store_con.msisdn_count)
    {
        //printf("stor_msisdn[%d] = %lu msisdn = %lu\n",i,store_con.msisdn[i],msisdn);
        if(store_con.msisdn[i] == msisdn)
        {
            return 1;
        }
        i++;
    }
    return 0;
}

int CON_Is_Stored(CON_TEID_IP con,save_CON store_con)
{
    int i=0;
    //store_con.con=s_con;
    while(i<store_con.count)
    {
        if(FFLAG==0x10)
        {
            if(store_con.con[i].teid==con.teid)
            {
                return 1;
            }
        }
        else if(FFLAG==0x1)
        {
            if(strcmp(store_con.con[i].ip,con.ip)==0)
            {
                return 1;
            }
        }
        else if(FFLAG==0x11)
        {
            if(store_con.con[i].teid==con.teid&&strcmp(store_con.con[i].ip,con.ip)==0)
            {
                return 1;
            }
        }
        i++;
    }
    return 0;
}
int output_search_info(save_CON store_con,char *imsi_file,char *msisdn_file,char *con_file,char *CACHE_INFO,char *pathname)
{
    FILE *con_fp,*imsi_fp,*msisdn_fp;
    sprintf(con_file,"%s/%s_con.txt",pathname,CACHE_INFO);
    sprintf(imsi_file,"%s/%s_imsi.txt",pathname, CACHE_INFO);
    sprintf(msisdn_file,"%s/%s_msisdn.txt",pathname, CACHE_INFO);

    char ss_out[100];
    if((con_fp=fopen(con_file,"w+"))==NULL)
    {
        printf("%s open error1\n",con_file);
    }
    for(int i=0; i<store_con.count; i++)
    {
        sprintf(ss_out,"0x%.8x %s\n",store_con.con[i].teid,store_con.con[i].ip);
        fputs(ss_out,con_fp);
        //printf("CON[%d]: teid:0x%.8x  ip:%s\n",i,store_con.con[i].teid,store_con.con[i].ip);
    }
    fclose(con_fp);

    if((imsi_fp=fopen(imsi_file,"w+"))==NULL)
    {
        printf("%s open error1\n",imsi_file);
    }
    for(int i=0; i<store_con.imsi_count; i++)
    {
        sprintf(ss_out,"%lu\n",store_con.imsi[i]);
        fputs(ss_out,imsi_fp);
    }
    fclose(imsi_fp);

    if((msisdn_fp=fopen(msisdn_file,"w+"))==NULL)
    {
        printf("%s open error1\n",msisdn_file);
    }
    for(int i=0; i<store_con.msisdn_count; i++)
    {
        sprintf(ss_out,"%lu\n",store_con.msisdn[i]);
        fputs(ss_out,msisdn_fp);
    }
    fclose(msisdn_fp);
    return 0;
}
int cat_usage()
{
    FILE *read;
    if((read=fopen("usepage","r"))==NULL)
    {
        printf("open usepage error!\n");
        return 0;
    }
    char content[1024];
    while(fgets(content,1024,read)!=NULL)
    {
        printf("%s",content);
    }
    fclose(read);
    return 0;
}
int set_filter_flag(char *op,char *filter_flag,char *catch_info,singal_flag_t *Flag)
{
    int NUM_SET = 0;
    char flag[10]= {0};
    int i = 0;
    if(strcmp(op,"--help")==0 || strcmp(op,"-h")==0 ||strcmp(op,"help")==0)
    {
        return HELP;
    }
    else if(strcmp(op,"--cut")==0 || strcmp(op,"-c")==0)
    {
        return CUT;
    }
    else if(strcmp(op,"--create")==0 || strcmp(op,"-C")==0)
    {
        return CREATE;
    }
    else if(strcmp(op,"--modify")==0 || strcmp(op,"-m")==0)
    {
        return MODIFY;
    }
	else if(strcmp(op,"--delvlan")==0 || strcmp(op,"-dv")==0)
    {
        return DEL_VLAN;
    }
	else if(strcmp(op,"--addvlan")==0 || strcmp(op,"-av")==0)
    {
        return ADD_VLAN;
    }
    Flag->NUM = 2;
    strcpy(flag,filter_flag);
    for(i=0; i<strlen(filter_flag); i++)
    {
        if(flag[i]=='c')
        {
            NUM_SET=2;
        }
        else if(flag[i]=='s')
        {
            NUM_SET=1;
        }
        else if(flag[i]=='u')
        {
            NUM_SET=3;
        }
        else if(flag[i]=='t')		//通过teid单独过滤
        {
            FFLAG =0x10;
        }
        else if(flag[i]=='i')		//通过ip过滤 ,默认表示通过teid+ip过滤
        {
            FFLAG =0x1;
        }
        else if(flag[i]=='p')
        {
            Flag->CIR_SIGNAL=1;					//对input.txt内的每一行teid+ip单条输出pcap
        }
        else if(flag[i]=='a')
        {
            Flag->MUTI_CATCH = 1;;
        }
        else if(flag[i]=='m')
        {
            Flag->MESS_TYPE=1;					//标志，要求匹配message_type
            Flag->MESS_TYPE_CATCH=atoi(catch_info);
            Flag->T_IP_FLAG = 0;
            if(Flag->MESS_TYPE_CATCH == 32)
            {
                Flag->NUM = 1;
            }
            else if(Flag->MESS_TYPE == 35)
            {
                Flag->NUM = 2;
            }
            else
            {
                Flag->NUM = 3;
            }
        }
        else if(flag[i]=='I')
        {
            Flag->IMSI=1; 						//标志，要求匹配imsi
            strcpy(Flag->IMSI_CATCH,catch_info);
            Flag->T_IP_FLAG = 0;
            Flag->NUM = 1;						//若能直接取到imsi，则过滤一遍就可以获得关联流
            //sprintf(log,"e212.imsi==\"%s\"",IMSI_CATCH);
            // printf("%s\n",log);
            // fputs(log,log_out);
        }
        else if(flag[i]=='M')
        {
            Flag->MSISDN=1;						//标志，要求匹配msisdn
            strcpy(Flag->MSISDN_CATCH,catch_info);	//需要匹配的msisdn值
            Flag->T_IP_FLAG = 0;
            Flag->NUM = 2;						//设置循环此时为2是因为若报文中没有create session request 还可通过mody bearer request获取msisdn进行两轮过滤
        }
        else if(flag[i]=='n')
        {
            Flag->NOT=1;
            Flag->NUM = 1;
        }
        else if(flag[i]=='f')
        {
            Flag->T_IP_FLAG = 1;
        }
    }

    if(Flag->T_IP_FLAG == 1)
    {
        sscanf(catch_info,"%[^.].%*s",Flag->CATCH_INFO);
    }
    else
    {
        strcpy(Flag->CATCH_INFO,catch_info);
    }
    if(NUM_SET)
    {
        Flag->NUM = NUM_SET;
    }
    printf("CIRCLE_NUM = %d\n",Flag->NUM);
    return SEARCH;

}
int gtp_parse_modify(const u_char *pktdata,gtpv2_pcap_info modify_pkt_info,long long count)
{
    MACHeader_t *eptr;
    _802_1Q_LAN_t *lan;
    IPHeader_t *ip_head;
    GTP_t *gtp_head;
    UDPHeader_t *udp;
    //eth
    int plus_offset = 0;
    //cur_con_in_pcap *tmp_cur_ptr = *cur_con_in_p;
    eptr=(MACHeader_t*)(pktdata);
    plus_offset=sizeof(MACHeader_t);
two_vlan:
    if(ntohs(eptr->Type)==0x8100)
    {
        lan = (_802_1Q_LAN_t*)(pktdata+plus_offset);
        if(ntohs(lan->Type)==0x0800)
            plus_offset+=sizeof(_802_1Q_LAN_t);
        else if(ntohs(lan->Type)==0x8100)
        {
            plus_offset+=sizeof(_802_1Q_LAN_t);
            goto two_vlan;
        }
        else
        {
            //printf("LAN_PRO is not 0x0800 or 0x8100!\n");
            printf("vlan type:%.4x count:%lld\n",ntohs(lan->Type),count);
            return 0;
        }
    }
    else if(ntohs(eptr->Type)!=0x0800)
    {
        printf("Ether type:%.4x count:%lld\n",ntohs(eptr->Type),count);
        return 0;
    }
    //ip
    ip_head=(IPHeader_t*)(pktdata+plus_offset);
    //sprintf(tmp_cur_ptr->sip.ip,"%d.%d.%d.%d",(unsigned char)ip_head->Source_IP[0],(unsigned char)ip_head->Source_IP[1],(unsigned char)ip_head->Source_IP[2],(unsigned char)ip_head->Source_IP[3]);
    //sprintf(tmp_cur_ptr->con[HEAD].ip,"%d.%d.%d.%d",(unsigned char)ip_head->Destin_IP[0],(unsigned char)ip_head->Destin_IP[1],(unsigned char)ip_head->Destin_IP[2],(unsigned char)ip_head->Destin_IP[3]);
    plus_offset+=sizeof(IPHeader_t);
    //udp
    udp = (UDPHeader_t*)(pktdata+plus_offset);
    plus_offset+=sizeof(UDPHeader_t) +2;

    if((unsigned char)ip_head->Protocol_Type==17)
    {
        gtp_head=(GTP_t*)(pktdata+plus_offset);
        //tmp_cur_ptr->Message_Type=(unsigned char)(gtp_head->Message_Type);
        //search_pcap_by_con_in_head(gtp_head,cur_con_in_p);//head
        plus_offset+=sizeof(GTP_t)+4;
        //printf("sport:%x dport:%x\n",(unsigned short)ntohs(udp->Source_port),(unsigned short)ntohs(udp->Destin_port));
        if((unsigned short)ntohs(udp->Source_port) == 2123 || (unsigned short)ntohs(udp->Destin_port) == 2123)
        {
            modify_pcap_in_data(pktdata,plus_offset,(unsigned short)ntohs(gtp_head->Len_Of_GTPData), modify_pkt_info);
        }
    }
    else
    {
        printf("ip type is not equal 17! ip protocol type: %d count:%lld\n",(unsigned char)ip_head->Protocol_Type,count);
    }
    return 0;
}
int _5g_cdr_add_vlan(const u_char *pktdata,char **pcap_out,int *vlan_count,struct pcap_pkthdr **pkt_head)
{
   // MACHeader_t *eptr;
    //_802_1Q_LAN_t *lan;
   // IPHeader_t *ip_head;
    //eth
    int plus_offset = 0;
   	int vlan_add = 0x26030081;
    //cur_con_in_pcap *tmp_cur_ptr = *cur_con_in_p;
    //eptr=(MACHeader_t*)(pktdata);
    plus_offset=sizeof(MACHeader_t);
	//int vlan_flag = 0;
	//print_hex((char *)pktdata, 50);
	*pcap_out = (char *)malloc(sizeof(char) * ((*pkt_head)->len));
	memcpy(*pcap_out,pktdata,sizeof(MACHeader_t)-2);
	
	memcpy(*pcap_out+sizeof(MACHeader_t)-2,&vlan_add,4);
	memcpy(*pcap_out+sizeof(MACHeader_t)+2,pktdata+sizeof(MACHeader_t)-2,sizeof(IPHeader_t)+sizeof(UDPHeader_t)+2);
	plus_offset = sizeof(MACHeader_t)+sizeof(_802_1Q_LAN_t)+sizeof(IPHeader_t)+sizeof(UDPHeader_t);
	memcpy(*pcap_out+plus_offset,pktdata+plus_offset,(*pkt_head)->len-plus_offset);
	//print_hex(*pcap_out, 50);
	//printf("vlan count = %d\n",*vlan_count);
    return 0;

}

int gtp_parse_no_vlan(const u_char *pktdata,char **pcap_out,int *vlan_count,struct pcap_pkthdr **pkt_head)
{
    MACHeader_t *eptr;
    _802_1Q_LAN_t *lan;
   // IPHeader_t *ip_head;
    //eth
    int plus_offset = 0;
    //cur_con_in_pcap *tmp_cur_ptr = *cur_con_in_p;
    eptr=(MACHeader_t*)(pktdata);
    plus_offset=sizeof(MACHeader_t);
	//int vlan_flag = 0;
two_vlan:
    if(ntohs(eptr->Type)==0x8100)
    {
        lan = (_802_1Q_LAN_t*)(pktdata+plus_offset);
		(*vlan_count)++;
		(*pkt_head)->caplen = (*pkt_head)->caplen-4;
		(*pkt_head)->len = (*pkt_head)->len-4;
        if(ntohs(lan->Type)==0x0800)
            plus_offset+=sizeof(_802_1Q_LAN_t);
        else if(ntohs(lan->Type)==0x8100)
        {
            plus_offset+=sizeof(_802_1Q_LAN_t);
            goto two_vlan;
        }
        else
        {
        	plus_offset+=sizeof(_802_1Q_LAN_t);
        }
    }

	if((*vlan_count) > 0){
		*pcap_out = (char *)malloc(sizeof(char) * ((*pkt_head)->len));
		memcpy(*pcap_out,pktdata,sizeof(MACHeader_t)-2);
		memcpy(*pcap_out+sizeof(MACHeader_t)-2,pktdata+plus_offset-2,(*pkt_head)->len-sizeof(MACHeader_t)+2);
		//print_hex(*pcap_out, 40);
		//printf("vlan count = %d\n",*vlan_count);
    	return 0;
	}else{
		//printf("ori is no vlan\n");
		return -1;
	}
	
}


int gtp_parse_dissector(const u_char *pktdata,cur_con_in_pcap **cur_con_in_p,long long count)
{
    MACHeader_t *eptr;
    _802_1Q_LAN_t *lan;
    IPHeader_t *ip_head;
    GTP_t *gtp_head;
    UDPHeader_t *udp;
    //eth
    int plus_offset = 0;
    cur_con_in_pcap *tmp_cur_ptr = *cur_con_in_p;
    eptr=(MACHeader_t*)(pktdata);
    plus_offset=sizeof(MACHeader_t);
two_vlan:
    if(ntohs(eptr->Type)==0x8100)
    {
        lan = (_802_1Q_LAN_t*)(pktdata+plus_offset);
        if(ntohs(lan->Type)==0x0800)
            plus_offset+=sizeof(_802_1Q_LAN_t);
        else if(ntohs(lan->Type)==0x8100)
        {
            plus_offset+=sizeof(_802_1Q_LAN_t);
            goto two_vlan;
        }
        else
        {
            //printf("LAN_PRO is not 0x0800 or 0x8100!\n");
            printf("vlan type:%.4x count:%lld\n",ntohs(lan->Type),count);
            return 0;
        }
    }
    else if(ntohs(eptr->Type)!=0x0800)
    {
        printf("Ether type:%.4x count:%lld\n",ntohs(eptr->Type),count);
        return 0;
    }
    //ip
    ip_head=(IPHeader_t*)(pktdata+plus_offset);
    sprintf(tmp_cur_ptr->sip.ip,"%d.%d.%d.%d",(unsigned char)ip_head->Source_IP[0],(unsigned char)ip_head->Source_IP[1],(unsigned char)ip_head->Source_IP[2],(unsigned char)ip_head->Source_IP[3]);
    sprintf(tmp_cur_ptr->con[HEAD].ip,"%d.%d.%d.%d",(unsigned char)ip_head->Destin_IP[0],(unsigned char)ip_head->Destin_IP[1],(unsigned char)ip_head->Destin_IP[2],(unsigned char)ip_head->Destin_IP[3]);
    plus_offset+=sizeof(IPHeader_t);
    //udp
    udp = (UDPHeader_t*)(pktdata+plus_offset);
    plus_offset+=sizeof(UDPHeader_t) +2;

    if((unsigned char)ip_head->Protocol_Type==17)
    {
        gtp_head=(GTP_t*)(pktdata+plus_offset);
        tmp_cur_ptr->Message_Type=(unsigned char)(gtp_head->Message_Type);
        search_pcap_by_con_in_head(gtp_head,cur_con_in_p);//head
        plus_offset+=sizeof(GTP_t)+4;
        //printf("sport:%x dport:%x\n",(unsigned short)ntohs(udp->Source_port),(unsigned short)ntohs(udp->Destin_port));
        if((unsigned short)ntohs(udp->Source_port) == 2123 || (unsigned short)ntohs(udp->Destin_port) == 2123)
        {
            search_pcap_by_con_in_data(pktdata,plus_offset,(unsigned short)ntohs(gtp_head->Len_Of_GTPData),cur_con_in_p);
        }
    }
    else
    {
        printf("ip type is not equal 17! ip protocol type: %d count:%lld\n",(unsigned char)ip_head->Protocol_Type,count);
    }
    return 0;
}
int store_con_init(save_CON **p2_store_con,CON_TEID_IP **p2_s_con,char* input_file,int T_P_FLAG)
{
    FILE *input;
    char ss[32];
    char ss_teid[12];
    char ss_ip[20];
    int init_count=2;
    int alloc_num = 3;
    int count = 0;
    uint64_t *p_s_imsi = NULL;
    uint64_t *p_s_msisdn = NULL;
    CON_TEID_IP *p_tmp = NULL;
    (*p2_store_con)->count = 0;
    (*p2_store_con)->sum_count = init_count;
    *p2_s_con = (CON_TEID_IP*)malloc(init_count*sizeof(CON_TEID_IP));
    p_s_imsi = (uint64_t*)malloc(init_count*sizeof(uint64_t));
    p_s_msisdn = (uint64_t*)malloc(init_count*sizeof(uint64_t));
    memset(*p2_s_con,0,sizeof(CON_TEID_IP)*init_count);
    memset(p_s_imsi,0,sizeof(uint64_t)*init_count);
    memset(p_s_msisdn,0,sizeof(uint64_t)*init_count);

    (*p2_store_con)->imsi = p_s_imsi;
    (*p2_store_con)->msisdn = p_s_msisdn;
    (*p2_store_con)->imsi_sum = 2;
    (*p2_store_con)->msisdn_sum = 2;

    if(T_P_FLAG == 0)
    {
        (*p2_store_con)->con = *p2_s_con;

        return 0;
    }
    if((input=fopen(input_file,"r"))==NULL)
    {
        printf("input error!\n");
    }
    while(fgets(ss,32,input)!=NULL)
    {
        count = (*p2_store_con)->count;
        sscanf(ss,"%[^ ] %[0-9|.]",ss_teid,ss_ip);
        sscanf(ss_teid,"%x",&((*p2_s_con)[count].teid));
        strcpy((*p2_s_con)[count].ip,ss_ip);
        (*p2_store_con)->count++;
        if((*p2_store_con)->count >= (*p2_store_con)->sum_count)
        {
            p_tmp = (CON_TEID_IP*)realloc((*p2_s_con),((*p2_store_con)->sum_count+alloc_num)*sizeof(CON_TEID_IP));
            if(p_tmp != NULL)
            {
                *p2_s_con = p_tmp;
                p_tmp = NULL;
            }
            else
            {
                printf("realloc failed!\n");
            }
            (*p2_store_con)->sum_count += alloc_num;
        }
    }
    fclose(input);
    PRINT_LINE("Load info");
    for(int i=0; i<(*p2_store_con)->count; i++)
    {
        printf("load con info[%d]: teid: %.4x ip:%s\n",i,(*p2_s_con)[i].teid,(*p2_s_con)[i].ip);
    }
    (*p2_store_con)->con = *p2_s_con;
    return 0;
}

int save_in_store_con(cur_con_in_pcap *cur_con_in_p,save_CON **p2_store_con)
{
    CON_TEID_IP *p_cur_con = cur_con_in_p->con;
    CON_TEID_IP *p_s_con = (*p2_store_con)->con;
    CON_TEID_IP *p_tmp = NULL;
    int cur_store_count = 0;
    for(int i = 0; i<MAX; i++)
    {
        if((p_cur_con[i].teid || ((FFLAG==0x1) && 0 != strlen(p_cur_con[i].ip)))&& 0 == CON_Is_Stored(p_cur_con[i], **p2_store_con))
        {
            cur_store_count = (*p2_store_con)->count;
            p_s_con[cur_store_count].teid = p_cur_con[i].teid ;
            strcpy(p_s_con[cur_store_count].ip,p_cur_con[i].ip);
            (*p2_store_con)->count ++;
            printf("save[%d] teid:%x ip:%s\n",cur_store_count,p_cur_con[i].teid,p_cur_con[i].ip);
        }

        if((*p2_store_con)->count+2 >= (*p2_store_con)->sum_count)
        {
            p_tmp = (CON_TEID_IP*)realloc(p_s_con,((*p2_store_con)->sum_count+3)*sizeof(CON_TEID_IP));
            if(p_tmp != NULL)
            {
                (*p2_store_con)->sum_count += 3;
                p_s_con = p_tmp;
                p_tmp = NULL;
            }
            else
            {
                printf("realloc failed!!!!!!\n");
            }
            (*p2_store_con)->con = p_s_con;
        }
    }
    return 0;
}

int pcap_cache_out(cur_con_in_pcap *cur_con_in_p,pcap_dumper_t **out_pfile,struct pcap_pkthdr *p_head,const u_char *pkt_data,save_CON **p2_store_con,singal_flag_t *p_singal_flag)
{

    CON_TEID_IP *p_cur_con = cur_con_in_p->con;
    if(p_singal_flag->IMSI == 1 && cur_con_in_p->IMSI && 0==strcmp((const char *)cur_con_in_p->IMSI,(const char*)p_singal_flag->IMSI_CATCH))
    {
        //catch imsi
        cur_con_in_p->flag = 1;
    }
    else if(p_singal_flag->MSISDN == 1 && cur_con_in_p->MSISDN && 0==strcmp((const char *)cur_con_in_p->MSISDN,(const char*)p_singal_flag->MSISDN_CATCH))
    {
        //catch msisdn
        cur_con_in_p->flag = 1;
    }
    else if(p_singal_flag->MESS_TYPE == 1 && cur_con_in_p->Message_Type && cur_con_in_p->Message_Type == p_singal_flag->MESS_TYPE_CATCH)
    {
        //catch message type
        cur_con_in_p->flag = 1;
    }
    /*如果开启了多种关联方式过滤，当且仅当该包没匹配中且存在imsi或msisdn时，对包的imsi和msisdn进行内存信息比对，若比对中则表示关联*/
    if(p_singal_flag->MUTI_CATCH == 1 && cur_con_in_p->flag == 0)
    {
        if(cur_con_in_p->flag == 0 && strlen((char *)cur_con_in_p->IMSI) != 0)
        {
            uint64_t imsi = 0;
            sscanf((char *)cur_con_in_p->IMSI,"%lu",&imsi);
            if(1 == IMSI_Is_Stored(imsi, **p2_store_con))
            {
                printf("imsi cached! %lu\n",imsi);
                cur_con_in_p->flag = 1;
            }
        }
        if(cur_con_in_p->flag == 0 && strlen((char *)cur_con_in_p->MSISDN) != 0)
        {
            uint64_t msisdn = 0;
            sscanf((char *)cur_con_in_p->MSISDN,"%lu",&msisdn);
            if(1 == MSISDN_Is_Stored(msisdn, **p2_store_con))
            {
                printf("msisdn cached! %lu\n",msisdn);
                cur_con_in_p->flag = 1;
            }
        }
    }
    /*如果过滤方式为加载输入文件内的teid+ip过滤，或者不为加载文件，但这个包没有匹配中，则采用teid+ip组合与内存中已存信息校验匹配*/
    if(p_singal_flag->T_IP_FLAG == 1 || (cur_con_in_p->flag == 0&& p_singal_flag->NOT == 0))
    {
        if(FFLAG == 0x1 && strlen(cur_con_in_p->sip.ip) != 0 && CON_Is_Stored(cur_con_in_p->sip, **p2_store_con))
        {
            cur_con_in_p->flag = 1;
        }
        else
        {
            for(int i = 0; i<MAX; i++)
            {
                if(p_cur_con[i].teid && CON_Is_Stored(p_cur_con[i], **p2_store_con))
                {
                    cur_con_in_p->flag = 1;
                }
            }
        }
    }
    /*若该pkt匹配成功，则保存包内的teid+ip信息，如果开启了多种方式关联，则把imsi和msisdn也保存*/
    if(1 == cur_con_in_p->flag)
    {
        save_in_store_con(cur_con_in_p,p2_store_con);
        if(p_singal_flag->MUTI_CATCH == 1)
        {
            if(strlen((char *)cur_con_in_p->IMSI) != 0)
            {
                uint64_t imsi = 0;
                sscanf((char *)cur_con_in_p->IMSI,"%lu",&imsi);
                save_imsi_in_store_con(imsi, p2_store_con);
            }
            if(strlen((char *)cur_con_in_p->MSISDN) != 0)
            {
                uint64_t msisdn = 0;
                sscanf((char *)cur_con_in_p->MSISDN,"%lu",&msisdn);
                save_msisdn_in_store_con(msisdn, p2_store_con);
            }
        }
        pcap_dump((u_char*)*out_pfile,p_head,pkt_data);
    }
    return 0;
}
int save_msisdn_in_store_con(uint64_t msisdn,save_CON **p2_store_con)
{
    uint64_t *p_msisdn = NULL;
    uint64_t *tmp_p_msisdn = NULL;
    p_msisdn = (*p2_store_con)->msisdn;
    if(msisdn && 0 == MSISDN_Is_Stored(msisdn, **p2_store_con))
    {
        p_msisdn[(*p2_store_con)->msisdn_count] = msisdn;
        (*p2_store_con)->msisdn_count++;
        printf("save [%d] msisdn:%lu\n",(*p2_store_con)->msisdn_count-1,p_msisdn[(*p2_store_con)->msisdn_count-1]);
        if(((*p2_store_con)->msisdn_count+2) >= (*p2_store_con)->msisdn_sum)
        {
            tmp_p_msisdn = (uint64_t*)realloc(p_msisdn,((*p2_store_con)->msisdn_sum+3)*sizeof(uint64_t));
            if(tmp_p_msisdn != NULL)
            {
                (*p2_store_con)->msisdn_sum+=3;
                p_msisdn = tmp_p_msisdn;
                tmp_p_msisdn = NULL;
            }
            else
            {
                printf("realloc msisdn failed!!!!!!\n");
            }
        }
    }
    (*p2_store_con)->msisdn = p_msisdn;
    return 0;
}

int save_imsi_in_store_con(uint64_t imsi,save_CON **p2_store_con)
{
    uint64_t *p_imsi = NULL;
    p_imsi = (*p2_store_con)->imsi;
    uint64_t *tmp_p_imsi = NULL;
    if(imsi && 0 == IMSI_Is_Stored(imsi, **p2_store_con))
    {
        p_imsi[(*p2_store_con)->imsi_count] = imsi;
        (*p2_store_con)->imsi_count++;
        printf("save [%d] imsi:%lu\n",(*p2_store_con)->imsi_count-1,p_imsi[(*p2_store_con)->imsi_count-1]);
        if(((*p2_store_con)->imsi_count+2) >= (*p2_store_con)->imsi_sum)
        {
            tmp_p_imsi = (uint64_t*)realloc(p_imsi,((*p2_store_con)->imsi_sum+3)*sizeof(uint64_t));
            if(tmp_p_imsi != NULL)
            {
                (*p2_store_con)->imsi_sum+=3;
                p_imsi = tmp_p_imsi;
                tmp_p_imsi = NULL;
            }
            else
            {
                printf("realloc imsi failed!!!!!!\n");
            }
        }
    }
    (*p2_store_con)->imsi = p_imsi;
    return 0;
}

void get_time(char *cur_time)
{
    time_t now;
    struct tm *tm_now;
    time(&now);
    tm_now = localtime(&now);
    //sprintf(cur_time,"%d:%d:%d:%d:%d:%d",tm_now->tm_year,tm_now->tm_mon,tm_now->tm_mday,tm_now->tm_hour,tm_now->tm_min,tm_now->tm_sec);
    strftime(cur_time,30,"%Y%m%d%H%M%S",tm_now);
}
int filter(char *catch_info_file,char *ori_pcap_file,singal_flag_t Flag)
{
    pcap_t *pfile;
    const u_char *pktdata=0;
    char errbuf[100];
    char outfile[200];
    char infile[200];
    char imsi_fname[100];
    char msisdn_fname[100];
    char con_fname[100];
    char tmp_line[100];
    struct pcap_pkthdr *p_head=0;
    cur_con_in_pcap cur_con_in_p;
    cur_con_in_pcap *ptr = &cur_con_in_p;
    long long count = 0;
    save_CON store_con;
    save_CON *p_store_con = NULL;
    CON_TEID_IP *p_s_con = NULL;
    uint64_t *p_s_imsi = NULL;
    uint64_t *p_s_msisdn = NULL;
    int i = 0;
    int circle_num = 0;
    int add_new_info_count;
    strcpy(infile,ori_pcap_file);
    char cur_time[30];
    get_time(cur_time);
    mkdir((const char *)cur_time,0777);
circle:
    p_store_con = &store_con;
    memset(p_store_con,0,sizeof(save_CON));
    if(Flag.CIR_SIGNAL == 1 && Flag.CIR_SIGNAL_START == 1)
    {
        store_con_init(&p_store_con, &p_s_con,catch_info_file,0);
        if(Flag.T_IP_FLAG==0)
        {
            Flag.NUM = 1;
        }
        FILE *catch_fp;
        char fname[100];
        if(Flag.T_IP_FLAG==0)
        {
            //strcpy(fname,imsi_fname);
            sprintf(fname,"%s",imsi_fname);

        }
        else
        {
            strcpy(fname,catch_info_file);
            //sprintf(fname,"%s/%s",cur_time,imsi_fname);
        }
        //printf("fname:%s\n",fname);
        if((catch_fp=fopen(fname,"r"))==NULL)
        {
            printf("%s open error1\n",fname);
        }
        if((Flag.T_IP_FLAG==0 && fgets_line(tmp_line,16,catch_fp,Flag.CIR_SIGNAL_LINE)==1)&&strlen(tmp_line)>1)
        {
            /*若T_IP_FLAG为0，则表示用户是按imsi，msisdn或者message type过滤，此时通过imsi用户分流*/
            sscanf(tmp_line,"%lu",&(store_con.imsi[0]));
            store_con.imsi_count = 1;
            sprintf(Flag.CATCH_INFO,"%lu",store_con.imsi[0]);
            sprintf(Flag.IMSI_CATCH,"%lu",store_con.imsi[0]);
            Flag.IMSI = 1;
            PRINT_LINE("CIR_SIGNAL_LINE:%d(%s)",Flag.CIR_SIGNAL_LINE,Flag.IMSI_CATCH);
            Flag.CIR_SIGNAL_LINE++;
        }
        else if((Flag.T_IP_FLAG != 0 && fgets_line(tmp_line,32,catch_fp,Flag.CIR_SIGNAL_LINE)==1)&&strlen(tmp_line)>1)
        {
            /*若T_IP_FLAG为1，则表示是通过teid+ip模式加载input.txt过滤的，则通过teid+ip进行分流*/
            char ss_teid[12];
            char ss_ip[20];
            sscanf(tmp_line,"%[^ ] %[0-9|.]",ss_teid,ss_ip);
            sscanf(ss_teid,"%x",&(store_con.con[0].teid));
            strcpy(store_con.con[0].ip,ss_ip);
            store_con.count = 1;
            if(FFLAG == 0x11)
            {
                sprintf(Flag.CATCH_INFO,"%s_%s",ss_teid,ss_ip);
            }
            else if(FFLAG == 0x10)
            {
                strcpy(Flag.CATCH_INFO,ss_teid);
            }
            else if(FFLAG == 0x1)
            {
                strcpy(Flag.CATCH_INFO,ss_ip);
            }
            PRINT_LINE("CIR_SIGNAL_LINE:%d(0x%.4x  %s)",Flag.CIR_SIGNAL_LINE,store_con.con[0].teid,store_con.con[0].ip);
            Flag.CIR_SIGNAL_LINE++;
        }
        else if(fgets_line(tmp_line,16,catch_fp,Flag.CIR_SIGNAL_LINE)==0 || strlen(tmp_line)<=1)
        {
            //printf("tmp_line:%s\n",tmp_line);
            p_s_con = store_con.con;
            p_s_imsi = store_con.imsi;
            p_s_msisdn = store_con.msisdn;
            free(p_s_con);
            free(p_s_imsi);
            free(p_s_msisdn);
            fclose(catch_fp);
            printf("result_dir:%s\n",cur_time);
            return 0;
        }
        fclose(catch_fp);
    }
    else
    {
        store_con_init(&p_store_con, &p_s_con,catch_info_file,Flag.T_IP_FLAG);
    }
    circle_num = 0;
    while(circle_num < Flag.NUM)
    {
        count = 0;
        circle_num++;
        pfile=pcap_open_offline(infile,errbuf);
        //sprintf(outfile,"out_%s_%d_%s",Flag.CATCH_INFO,circle_num,infile);
        sprintf(outfile,"%s/out_%s_%s",cur_time,Flag.CATCH_INFO,ori_pcap_file);
        printf("Output pcap file name :%s\n",outfile);
        if(NULL==pfile)
        {
            printf("%s\n",errbuf);
            return -1;
        }
        pcap_dumper_t *out_pfile=pcap_dump_open(pfile,outfile);
        if(out_pfile==NULL)
        {
            printf("open outfile failed!\n");
        }
        add_new_info_count = store_con.count +store_con.msisdn_count+store_con.imsi_count;
        //printf("before info_count:%d\n",add_new_info_count);
        while(pcap_next_ex(pfile,&p_head,&pktdata)==1)
        {
            count++;
            memset(&cur_con_in_p,0,sizeof(cur_con_in_pcap));
            gtp_parse_dissector(pktdata,&ptr,count);
            pcap_cache_out(&cur_con_in_p,&out_pfile,p_head,pktdata,&p_store_con,&Flag);
            //printf("---------------------------------------------cur_count = %lld\n",count);
            if(cur_con_in_p.flag == 1)
            {
                //printf_cur_con(&cur_con_in_p);
                //printf("============================================================cache_count = %lld\n",count);
            }
        }
        pcap_close(pfile);
        pcap_dump_close(out_pfile);
        //printf("after info_count:%d\n",store_con.count +store_con.msisdn_count+store_con.imsi_count);
        add_new_info_count = store_con.count +store_con.msisdn_count+store_con.imsi_count - add_new_info_count;
        printf("after add_count:%d\n",add_new_info_count);
        if(add_new_info_count == 0)
            break;
    }
    for( i=0; i<store_con.count; i++)
    {
        printf("load con info[%d]: teid: %.4x ip:%s\n",i,store_con.con[i].teid,store_con.con[i].ip);
    }
    //中途realloc后，指针可能已经变化了，这个时候需要重新取一遍store里的指针，然后再free，否则会出错
    p_s_con = store_con.con;
    p_s_imsi = store_con.imsi;
    p_s_msisdn = store_con.msisdn;
    if(Flag.CIR_SIGNAL_START == 0)
    {
        output_search_info(store_con,imsi_fname,msisdn_fname,con_fname,(char *)Flag.CATCH_INFO,cur_time);
    }
    //printf("imsi_name:%s msisdn_name:%s con_name:%s\n",imsi_fname,msisdn_fname,con_fname);
    free(p_s_con);
    free(p_s_imsi);
    free(p_s_msisdn);

    /*需要对输出的大文件outfile拆分成小文件，需要拆分时，请开启MUTI_CATCH选项*/
    if(Flag.CIR_SIGNAL == 1)
    {
        Flag.CIR_SIGNAL_START = 1;
        Flag.NOT = 0;
        Flag.MUTI_CATCH = 1;
        if(Flag.CIR_SIGNAL_LINE == 0)
        {
            sprintf(infile,"%s/out_%s_%s",cur_time, Flag.CATCH_INFO,ori_pcap_file);
            printf("part input_pcap_file:%s\n",infile);
        }
        goto circle;
    }
    else
    {
        printf("return\n");
    }
    printf("result_dir:%s\n",cur_time);
    return 0;
}


int cut(char *input_pcap_file,char *start_num,char *plus_num,char *output_pcap_file)
{
    char errbuf[100];
    void print_hex(char *,int);
    struct pcap_pkthdr *p_head=0;
    const u_char *pktdata=0;
    char outfile[100];
    int count=0;
    int cached=0;
    pcap_t *pfile=pcap_open_offline(input_pcap_file,errbuf);
    if(NULL==pfile)
    {
        printf("%s\n",errbuf);
        return -1;
    }
    int num1 = atoi(start_num);
    int num2 = atoi(plus_num);
    sprintf(outfile,"%s",output_pcap_file);
    pcap_dumper_t *out_pfile=pcap_dump_open(pfile,outfile);
    if(out_pfile==NULL)
    {
        printf("open outfile failed!\n");
    }
    while(pcap_next_ex(pfile,&p_head,&pktdata)==1)
    {
        count++;
        if(count>=num1)
        {
            cached++;
            pcap_dump((u_char*)out_pfile,p_head,pktdata);
            if(cached>=num2)
            {
                break;
            }
        }

    }
    pcap_close(pfile);
    pcap_dump_close(out_pfile);
    return 0;
}
void print_pkt_info(gtpv2_pcap_info pkt_info)
{
    printf("modify_pkt.index = %d\n",pkt_info.count);
    printf("msg_type = %d\n",pkt_info.msg_type);
    printf("imsi = %lx\n",pkt_info.imsi);
    printf("imei = %lx\n",pkt_info.imei);
    printf("msisdn = %lx\n",pkt_info.msisdn);
    printf("plmnid = %d \n",pkt_info.plmnid);
    printf("tac = %x\n",pkt_info.tac);
    printf("ci = %x\n",pkt_info.ci);
    for(int i = 0; i<MAX; i++)
    {
        if(pkt_info.tunnel[i].teid)
        {
            printf("tunnel[%s].teid = %x\n",str_type[i],pkt_info.tunnel[i].teid);
        }
        if(pkt_info.tunnel[i].ip.addr)
        {
            printf("tunnel[%s].ip = %x (%d.%d.%d.%d) \n",str_type[i],pkt_info.tunnel[i].ip.addr,pkt_info.tunnel[i].ip.b[0],pkt_info.tunnel[i].ip.b[1],pkt_info.tunnel[i].ip.b[2],pkt_info.tunnel[i].ip.b[3]);
        }
    }
}
int modify(char *input_pcap_file,char *modify_file)
{
    PRINT_LINE("MODIFY");
    gtpv2_pcap_info pkt_info;
    int count = 0,catch_index = 0;
    char errbuf[100];
    struct pcap_pkthdr *p_head=0;
    const u_char *pktdata=0;
    memset(&pkt_info,0,sizeof(gtpv2_pcap_info));
    read_modify_file(&pkt_info,modify_file,catch_index);
    print_pkt_info(pkt_info);
    char out_pcap_file[100];
    pcap_t *pfile=pcap_open_offline(input_pcap_file,errbuf);
    if(NULL==pfile)
    {
        printf("%s\n",errbuf);
        return -1;
    }
    sprintf(out_pcap_file,"modify_%s",input_pcap_file);
    pcap_dumper_t *out_pfile=pcap_dump_open(pfile,out_pcap_file);
    if(out_pfile==NULL)
    {
        printf("open outfile failed!\n");
    }
    while(pcap_next_ex(pfile,&p_head,&pktdata)==1)
    {
        count++;
        if(count == pkt_info.count)
        {

            gtp_parse_modify(pktdata,pkt_info,count);
        }
        pcap_dump((u_char*)out_pfile,p_head,pktdata);
    }
    pcap_close(pfile);
    pcap_dump_close(out_pfile);
    return 0;
}
int cdr_add_vlan(char *input_pcap_file)
{
    PRINT_LINE("5g_cdr_add_VLAN");
    gtpv2_pcap_info pkt_info;
    char errbuf[100];
	long long count = 0;
	int vlan_count = 0;
    struct pcap_pkthdr *p_head=0;
    const u_char *pktdata=0;
	char *pcap_out = NULL;;
    memset(&pkt_info,0,sizeof(gtpv2_pcap_info));
    //print_pkt_info(pkt_info);
    char out_pcap_file[100];
    pcap_t *pfile=pcap_open_offline(input_pcap_file,errbuf);
    if(NULL==pfile)
    {
        printf("%s\n",errbuf);
        return -1;
    }
    sprintf(out_pcap_file,"add_vlan_%s",input_pcap_file);
    pcap_dumper_t *out_pfile=pcap_dump_open(pfile,out_pcap_file);
    if(out_pfile==NULL)
    {
        printf("open outfile failed!\n");
    }
    while(pcap_next_ex(pfile,&p_head,&pktdata)==1)
    {
    	vlan_count = 0;
    	//printf("cap_len:%d len:%d\n",p_head->caplen,p_head->len);
        _5g_cdr_add_vlan(pktdata,&pcap_out,&vlan_count,&p_head);
		if(count%10000==0){
			printf("===========================count:%lld\n",count);
		}
		count++;
        pcap_dump((u_char*)out_pfile,p_head,(const u_char*)pcap_out);
		//printf("vlan_count = %d\n",vlan_count);
		free(pcap_out);
		pcap_out= NULL;
    }
    pcap_close(pfile);
    pcap_dump_close(out_pfile);
    return 0;
}

int del_vlan(char *input_pcap_file)
{
    PRINT_LINE("NO_VLAN");
    gtpv2_pcap_info pkt_info;
    char errbuf[100];
	long long count = 0;
	int vlan_count = 0;
    struct pcap_pkthdr *p_head=0;
    const u_char *pktdata=0;
	char *pcap_out = NULL;;
    memset(&pkt_info,0,sizeof(gtpv2_pcap_info));
    //print_pkt_info(pkt_info);
    char out_pcap_file[100];
    pcap_t *pfile=pcap_open_offline(input_pcap_file,errbuf);
    if(NULL==pfile)
    {
        printf("%s\n",errbuf);
        return -1;
    }
    sprintf(out_pcap_file,"no_vlan_%s",input_pcap_file);
    pcap_dumper_t *out_pfile=pcap_dump_open(pfile,out_pcap_file);
    if(out_pfile==NULL)
    {
        printf("open outfile failed!\n");
    }
    while(pcap_next_ex(pfile,&p_head,&pktdata)==1)
    {
    	vlan_count = 0;
    	//printf("cap_len:%d len:%d\n",p_head->caplen,p_head->len);
        int ret = gtp_parse_no_vlan(pktdata,&pcap_out,&vlan_count,&p_head);
		if(count%10000==0){
			printf("===========================count:%lld\n",count);
		}
		count++;
		if(ret == -1){
			pcap_dump((u_char*)out_pfile,p_head,pktdata);
			continue;
		}
		if(vlan_count>0){
			//printf("vlan_count = %d\n",vlan_count);
			//p_head->caplen=p_head->caplen- 4*vlan_count;
			//p_head->len= p_head->len-4*vlan_count;
			//printf("modify cap_len:%d len:%d\n",p_head->caplen,p_head->len);
		}
        pcap_dump((u_char*)out_pfile,p_head,(const u_char*)pcap_out);
		//printf("vlan_count = %d\n",vlan_count);
		free(pcap_out);
		pcap_out= NULL;
    }
    pcap_close(pfile);
    pcap_dump_close(out_pfile);
    return 0;
}

int read_modify_file(gtpv2_pcap_info *p_pkt_info,char *modify_file,int index)
{
    FILE *modify_fp;
    char tmp_line[128];
    char op[16];
    char is_equal[5];
    char count[8];
    char value[100];
    int m_count = 0;
    if((modify_fp=fopen(modify_file,"a+"))==NULL)
    {
        printf("%s open error1\n",modify_file);
    }
    printf("m_count %d index:%d\n",m_count,index);
    printf("modify_file:%s\n",modify_file);
    while(fgets(tmp_line,64,modify_fp)!=NULL)
    {
        //printf("m_count %d index:%d\n",m_count,index);
        if(tmp_line[0] == '[' )
        {
            sscanf(tmp_line,"%*[^a-z]%[a-z|.]",op);
            //printf("op:%s\n",op);
            if(strcmp(op,"modify.pkt") == 0 && m_count == index)
            {
                sscanf(tmp_line,"%*[^a-z]%[a-z|.]%[ *= *]%[0-9]",op,is_equal,count);
                sscanf(is_equal,"%*[ *]%[=]",is_equal);
                int len = strlen(count);
                printf("isequal:%s count:%s strlen(count):%d\n",is_equal,count,len);
                if(is_equal[0] == '=')
                {
                    //count[len] = '\0';
                    p_pkt_info->count = atoi(count);
                    printf("count:%d\n",p_pkt_info->count);
                }

            }
            else if(strcmp(op,"end") == 0)
            {
                if(m_count == index)
                {
                    printf("get modify info end\n");
                    return 1;
                }
                m_count++;
            }
        }
        else if(m_count == index)
        {
            sscanf(tmp_line,"%[a-z|.|_|0-9]%[ *= *]%s",op,is_equal,value);
            sscanf(is_equal,"%*[ *]%[=]",is_equal);
            //printf("op: %s\n",op);
            if(is_equal[0] == '=')
            {
                if(strcmp(op,"msg_type")==0)
                {
                    p_pkt_info->msg_type = atoi(value);
                    //printf("value:%s\n",value);
                }
                else if(strcmp(op,"imsi")==0)
                {
                    sscanf(value,"%lx",&(p_pkt_info->imsi));
                }
                else if(strcmp(op,"imei")==0)
                {
                    sscanf(value,"%lx",&(p_pkt_info->imei));
                }
                else if(strcmp(op,"msisdn")==0)
                {
                    sscanf(value,"%lx",&(p_pkt_info->msisdn));
                }
                else if(strcmp(op,"s5_sgw_c.ip")==0)
                {
                    char ip[4][4];
                    sscanf(value,"%[0-9]%*[.]%[0-9]%*[.]%[0-9]%*[.]%[0-9]",ip[0],ip[1],ip[2],ip[3]);
                    for(int i = 0; i<4; i++)
                    {
                        p_pkt_info->tunnel[S5_SGW].ip.b[i] = atoi(ip[i]);
                    }
                    //printf("sgw_c.ip:%d.%d.%d.%d\n",p_pkt_info->tunnel[S5_SGW].ip.b[0],p_pkt_info->tunnel[S5_SGW].ip.b[1],p_pkt_info->tunnel[S5_SGW].ip.b[2],p_pkt_info->tunnel[S5_SGW].ip.b[3]);
                }
                else if(strcmp(op,"s5_sgw_c.teid")==0)
                {
                    sscanf(value,"%xu",&(p_pkt_info->tunnel[S5_SGW].teid));
                }
                else if(strcmp(op,"tac")==0)
                {
                    sscanf(value,"%xu",&(p_pkt_info->tac));
                }
                else if(strcmp(op,"ci")==0)
                {
                    sscanf(value,"%xu",&(p_pkt_info->ci));
                }
                else if(strcmp(op,"plmnid")==0)
                {
                    sscanf(value,"%u",&(p_pkt_info->plmnid));
                }
            }
        }

    }
    fclose(modify_fp);
    return 0;
}
