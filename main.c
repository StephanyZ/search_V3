/*************************************************************************
	> File Name: main.c
	> Author:xfzhang
	> Mail:923036400@qq.com
	> Created Time: 2018年08月03日 星期五 11时27分47秒
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
int g_debug = 1;
int FFLAG = 0x11;

int main(int argc,char *argv[])
{
    singal_flag_t Flag;
    memset(&Flag,0,sizeof(singal_flag_t));
    int ret =  set_filter_flag(argv[1],argv[3],argv[4],&Flag);
    switch(ret)
    {
    case HELP:
        cat_usage();
        break;
    case SEARCH:
        filter(argv[4],argv[2],Flag);
        break;
    case CUT:
        cut(argv[2],argv[3],argv[4],argv[5]);
        break;
    case CREATE:
        break;
    case MODIFY:
        modify(argv[2],argv[3]);
        break;
	case DEL_VLAN:
		del_vlan(argv[2]);
		break;
	case ADD_VLAN:
		cdr_add_vlan(argv[2]);
		break;
    default:
        break;
    }
    return 0;
}



