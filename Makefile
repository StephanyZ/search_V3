#$@ 表示目标文件
#$^ 表示所有的依赖文件
#$< 表示第一个依赖文件
#$? 表示比目标还要新的依赖文件列表
#widcard :扩展通配符
#notdir: 去除路径
#patsubst: 替换通配符

TARGET := search_pcap
CC 	:= gcc 
CFLAG 	:= -g -std=c99 -Wall -D_GUN_SOURCE 
INCLUDE =
LIBS = -lpcap
SRCS := $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(notdir $(SRCS))) 
$(TARGET):$(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS)

%.o : %.c %.h 
	$(CC) $(CFLAG) -c $(INCLUDE) $< -o $@ $(LIBS)

clean:
	rm -rf *.o search_pcap
