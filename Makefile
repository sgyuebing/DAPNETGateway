CC      = cc
CXX     ?= c++
CFLAGS  ?= -g -O2 -Wall -Wextra -Wno-unused-parameter -Wformat=2 -DHAVE_LOG_H -std=c++11 -pthread
CPPFLAGS = -MMD -MP		# ★ 新增：头文件改动触发重编（原来改 .h 必须 make clean）
LIBS    = -lm -lpthread
LDFLAGS = -g

OBJECTS = Version.o Conf.o DAPNETGateway.o DAPNETNetwork.o Log.o POCSAGMessage.o POCSAGNetwork.o StopWatch.o TCPSocket.o Thread.o Timer.o UDPSocket.o Utils.o REGEX.o

all:		DAPNETGateway

DAPNETGateway:	$(OBJECTS)
		$(CXX) $(LDFLAGS) $(OBJECTS) $(CFLAGS) $(LIBS) -o DAPNETGateway

%.o: %.cpp
		$(CXX) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

-include $(OBJECTS:.o=.d)

install:
		install -m 755 DAPNETGateway /usr/local/bin/

clean:
		$(RM) DAPNETGateway *.o *.d *.bak *~

re: clean all
