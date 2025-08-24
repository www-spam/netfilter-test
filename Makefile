# Makefile for netfilter-test
CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lnetfilter_queue -lnfnetlink
TARGET = netfilter-test
SOURCES = netfilter-test.c
HEADERS = libnetfilter_queue.h

# 기본 타겟 - 빌드 후 iptables 설정
all: $(TARGET) setup-iptables

# 실행 파일 생성
$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

# 정리 - iptables 정리 후 파일 삭제
clean: cleanup-iptables
	rm -f $(TARGET)

# 설치 (선택사항)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

# 테스트용 iptables 규칙 설정
setup-iptables:
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0
	@echo "iptables rules configured."

# iptables 규칙 제거
cleanup-iptables:
	sudo iptables -F
	@echo "iptables rules cleared."

.PHONY: all clean install setup-iptables cleanup-iptables
