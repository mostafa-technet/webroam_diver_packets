// webroam_diver_packets.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <Shlwapi.h>
#include "windivert.h"
#define MAXBUF 1024

#pragma comment (lib, "Shlwapi.lib")


void
print_hex_ascii_line(const u_char *payload, int len, int offset, char* output)
{

	int i, p = 0;
	//int gap;
	const u_char *ch;

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
		{
			p += sprintf_s(output + p, 1024, "%c", *ch);

		}
		else
			 p += sprintf_s(output + p, 1024, ".");
		ch++;
	}

	p+= sprintf_s(output+p, 1024, "\n");

	return;
}
BOOL isinfile(char* warg)
{
	char buf[1024];
	FILE *file;
	fopen_s(&file, ".\\blockedsites.txt", "r+t");
	while (fgets(buf, 1024, file) != NULL)
	{
		if (strlen(buf)>1 && isprint(buf[0])&&StrStrIA(buf, warg) != NULL)
		{
			fclose(file);
			return buf[0] == '.' ? TRUE : StrCmpNIA(buf, warg, strlen(warg));
		}
	}
fclose(file);
return FALSE;
}
typedef struct config
{
	HANDLE handle;
} Config, *PConfig;
void process(void* arg);

int main()
{
	HANDLE handle;// , thread;          // WinDivert handle
	wchar_t curD[1024] = { 0 };
	system("REG.exe ADD HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\ /v maxcacheTTL /t REG_DWORD /d 0 /f");
	//GetCurrentDirectoryW(1024, curD);
	///SetCurrentDirectoryW(curD);
	// Open some filter
	handle = WinDivertOpen("outbound and udp.DstPort == 53 or inbound and udp.DstPort = 53", WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		printf("%d\n", GetLastError());
		// Handle error
		exit(1);
	}
	Config c = {handle};
	/*for (int i = 0; i < 2; i++)
	{
		thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)process,
			(LPVOID)&c, 0, NULL);
		if (thread == NULL)
		{
			fprintf(stderr, "error: failed to start passthru thread (%d)\n",
				GetLastError());
			exit(EXIT_FAILURE);
		}
	}*/
	process(&c);
    return 0;
}

void process(void* arg)
{
	WINDIVERT_ADDRESS addr; // Packet address
	char packet[MAXBUF];    // Packet buffer
	UINT packetLen;
	PWINDIVERT_IPHDR ip_header;
	PVOID payload;
	UINT payload_len;
	PWINDIVERT_UDPHDR udp_header;
	
	char *buf = (char*)malloc(1024), *cmd = (char*)malloc(1024);
	PConfig config = (PConfig)arg;
	FILE * fl;
	// Main capture-modify-inject loop:
	while (TRUE)
	{
		if (!WinDivertRecv(config->handle, packet, sizeof(packet), &packetLen, &addr))
		{
			// Handle recv error
			printf("%d\n", GetLastError());
			continue;
		}

		WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL,
			NULL, NULL, NULL, NULL, &udp_header, &payload, &payload_len,
			NULL, NULL);
		char* str = (char*)malloc(payload_len+1);
		strncpy_s(str, payload_len, (char*)&payload, payload_len);
		str[payload_len] = '\0';
		//puts("1\n");
		if (ip_header == NULL || udp_header == NULL || payload == NULL)
		{
			// Packet does not match the blacklist; simply reinject it.
			/*if (!WinDivertSend(handle, packet, packetLen, NULL, &addr))
			{
			fprintf(stderr, "warning: failed to reinject packet (%d)\n",
			GetLastError());
			}*/
			free(str);
			continue;
		}
		//puts("2\n");
		// Modify packet.
		print_hex_ascii_line((const u_char *)payload, payload_len, 0, str);
		
		if (isinfile(str))
		{
			//puts(str);
			int i;
			char* ch = (char*)payload;
			for (i = 0; i < packetLen - 8; i++) {
				if (isprint(*ch))
				{
					*ch = 'b';
				}
				ch++;
			}
		}
		/*
		char* sp, * s2;
	//	printf("%s\n",payload);
		while ((sp = strstr(str, "..")) != NULL)
		{
			*sp = ' ';
			sp[1] = ' ';
		}
		while ((sp = strstr(str, " .")) != NULL)
		{
			sp[1] = ' ';
		}
		sp = str + 2;
		int c = 0;
		for (; c<1024; ++c)
		{
			if (sp[c] != ' ')
				break;
		}
		sp += c;
		s2 = strstr(sp, " ");
		*s2 = '\0';
		
		if (isinfile(s2))
		{
			int i;
			char* ch = (char*)payload;
			for (i = 0; i < packetLen - 8; i++) {
				if (isprint(*ch))
				{
					*ch = 'b';
				}
				ch++;
			}*/
			//print_hex_ascii_line((const u_char *)payload, payload_len, 0, str);
			//printf("%s\n",str);
			/*puts("3\n");
			WinDivertHelperCalcChecksums(packet, packetLen, &addr, WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM | WINDIVERT_HELPER_NO_TCP_CHECKSUM);*/
			//puts("4\n");
			if (!WinDivertSend(config->handle, packet, packetLen, NULL, &addr))
			{
				// Handle send error

				printf("Error!\n");
				free(str);
				continue;
			}
			free(str);
		}
	
}