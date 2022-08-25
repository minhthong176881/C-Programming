#include <signal.h>
#include <stdio.h>

#include "helper.h"

char* signal_name(int signal)
{
	switch (signal)
	{
	case SIGINT:
		return "SIGINT";
	case SIGTERM:
		return "SIGTERM";
	case SIGABRT:
		return "SIGABRT";
	default:
		return "Unknown";
	}

	return "Unknown";
}

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM || signal == SIGABRT) {
		printf("Detect %s signal. Stop capturing!\n", signal_name(signal));

		// if (adhandle1)
		// 	pcap_breakloop(adhandle1);
	}

	return;
}