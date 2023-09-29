#include <windows.h>
#include <fltuser.h>
#include <stdio.h>
#include <vector>
#include <algorithm>
#include <string>
#include <iostream>
#include <chrono>
#include <inttypes.h>
#include <stdint.h>

// Structs de recebimento de notificações
typedef struct _FsMiniFilterNotificationStruct {
	ULONG PID;
	WCHAR FileName[260];
} FsMiniFilterNotificationStruct, * PFsMiniFilterNotificationStruct;

typedef struct _FsMiniFilterMessageStruct {
	FILTER_MESSAGE_HEADER MessageHeader;
	FsMiniFilterNotificationStruct FsMiniFilterNotification;
} FsMiniFilterMessageStruct, * PFsMiniFilterMessageStruct;

typedef struct _Information {
	ULONG PID = 0;
	
	std::vector<std::wstring> Files;
	std::vector<uint64_t> TimeStamps;
} Information;

/* Funções utilitárias */

// Responsável por verificar se na lista "infos" há um item com o atributo "PID" igual ao argumento "pid".
int checkPid(std::vector<Information> infos, ULONG pid) {
	for (int i = 0; i < infos.size(); ++i) {
		if (infos[i].PID == pid) return i;
	}

	return -1;
}

// Checa se dentro dos arquivos atualizados por aquele processo já existe o arquivo com caminho igual ao argumento "fileName".
bool alreadyExists(Information info, std::wstring fileName) {
	for (int i = 0; i < info.Files.size(); ++i) {
		if (info.Files[i] == fileName) return true;
	}

	return false;
}

// Verifica se uma dada string termina com uma certa substring.
bool endsWith(std::wstring fullString, std::wstring ending) {
	if (fullString.length() >= ending.length()) {
		return (fullString.compare(fullString.length() - ending.length(), ending.length(), ending) == 0);
	}
	else {
		return false;
	}
}


// Verifica se o arquivo tem uma extensão "especial".
bool verify_common_exts(std::wstring filename) {
	std::vector<std::wstring> exts = { L".pdf", L".doc", L".docx", L".csv", L".xml", L".txt", L".jpg", L".jpeg", L".png", L".xls", L".xlsx", L".pptx", L".cookie", L".key", L".rsa", L".mp3", L".conf", L".json", L".sys", L".log", L".dll", L".dat", L".lnk", L".chk" , L".pma" , L".db" , L".db-wal" , L".reg" };
	for (int i = 0; i < exts.size(); ++i) {
		if (endsWith(filename, exts[i]))
			return true;
	}

	return false;
}

bool verify_bad_exts(std::wstring filename) {
	std::vector<std::wstring> exts = { L".WNGRYPT" };
	for (int i = 0; i < exts.size(); ++i) {
		if (endsWith(filename, exts[i]))
			return true;
	}
	return false;
}

// Função responsável por análisar uma informação e dizer se o processo referente é ou não um ransomware.
bool checkForRansomware(Information info) {
	// File update rate
	// File extensions (.pdf, .csv, .doc and other personal files have more credit than .tmp files)
	// Content to write entropy (not ready yet) > 0.3, verify entropy in the string.
	if (std::any_of(info.Files.begin(), info.Files.end(), verify_bad_exts)) {
		return true;
	}

	if (std::any_of(info.Files.begin(), info.Files.end(), verify_common_exts) && info.Files.size() > 3) {
		// calculando frequência 
		std::vector<uint64_t> vars = {};
		
		// Duvida: Pode dar conflito? Pois as listas podem acabar sendo modificadas, ou foi feito uma cópia?
		for (int i = 1; i < info.Files.size(); ++i) {
			vars.push_back(info.TimeStamps[i] - info.TimeStamps[i - 1]);
		}

		unsigned long long ms = 0;
		for (int i = 0; i < vars.size(); ++i) {
			ms += vars[i];
		}

		if (ms == 0) return false;
		long double f = 1.0 / ms;
		
		printf("frêquencia: %Lf\n", f);
		return (f) > 0.03;
	}

	return false;
}

// Função responsável por matar o processo do ransomware.
void killRansomware(ULONG pid) {
	const auto explorer = OpenProcess(PROCESS_TERMINATE, false, pid);
	TerminateProcess(explorer, 1);
	CloseHandle(explorer);

	wprintf(L"Killed %lu.\n", pid);
}

// Função main
int main(void) {
	HRESULT r = S_OK;
	HANDLE port;

	// Vetor com todos os dados enviados pelo mini-filter.
	std::vector<Information> info;

	// Começando a comunicação com o mini-filter por meio de uma CommunicationPort.
	printf("Iniciando conexão com o mini-filter...\n");
	r = FilterConnectCommunicationPort(L"\\FsMiniFilterCommunicationPort", 0, NULL, 0, NULL, &port);

	// Aguardando até que a comunicação seja iniciada ou que o número de tentativas limite seja excedido.
	for (int attempt = 1; r != S_OK; ++attempt) {
		if (attempt == 10) {
			printf("O número de tentativas de conexão foi excedido. Finalizando o programa.\n");
			return 1;
		}

		printf("Falha ao se comunicar com o mini-filter. Tentando novamente (%d)...\n", attempt);

		r = FilterConnectCommunicationPort(L"\\FsMiniFilterCommunicationPort", 0, NULL, 0, NULL, &port);
		Sleep(2 * 1000);
	}

	printf("Conexão iniciada com sucesso. Iniciando recebimento de dados... \n");

	// Recebendo notificações
	while (1) {
		// Alocando memória
		PFsMiniFilterMessageStruct data = static_cast<PFsMiniFilterMessageStruct>(HeapAlloc(GetProcessHeap(), 0, sizeof(FsMiniFilterMessageStruct)));
		
		// Recebendo uma notificação
		r = FilterGetMessage(port, &data->MessageHeader, sizeof(FsMiniFilterMessageStruct), NULL);

		if (r == S_OK) {
			wprintf(L"Mensagem recebida com sucesso. PID: %lu. Caminho: %s\n", data->FsMiniFilterNotification.PID, data->FsMiniFilterNotification.FileName);
			
			// Salva novas informações ou atualiza informações de um processo já existente.
			int index = checkPid(info, data->FsMiniFilterNotification.PID);
			uint64_t timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			printf("timestamp: %I64u\n", timestamp);
			
			if (index > -1) {
				if (!alreadyExists(info[index], data->FsMiniFilterNotification.FileName)) {
					info[index].Files.push_back(data->FsMiniFilterNotification.FileName);
					info[index].TimeStamps.push_back(timestamp);
				}

				// Verificação de possíveis ransomwares.
				int pid = info[index].PID;
				if (checkForRansomware(info[index])) {
					info.erase(info.begin() + index); 
					killRansomware(pid);
				}
			}
			else {
				Information i;

				i.PID = data->FsMiniFilterNotification.PID;
				i.Files.push_back(data->FsMiniFilterNotification.FileName);
				i.TimeStamps.push_back(timestamp);

				info.push_back(i);
			}
		}

		// Liberando memória alocada.
		HeapFree(GetProcessHeap(), 0, data);
	}

	Sleep(10000);

	// Finalizando conexão.
	FilterClose(port);
	return 0;
}