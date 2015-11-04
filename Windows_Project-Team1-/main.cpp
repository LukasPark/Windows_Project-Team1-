#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <algorithm>
#include <list>

#include "patterns.h"
using namespace std;
#pragma warning(disable:4996)

#define MAX_PATTERN_NUM 100


void getPatterns(_Out_ PATTERNS* pattern_list);
bool findPatterns(_In_ DWORD_PTR baseAdress, _In_ DWORD pID, _In_ PATTERNS* pattern_list, _In_ wchar_t* procName);
list<FOUND_PATTERN>* findPatternsDetail(_In_ UCHAR* buf, _In_ int buf_size, _In_ PATTERNS* pattern_list, _In_ int pattern_type);
void logFoundList(_In_ list<FOUND_PATTERN>* found_list, _In_ wchar_t* procName, const char* location);
int section_name(const char* section_name);

DWORD_PTR getBaseAddress(_In_ DWORD pID);
bool setPrivilege(_In_z_ const wchar_t* privilege, _In_ bool enable);

void freePatterns(_Out_ PATTERNS* pattern_list);

int _tmain(int argc, TCHAR* argv[]){
	PATTERNS* pattern_list = (PATTERNS*)malloc(sizeof(PATTERNS));
	pattern_list->patterns = NULL;
	// 우선 pattern_list.txt와 같이 미리 만들어놓은 DB로부터 pattern을 가져온다.
	getPatterns(pattern_list);

	// 메모리에 접근할 수 있는 권한을 획득하기 위하여 Debug Privilege를 세팅한다.
	if (false == setPrivilege(SE_DEBUG_NAME, true)){
		_tprintf(_T("set privilege failed."));
		return 0;
	};

	// 프로세스 리스트를 얻는다.
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE){
		_tprintf(_T("CreateToolhelp32Snapshot error \n"));
		return 0;
	}

	PROCESSENTRY32 pe32; //프로세스 정보 저장 구조체
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)){
		_tprintf(_T("Process32First error ! \n"));
		CloseHandle(hProcessSnap);
		return 0;
	}

	// 각 process의 base address를 찾아 PE헤더를 분석하여 pattern을 찾아낸다.
	DWORD_PTR baseAddress;
	do
	{
		baseAddress = getBaseAddress(pe32.th32ProcessID);
		if (0 == baseAddress){
			continue;
		}
		else{
			if (TRUE == findPatterns(baseAddress, pe32.th32ProcessID, pattern_list, pe32.szExeFile)){
				/*_tprintf(_T("###########################################\n"));
				_tprintf(_T("found process name : %s, process id : %u\n"),pe32.szExeFile,pe32.th32ProcessID);
				_tprintf(_T("###########################################\n"));*/
			}
		};
	} while (Process32Next(hProcessSnap, &pe32));

	freePatterns(pattern_list);
	return 0;
}

void getPatterns(_Out_ PATTERNS* pattern_list)
{
	int nCutPos, nHexValue, pIndex = 0;
	const char* filename = "patterns.txt";
	ifstream ifp(filename);
	string pattern, strResult, one_pattern;
	while (getline(ifp, pattern)) {
		cout << pattern << endl;
		// []내부내용 검사. []가 있으면 해당 pattern type으로 설정하고, 없으면 ALL로 설정.
		if (pattern_list->patterns != NULL) {
			pattern_list->next = (PATTERNS*)malloc(sizeof(PATTERNS));
			pattern_list = pattern_list->next;
		}
		if ((nCutPos = pattern.find_first_of("]")) != pattern.npos) {
			string tmp_pattern_type = pattern.substr(0, nCutPos);
			transform(tmp_pattern_type.begin(), tmp_pattern_type.end(), tmp_pattern_type.begin(), toupper);
			if (!tmp_pattern_type.compare("[ALL")) {
				pattern_list->pattern_type = ALL_SECTION;
			}
			else if (!tmp_pattern_type.compare("[PE_HEADER")) {
				pattern_list->pattern_type = PE_HEADERS;
			}
			else if (!tmp_pattern_type.compare("[.TEXT")) {
				pattern_list->pattern_type = TEXT_SECTION;
			}
			else if (!tmp_pattern_type.compare("[.DATA")) {
				pattern_list->pattern_type = DATA_SECTION;
			}
			else if (!tmp_pattern_type.compare("[.IDATA")) {
				pattern_list->pattern_type = IDATA_SECTION;
			}
			else if (!tmp_pattern_type.compare("[.RSRC")) {
				pattern_list->pattern_type = RSRC_SECTION;
			}
			else if (!tmp_pattern_type.compare("[.RELOC")) {
				pattern_list->pattern_type = RELOC_SECTION;
			}
		}
		else {
			pattern_list->pattern_type = ALL_SECTION;
		};

		// 패턴들을 list에 담음
		pattern = pattern.substr(nCutPos + 2);
		pattern_list->pattern_size = pattern.size() / 3 + 1;
		pattern_list->patterns = (UCHAR*)malloc(sizeof(UCHAR)*pattern_list->pattern_size);

		while (true)
		{
			if ((nCutPos = pattern.find_first_of(" ")) != pattern.npos) {
				one_pattern = pattern.substr(0, nCutPos);
				stringstream convert(one_pattern);
				convert >> hex >> nHexValue;
				memcpy(&pattern_list->patterns[pIndex++], (UCHAR*)&nHexValue, sizeof(UCHAR));
				pattern = pattern.substr(nCutPos + 1);
			}
			else {
				stringstream convert(pattern);
				convert >> hex >> nHexValue;
				memcpy(&pattern_list->patterns[pIndex], (UCHAR*)&nHexValue, sizeof(UCHAR));
				break;
			}
		}

		pIndex = 0;
		pattern_list->next = NULL;
	}
}

bool setPrivilege(_In_z_ const wchar_t* privilege, _In_ bool enable)
{
	HANDLE hToken;
	if (TRUE != OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
	{
		if (GetLastError() == ERROR_NO_TOKEN)
		{
			if (ImpersonateSelf(SecurityImpersonation) != TRUE)
			{
				_tprintf(_T("ImpersonateSelf( ) failed. gle=0x%08x"), GetLastError());
				return false;
			}

			if (TRUE != OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
			{
				_tprintf(_T("OpenThreadToken() failed. gle=0x%08x"), GetLastError());
				return false;
			}
		}
		else
		{
			_tprintf(_T("OpenThread() failed. gle=0x%08x"), GetLastError());
			return false;
		}

		TOKEN_PRIVILEGES tp = { 0 };
		LUID luid = { 0 };
		DWORD cb = sizeof(TOKEN_PRIVILEGES);
		if (!LookupPrivilegeValue(NULL, privilege, &luid))
		{
			_tprintf(_T("LookupPrivilegeValue() failed. gle=0x%08x"), GetLastError());
			CloseHandle(hToken);
			return false;
		}
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		if (enable)
		{
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		}
		else
		{
			tp.Privileges[0].Attributes = 0;
		}

		if (FALSE == AdjustTokenPrivileges(hToken, FALSE, &tp, cb, NULL, NULL))
		{
			DWORD gle = GetLastError();
			if (gle != ERROR_SUCCESS)
			{
				_tprintf(_T("AdjustTokenPrivileges() failed. gle=0x%08x"), GetLastError());
				CloseHandle(hToken);
				return false;
			}
		}

		CloseHandle(hToken);
	}

	return true;
}

DWORD_PTR getBaseAddress(_In_ DWORD pID)
{
	MODULEENTRY32 me32 = { 0 };

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		//_tprintf(_T("CreateToolhelp32Snapshot (of modules), Process ID = %u, gle = %u\n"), pID, GetLastError());
		return 0;
	}

	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{
		_tprintf(_T("Module32First() failed, Process ID = %u, gle = %u\n"), pID, GetLastError());
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object!
		return 0;
	}

	CloseHandle(hModuleSnap);
	return (DWORD_PTR)me32.modBaseAddr;
}

bool findPatterns(_In_ DWORD_PTR baseAddress, _In_ DWORD pID, _In_ PATTERNS* pattern_list, _In_ wchar_t* procName)
{
	_IMAGE_DOS_HEADER dos;
	_IMAGE_NT_HEADERS nt;
	_IMAGE_NT_HEADERS64 nt64;
	_IMAGE_SECTION_HEADER section;

	bool is32 = true;

	UCHAR buf[1024] = { 0 };

	SIZE_T readNum = 0;

	list<FOUND_PATTERN>* found_list;

	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (NULL == pHandle){
		if(pID != 0)
		_tprintf(_T("OpenProcess() failed, Process ID = %d, gle = %u\n"), pID, GetLastError());
		return false;
	}
	else{
		// DOS 헤더 읽기
		if (TRUE != ReadProcessMemory(pHandle, (LPCVOID)baseAddress, &dos, sizeof(_IMAGE_DOS_HEADER), &readNum)){
			_tprintf(_T("ReadProcessMemory() - DOS HEADER failed, Process ID = %u, gle = %u\n"), pID, GetLastError());
			CloseHandle(pHandle);
			return false;
		}
		else{			
			if (pID == 768){
				// DOS 헤더 분석
				printf("\n<<DOS>>");
				memcpy(buf, &dos, sizeof(_IMAGE_DOS_HEADER));
				for (SIZE_T i = 0; i < readNum; i++){
					if (i % 8 == 0) printf(" ");
					if (i % 16 == 0) printf("\n");
					printf("%02X ", buf[i]);
				}
				if ((found_list = findPatternsDetail(buf, readNum, pattern_list, PE_HEADERS))->empty() == false)
					logFoundList(found_list, procName, "DOS HEADER");
				// NT 헤더를 읽는다. 읽었는데 64bit로 돌아가는 프로그램이었다면, 64비트로 다시 읽는다.
				if (TRUE != ReadProcessMemory(pHandle, (LPCVOID)(baseAddress + dos.e_lfanew), &nt, sizeof(_IMAGE_NT_HEADERS), &readNum)){
					_tprintf(_T("ReadProcessMemory() - NT HEADER 32bit failed, Process ID = %u, gle = %u\n"), pID, GetLastError());
					CloseHandle(pHandle);
					return false;
				}
				else {
					if (nt.FileHeader.Machine == IMAGE_FILE_MACHINE_IA64){
						printf("64bit!! pID : %d\n", pID);
						is32 = false;
						if (TRUE != ReadProcessMemory(pHandle, (LPCVOID)(baseAddress + dos.e_lfanew), &nt64, sizeof(_IMAGE_NT_HEADERS64), &readNum)){
							_tprintf(_T("ReadProcessMemory() - NT HEADER 64bit failed, Process ID = %u, gle = %u\n"), pID, GetLastError());
							CloseHandle(pHandle);
							return false;
						}
					}

					// NT 헤더 분석-32bit / 64bit에 따라 다르게 분석해야할 필요 있을듯.
					printf("\n<<NT>>");
					memcpy(buf, &nt, sizeof(_IMAGE_NT_HEADERS));
					for (SIZE_T i = 0; i < readNum; i++){
						if (i % 8 == 0) printf(" ");
						if (i % 16 == 0) printf("\n"); 
						printf("%02X ", buf[i]);
					}
					if ((found_list = findPatternsDetail(buf, readNum, pattern_list, PE_HEADERS))->empty() == false)
						logFoundList(found_list, procName, "NT HEADER");

					// SECTION 헤더 읽기
					int sec_num = 0;
					int nt_size = readNum;
					while (sec_num < nt.FileHeader.NumberOfSections){
						if (TRUE != ReadProcessMemory(pHandle, (LPCVOID)(baseAddress + dos.e_lfanew + nt_size + sec_num*sizeof(_IMAGE_SECTION_HEADER)), &section, sizeof(_IMAGE_SECTION_HEADER), &readNum)){
							_tprintf(_T("ReadProcessMemory() - SECTION HEADER failed, Process ID = %u, gle = %u\n"), pID, GetLastError());
							CloseHandle(pHandle);
							return false;
						}
						else{
							printf("\n<<SECTION_HEADER(%s)>>", section.Name);
							memcpy(buf, &section, sizeof(_IMAGE_SECTION_HEADER));
							for (SIZE_T i = 0; i < readNum; i++){
								if (i % 8 == 0) printf(" ");
								if (i % 16 == 0) printf("\n");
								printf("%02X ", buf[i]);
							}
							if ((found_list = findPatternsDetail(buf, readNum, pattern_list, PE_HEADERS))->empty() == false)
								logFoundList(found_list, procName, "SECTION HEADER");
							UCHAR* buf2;
							buf2 = (UCHAR*)malloc(sizeof(UCHAR)*section.SizeOfRawData);

							if (TRUE != ReadProcessMemory(pHandle, (LPCVOID)(baseAddress + section.VirtualAddress), buf2, section.SizeOfRawData, &readNum)){
								_tprintf(_T("ReadProcessMemory() - SECTION CONTENT failed, Process ID = %u, gle = %u\n"), pID, GetLastError());
								CloseHandle(pHandle);
								return false;
							}
							else {
								printf("\n<<SECTION_CONTENT(%s)>>\n", section.Name);
								for (SIZE_T i = 0; i < 400; i+=16){
									printf("%08X    ", i + section.VirtualAddress);
									for (int j = 0; j < 16; j++) {
										printf("%02X ", buf2[i + j]);
									}
									printf("     ");
									for (int j = 0; j < 16; j++) {
										if (buf2[i + j] >= 128 || buf2[i + j]<32) printf(".");
										else printf("%c", buf2[i + j]);
									}
									printf("\n");
								}
								
								if ((found_list = findPatternsDetail(buf2, readNum, pattern_list, section_name((char*)section.Name)))->empty() == false) {
									char tmp_section_body[20] = { 0 };
									strncpy(tmp_section_body, (char*)section.Name, strlen((char*)section.Name));
									strcat(tmp_section_body, " SECTION BODY");
									logFoundList(found_list, procName, tmp_section_body);
								}
							}
							free(buf2);
						}
						sec_num++;
					}
				}
			}
		}
	}

	CloseHandle(pHandle);
	return true;
}

list<FOUND_PATTERN>* findPatternsDetail(_In_ UCHAR* buf, _In_ int buf_size, _In_ PATTERNS* pattern_list, _In_ int pattern_type)
{
	list<FOUND_PATTERN>* found_list = new list<FOUND_PATTERN>;
	bool found = false;
	int pIndex;
	while (pattern_list != NULL) {
		if (pattern_type & pattern_list->pattern_type) {
			for (int buf_num = 0; buf_num < buf_size; buf_num++) {
				for (pIndex = 0; pIndex < pattern_list->pattern_size; pIndex++) {
					if (buf_num + pIndex > buf_size) break;
					if (buf[buf_num + pIndex] == pattern_list->patterns[pIndex])
						found = true;
					else break;
				}
				if (found && pIndex == pattern_list->pattern_size) {
					FOUND_PATTERN* tmp = (FOUND_PATTERN*)malloc(sizeof(FOUND_PATTERN));
					tmp->found_loc = buf_num;
					tmp->pattern_size = pattern_list->pattern_size;
					memcpy(&(tmp->patterns), &pattern_list->patterns, pattern_list->pattern_size);
					found_list->push_back(*tmp);
				}
				found = false;
			}
		}
		pattern_list = pattern_list->next;
	}
	return found_list;
}

void logFoundList(_In_ list<FOUND_PATTERN>* found_list, _In_ wchar_t* procName, _In_ const char* location)
{
	FILE* fp;
	int i = 0;
	fp = fopen("found_list.txt", "a");
	fprintf(fp, "발견된 프로세스 : %ws, 발견된 패턴 영역 : %s, 발견된 패턴 수 : %d\n", procName, location, found_list->size());
	fprintf(fp, "<<패턴 리스트>>\n");
	for (list<FOUND_PATTERN>::iterator iter = found_list->begin(); iter != found_list->end(); iter++) {
		fprintf(fp, "%02d.발견된 위치 : 0x%02X, \t발견된 패턴 : ", ++i, (*iter).found_loc);
		for (int j = 0; j < (*iter).pattern_size; j++)
			fprintf(fp, "%02X ", (*iter).patterns[j]);
		fprintf(fp, "\n");
	}
	fprintf(fp, "\n");
	fclose(fp);
	return;
}

int section_name(_In_ const char* section_name)
{
	if (!strcmp(section_name, ".text")) {
		return TEXT_SECTION;
	}
	else if(!strcmp(section_name, ".data")){
		return DATA_SECTION;
	}
	else if (!strcmp(section_name, ".idata")) {
		return IDATA_SECTION;
	}
	else if (!strcmp(section_name, ".rsrc")) {
		return RSRC_SECTION;
	}
	else if (!strcmp(section_name, ".reloc")) {
		return RELOC_SECTION;
	}
}

void freePatterns(_Out_ PATTERNS* pattern_list)
{
	while (pattern_list != NULL) {
		PATTERNS* tmp;
		tmp = pattern_list->next;
		free(pattern_list);
		pattern_list = tmp;
	}
}