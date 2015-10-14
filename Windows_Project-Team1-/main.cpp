#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winnt.h>

void getPatterns(_Out_ wchar_t* patterns[]);
bool findPatterns(_In_ DWORD_PTR baseAdress, _In_ DWORD pID, _In_ wchar_t* patterns[]);

DWORD_PTR getBaseAddress(DWORD pID);
bool setPrivilege(_In_z_ const wchar_t* privilege, _In_ bool enable);

int _tmain(int argc, TCHAR* argv[]){
	wchar_t* patterns[] = { 0 };

	// 우선 pattern_list.txt와 같이 미리 만들어놓은 DB로부터 pattern을 가져온다.
	getPatterns(patterns);

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
			if (TRUE == findPatterns(baseAddress, pe32.th32ProcessID, patterns)){
				/*_tprintf(_T("###########################################\n"));
				_tprintf(_T("found process name : %s, process id : %u\n"),pe32.szExeFile,pe32.th32ProcessID);
				_tprintf(_T("###########################################\n"));*/
			}
		};
	} while (Process32Next(hProcessSnap, &pe32));

	return 0;
}

void getPatterns(_Out_ wchar_t* patterns[])
{

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

DWORD_PTR getBaseAddress(DWORD pID)
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

bool findPatterns(_In_ DWORD_PTR baseAddress, _In_ DWORD pID, _In_ wchar_t* patterns[])
{
	_IMAGE_DOS_HEADER dos;
	_IMAGE_NT_HEADERS nt;
	_IMAGE_NT_HEADERS64 nt64;
	_IMAGE_SECTION_HEADER section;

	bool is32 = true;

	UCHAR buf[1024] = { 0 };

	SIZE_T readNum = 0;

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
			if (pID == 6304){
				// DOS 헤더 분석
				printf("\n<<DOS>>");
				memcpy(buf, &dos, sizeof(_IMAGE_DOS_HEADER));
				for (SIZE_T i = 0; i < readNum; i++){
					if (i % 8 == 0) printf(" ");
					if (i % 16 == 0) printf("\n");
					printf("%02X ", buf[i]);
				}
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

							UCHAR* buf2;
							buf2 = (UCHAR*)malloc(sizeof(UCHAR)*section.Misc.VirtualSize);
							if (TRUE != ReadProcessMemory(pHandle, (LPCVOID)(baseAddress + section.VirtualAddress), &buf2, section.Misc.VirtualSize, &readNum)){
								_tprintf(_T("ReadProcessMemory() - NT HEADER 64bit failed, Process ID = %u, gle = %u\n"), pID, GetLastError());
								CloseHandle(pHandle);
								return false;
							}
							else {
								printf("\n<<SECTION_CONTENT(%s)>>", section.Name);
								for (SIZE_T i = 0; i < readNum; i++){
									if (i % 8 == 0) printf(" ");
									if (i % 16 == 0) printf("\n");
									printf("%02X ", buf2[i]);
								}
								free(buf2);
							}
							return true;
							sec_num++;
						}
					}

					/*UCHAR buf2[2048];
					if (TRUE != ReadProcessMemory(pHandle, (LPCVOID)(baseAddress + dos.e_lfanew + nt_size + (sec_num-1)*sizeof(_IMAGE_SECTION_HEADER)), &buf2, sizeof(buf2), &readNum)){
						_tprintf(_T("ReadProcessMemory() - SECTION CONTENT failed, Process ID = %u, gle = %u\n"), pID, GetLastError());
						CloseHandle(pHandle);
						return false;
					}
					else{
						for (SIZE_T i = 0; i < readNum; i++){
							if (i % 8 == 0) printf(" ");
							if (i % 16 == 0) printf("\n");
							printf("%02X ", buf2[i]);
						}
					}
					printf("readNum : %d", readNum);*/
				}
			}
		}
	}

	CloseHandle(pHandle);
	return true;
}

