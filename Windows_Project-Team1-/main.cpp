#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>

#define ARRAY_EACH_SIZE 100     // 배열 크기
PDWORD FindMem(HANDLE hProc);
void ListProcessInfo(void);
int _tmain(int argc, TCHAR* argv[]){ //여기 메인임ㅋ
	//TCHAR TargetProcess[BUFSIZ];
	//종료를 원하는 프로세스의 이름을 입력받을 버퍼
	while (1){
		ListProcessInfo();

		break;
		//I'm Choi

	}
	return 0;
}
//아래 함수는 프로세스 목록 출력 함수입니다.
void ListProcessInfo(void){

	DWORD pID;
	HANDLE hProcessSnap =
		CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//현재 프로세스의 상태를 사진찍듯 스냅샷~!

	if (hProcessSnap == INVALID_HANDLE_VALUE){
		_tprintf(_T("CreateToolhelp32Snapshot error \n"));
		exit(EXIT_FAILURE);
	}
	PROCESSENTRY32 pe32; //프로세스 정보 저장 구조체
	pe32.dwSize = sizeof(PROCESSENTRY32);


	if (!Process32First(hProcessSnap, &pe32)){
		_tprintf(_T("Process32First error ! \n"));
		CloseHandle(hProcessSnap);
		return;
	}
	//Process32First 함수로 부터, 모든 프로세스의 어머니격인
	//System Process의 정보를 받아옵니다
	_tprintf(_T("               \t[Process name]  \t[PID]\t[PPID]\t[ThreadID] \n"));
	WCHAR *note;
	bool search = 0;
	do
	{ //do~while() 구문
		_tprintf(_T("%35s %8d %8d %8d \n"),
			pe32.szExeFile, pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.cntThreads);
	} while (Process32Next(hProcessSnap, &pe32));
	//Process32Next로 얻어온 프로세스 정보들을 모두 출력합니다.

	printf("Select Process(Id): ");
	scanf_s("%d", &pID);

	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	FindMem(h);

	return;
}

PDWORD FindMem(HANDLE hProc)
{
	SYSTEM_INFO si; // 메모리 주소 최소값, 최대값을 출력

	MEMORY_BASIC_INFORMATION mbi;   // 페이지 정보 출력

	DWORD nMem = 0, i, j, result_ct = 0;        // 현재 메모리 주소 변수와 그 외 연산에 필요한 변수

	BYTE *destArray;    // 메모리에서 읽어낸 것

	DWORD *FindData = (DWORD *)malloc(ARRAY_EACH_SIZE * 4);   // 찾아낸 것을 저장

	GetSystemInfo(&si);
	nMem = (DWORD)si.lpMinimumApplicationAddress; //메모리 주소의 최소값을 구한다.

	do{
		if (VirtualQueryEx(hProc, (LPVOID)nMem, &mbi, sizeof(mbi)) == sizeof(mbi))
		{         // 페이지의 정보를 읽어낸다

			if (mbi.RegionSize > 0 && mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT)
			{      // 페이지가 사용가능한지 알아낸다

				destArray = new BYTE[mbi.RegionSize];      // 메모리를 읽을 준비를 한다

				if (ReadProcessMemory(hProc, mbi.BaseAddress, destArray, mbi.RegionSize, NULL) != 0)
				{       // 메모리를 읽는다
					for (i = 0; i<(DWORD)mbi.RegionSize; i++)
					{        // 읽은 메모리와 찾을 메모리를 비교한다
						printf("%C ", destArray[i]);
						if (i % 50 == 0) printf("\n");
					}
				}
				delete destArray;       // 메모리를 읽었으니 해제

			}
			else printf("page not usable!\n");

			nMem = (DWORD)mbi.BaseAddress + (DWORD)mbi.RegionSize;  //현재 페이지 주소 계산
		}
		else printf("cant read page!\n");
	} while (nMem < (DWORD)si.lpMaximumApplicationAddress);       // 최대 주소를 넘어갔으면 루프에서 빠져나옴

	return FindData;    // 결과값 리턴
}