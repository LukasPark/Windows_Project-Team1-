#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>
#include <tlhelp32.h>

#define ARRAY_EACH_SIZE 100     // �迭 ũ��
PDWORD FindMem(HANDLE hProc);
void ListProcessInfo(void);
int _tmain(int argc, TCHAR* argv[]){ //���� �����Ӥ�
	//TCHAR TargetProcess[BUFSIZ];
	//���Ḧ ���ϴ� ���μ����� �̸��� �Է¹��� ����
	while (1){
		ListProcessInfo();

		break;
		//I'm Choitest

	}
	return 0;
}
//�Ʒ� �Լ��� ���μ��� ��� ��� �Լ��Դϴ�.
void ListProcessInfo(void){

	DWORD pID;
	HANDLE hProcessSnap =
		CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//���� ���μ����� ���¸� ������� ������~!

	if (hProcessSnap == INVALID_HANDLE_VALUE){
		_tprintf(_T("CreateToolhelp32Snapshot error \n"));
		exit(EXIT_FAILURE);
	}
	PROCESSENTRY32 pe32; //���μ��� ���� ���� ����ü
	pe32.dwSize = sizeof(PROCESSENTRY32);


	if (!Process32First(hProcessSnap, &pe32)){
		_tprintf(_T("Process32First error ! \n"));
		CloseHandle(hProcessSnap);
		return;
	}
	//Process32First �Լ��� ����, ��� ���μ����� ��Ӵϰ���
	//System Process�� ������ �޾ƿɴϴ�
	_tprintf(_T("               \t[Process name]  \t[PID]\t[PPID]\t[ThreadID] \n"));
	WCHAR *note;
	bool search = 0;
	do
	{ //do~while() ����
		_tprintf(_T("%35s %8d %8d %8d \n"),
			pe32.szExeFile, pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.cntThreads);
	} while (Process32Next(hProcessSnap, &pe32));
	//Process32Next�� ���� ���μ��� �������� ��� ����մϴ�.

	printf("Select Process(Id): ");
	scanf_s("%d", &pID);

	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	FindMem(h);

	return;
}

PDWORD FindMem(HANDLE hProc)
{
	SYSTEM_INFO si; // �޸� �ּ� �ּҰ�, �ִ밪�� ���

	MEMORY_BASIC_INFORMATION mbi;   // ������ ���� ���

	DWORD nMem = 0, i, j, result_ct = 0;        // ���� �޸� �ּ� ������ �� �� ���꿡 �ʿ��� ����

	BYTE *destArray;    // �޸𸮿��� �о ��

	DWORD *FindData = (DWORD *)malloc(ARRAY_EACH_SIZE * 4);   // ã�Ƴ� ���� ����

	GetSystemInfo(&si);
	nMem = (DWORD)si.lpMinimumApplicationAddress; //�޸� �ּ��� �ּҰ��� ���Ѵ�.

	do{
		if (VirtualQueryEx(hProc, (LPVOID)nMem, &mbi, sizeof(mbi)) == sizeof(mbi))
		{         // �������� ������ �о��

			if (mbi.RegionSize > 0 && mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT)
			{      // �������� ��밡������ �˾Ƴ���

				destArray = new BYTE[mbi.RegionSize];      // �޸𸮸� ���� �غ� �Ѵ�

				if (ReadProcessMemory(hProc, mbi.BaseAddress, destArray, mbi.RegionSize, NULL) != 0)
				{       // �޸𸮸� �д´�
					for (i = 0; i<(DWORD)mbi.RegionSize; i++)
					{        // ���� �޸𸮿� ã�� �޸𸮸� ���Ѵ�
						printf("%C ", destArray[i]);
						if (i % 50 == 0) printf("\n");
					}
				}
				delete destArray;       // �޸𸮸� �о����� ����

			}
			else printf("page not usable!\n");

			nMem = (DWORD)mbi.BaseAddress + (DWORD)mbi.RegionSize;  //���� ������ �ּ� ���
		}
		else printf("cant read page!\n");
	} while (nMem < (DWORD)si.lpMaximumApplicationAddress);       // �ִ� �ּҸ� �Ѿ���� �������� ��������

	return FindData;    // ����� ����
}