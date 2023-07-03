// Project1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <cstdlib>
#include <tchar.h>
#include "api/auth.hpp"
#include "api/skStr.h"
#include "api/utils.hpp"
#include "resource.h"
#include <future>       
#include <chrono>       
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <time.h>
#include <cstdlib>
#include <sstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <Psapi.h>
#include <cstring>
#include <thread>
#include <iterator>
#include <math.h>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <stdio.h>
#include <urlmon.h>
#pragma comment(lib,"urlmon.lib")
#include "Discord.h"
#include <shellapi.h>
using namespace KeyAuth;
using namespace std;
Discord* g_Discord;

HANDLE Gamephandle;
string publicserver;
bool norecoilactive = false;
bool ipadviewactive = false;
bool noheadshotactive = true;
DWORD ue4addrbk = 0;

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

std::string name = "modskin";
std::string ownerid = "HvgVPUCbHy";
std::string secret = "f9d64c3605700c318ba0b34d0a41f5254d496925f59c52c580285a8576dc3307";
std::string version = "1.0";
std::string url = "https://keyauth.win/api/1.2/";

api KeyAuthApp(name, ownerid, secret, version, url);
#pragma region
LRESULT CALLBACK WndProc(HWND hwnd, unsigned int msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CREATE:
	{
		HINSTANCE hInstance = ((LPCREATESTRUCT)lParam)->hInstance;
		HICON hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
		_ASSERTE(hIcon != 0);
		SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
		return 0;
	}
	case WM_COMMAND:
	{
		return 0;
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		return 0;
	}
	}

	return (DefWindowProc(hwnd, msg, wParam, lParam));
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevIns, LPSTR lpszArgument, int iShow)
{
	TCHAR szClassName[] = _T("Template");
	TCHAR szWindowName[] = _T("Template");
	WNDCLASSEX wc = { 0 };
	MSG messages;
	HWND hWnd;

	wc.lpszClassName = szClassName;
	wc.lpfnWndProc = WndProc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.hbrBackground = (HBRUSH)COLOR_BTNSHADOW;
	wc.hInstance = hInstance;

	_ASSERTE(RegisterClassEx(&wc) != 0);

	hWnd = CreateWindowEx(0, szClassName, szWindowName, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		HWND_DESKTOP, 0, hInstance, 0);

	_ASSERTE(::IsWindow(hWnd));

	ShowWindow(hWnd, iShow);
	while (GetMessage(&messages, NULL, 0, 0))
	{
		TranslateMessage(&messages);
		DispatchMessage(&messages);
	}

	return static_cast<int>(messages.wParam);
}

static bool Loged_in;

void ColorWrite(string text, int color)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
	cout << text << endl;
}
void ColorWrite1(string text, int color)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
	cout << text ;
}
VOID UnloadDriver(LPCSTR DisplayName)
{
	SC_HANDLE hSCManager = OpenSCManagerA(0, 0, SC_MANAGER_CONNECT);
	SC_HANDLE hService = OpenServiceA(hSCManager, DisplayName, SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE);
	SERVICE_STATUS ServiceStatus;
	ControlService(hService, SERVICE_CONTROL_STOP, &ServiceStatus);
	DeleteService(hService);
	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hService);
}

BOOL LoadDriver(PCHAR DriverPath, LPCSTR DisplayName)
{
	UnloadDriver(DisplayName);
	SC_HANDLE hSCManager = OpenSCManagerA(0, 0, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager == 0x0 || hSCManager == INVALID_HANDLE_VALUE) return FALSE;

	SC_HANDLE hService = OpenServiceA(hSCManager, DisplayName, SERVICE_START);
	if (hService == 0x0 || hService == INVALID_HANDLE_VALUE)
	{
		hService = CreateServiceA(hSCManager, DisplayName, DisplayName, SERVICE_START, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, DriverPath, nullptr, nullptr, nullptr, nullptr, nullptr);
		if (hService == 0x0 || hService == INVALID_HANDLE_VALUE)
		{
			CloseServiceHandle(hSCManager);
			return FALSE;
		}
	}

	bool bStartService = StartServiceA(hService, NULL, nullptr);
	if (!bStartService)
	{
		CloseServiceHandle(hService);
		hService = OpenServiceA(hSCManager, DisplayName, SERVICE_START | SERVICE_CHANGE_CONFIG);
		bool bChangeServiceConfig = ChangeServiceConfigA(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
		if (bChangeServiceConfig)
		{
			bStartService = StartServiceA(hService, NULL, nullptr);
			if (!bStartService)
			{
				UnloadDriver(DisplayName);
				return FALSE;
			}
		}
	}

	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hService);
	return TRUE;
}


INT CheckDriver(LPCWSTR name)
{
	SC_HANDLE theService, scm;
	SERVICE_STATUS m_SERVICE_STATUS;
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwBytesNeeded;
	scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!scm) {
		return 0;
	}
	theService = OpenService(scm, name, SERVICE_QUERY_STATUS);
	if (!theService) {
		CloseServiceHandle(scm);
		return 0;
	}
	auto result = QueryServiceStatusEx(theService, SC_STATUS_PROCESS_INFO,
		reinterpret_cast<LPBYTE>(&ssStatus), sizeof(SERVICE_STATUS_PROCESS),
		&dwBytesNeeded);
	CloseServiceHandle(theService);
	CloseServiceHandle(scm);
	if (result == 0) {
		return 0;
	}
	return ssStatus.dwCurrentState;
}
std::string GetCurrentDirectory()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	return std::string(buffer).substr(0, pos);
}
bool Adb_Cmd(string CmdCode)
{
	if (!CmdCode.empty())
	{
		string CmdCode2 = "/C " + CmdCode;
		std::wstring stemp = std::wstring(CmdCode2.begin(), CmdCode2.end());
		LPCWSTR sw = stemp.c_str();
		string CurrentDirectory = GetCurrentDirectory();
		std::wstring stemp2 = std::wstring(CurrentDirectory.begin(), CurrentDirectory.end());
		LPCWSTR sw2 = stemp2.c_str();
		SHELLEXECUTEINFO info1 = { 0 };
		info1.cbSize = sizeof(SHELLEXECUTEINFO);
		info1.fMask = SEE_MASK_NOCLOSEPROCESS;
		info1.hwnd = NULL;
		info1.lpVerb = NULL;
		info1.lpFile = L"cmd.exe";
		info1.lpParameters = sw;
		info1.lpDirectory = sw2;
		info1.nShow = SW_HIDE;
		info1.hInstApp = NULL;
		ShellExecuteEx(&info1);
		WaitForSingleObject(info1.hProcess, INFINITE);
		return true;
	}
	else
	{
		return false;
	}
}
bool runfile(LPCWSTR lpfile)
{
		
		SHELLEXECUTEINFO info1 = { 0 };
		info1.cbSize = sizeof(SHELLEXECUTEINFO);
		info1.fMask = SEE_MASK_NOCLOSEPROCESS;
		info1.hwnd = NULL;
		info1.lpVerb = NULL;
		info1.lpFile = lpfile;
		info1.lpParameters = NULL;
		info1.lpDirectory = NULL;
		info1.nShow = SW_HIDE;
		info1.hInstApp = NULL;
		ShellExecuteEx(&info1);
		WaitForSingleObject(info1.hProcess, INFINITE);
		return true;
}
void RunHide(LPCWSTR lpfile)
{
	runfile(lpfile);
	std::future<bool> fut = std::async(runfile, lpfile);
	fut.wait();
}
void cmd(string text) {
	std::future<bool> fut = std::async(Adb_Cmd, text);
	fut.wait();
}
void WriteResToDisk(std::string PathFile, LPWSTR File_WITHARG)
{
	HRSRC myResource = ::FindResource(NULL, File_WITHARG, RT_RCDATA);
	unsigned int myResourceSize = ::SizeofResource(NULL, myResource);
	HGLOBAL myResourceData = ::LoadResource(NULL, myResource);
	void* pMyExecutable = ::LockResource(myResourceData);
	std::ofstream f(PathFile, std::ios::out | std::ios::binary);
	f.write((char*)pMyExecutable, myResourceSize);
	f.close();
}
int getAowProcId()
{
	int pid = 0;
	int threadCount = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnap, &pe);
	while (Process32Next(hSnap, &pe)) {
		if (lstrcmpiW(pe.szExeFile, L"aow_exe.exe") == 0) {
			if ((int)pe.cntThreads > threadCount) {
				threadCount = pe.cntThreads;
				pid = pe.th32ProcessID;
			}
		}


	}
	return pid;
}



int gettrueaow()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (lstrcmpiW(ProcEntry.szExeFile, L"aow_exe.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 250000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}
	CloseHandle(snapshot);
}
int getProcId()
{
	int AOW = 0;
	AOW = getAowProcId();
	if (AOW == 0 || AOW == 1)
	{
		return 0;
	}
	else
	{
		return AOW;
	}
}



void offsetpatch(int offset, BYTE write[], SIZE_T size, int header)
{
	HANDLE phandle = Gamephandle;
	DWORD addr = header + offset;
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (BYTE*)addr, write, size, NULL);
	VirtualProtectEx(phandle, (BYTE*)addr, size, OldProtect, &OldProtect2);
	Sleep(1.5);
}



typedef struct _MEMORY_REGION {
	DWORD_PTR dwBaseAddr;
	DWORD_PTR dwMemorySize;
}MEMORY_REGION;

int MemFind(BYTE* buffer, int dwBufferSize, BYTE* bstr, DWORD dwStrLen)
{
	if (dwBufferSize < 0)
	{
		return -1;
	}
	DWORD  i, j;
	for (i = 0; i < dwBufferSize; i++)
	{
		for (j = 0; j < dwStrLen; j++)
		{
			if (buffer[i + j] != bstr[j] && bstr[j] != '?')
				break;
		}
		if (j == dwStrLen)
			return i;
	}
	return -1;
}
int SundaySearch(BYTE* bStartAddr, int dwSize, BYTE* bSearchData, DWORD dwSearchSize)
{
	if (dwSize < 0)
	{
		return -1;
	}
	int iIndex[256] = { 0 };
	int i, j;
	DWORD k;

	for (i = 0; i < 256; i++)
	{
		iIndex[i] = -1;
	}

	j = 0;
	for (i = dwSearchSize - 1; i >= 0; i--)
	{
		if (iIndex[bSearchData[i]] == -1)
		{
			iIndex[bSearchData[i]] = dwSearchSize - i;
			if (++j == 256)
				break;
		}
	}
	i = 0;
	BOOL bFind = FALSE;
	//j=dwSize-dwSearchSize+1;
	j = dwSize - dwSearchSize + 1;
	while (i < j)
	{
		for (k = 0; k < dwSearchSize; k++)
		{
			if (bStartAddr[i + k] != bSearchData[k])
				break;
		}
		if (k == dwSearchSize)
		{
			//ret=bStartAddr+i;
			bFind = TRUE;
			break;
		}
		if (i + dwSearchSize >= dwSize)
		{

			return -1;
		}
		k = iIndex[bStartAddr[i + dwSearchSize]];
		if (k == -1)
			i = i + dwSearchSize + 1;
		else
			i = i + k;
	}
	if (bFind)
	{
		return i;
	}
	else
		return -1;

}
DWORD FindProcessId(const wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}
	CloseHandle(processesSnapshot);
	return 0;
}

string FileReadLine(string filename) {
	fstream my_file;
	my_file.open(filename, ios::in);
	if (!my_file) {

	}
	else {
		char ch;

		while (1) {
			my_file >> ch;
			if (my_file.eof())
				break;
			string returnname = string(1, ch);
			return returnname;
		}

	}
	my_file.close();
}
BOOL MemSearch(HANDLE phandle, BYTE* bSearchData, int nSearchSize, DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr, BOOL bIsCurrProcess, int iSearchMode, std::vector<DWORD_PTR>& vRet)
{
    
	BYTE* pCurrMemoryData = NULL;
	MEMORY_BASIC_INFORMATION	mbi;
	std::vector<MEMORY_REGION> m_vMemoryRegion;
	mbi.RegionSize = 0x1000;
	DWORD dwAddress = dwStartAddr;



	while (VirtualQueryEx(phandle, (LPCVOID)dwAddress, &mbi, sizeof(mbi)) && (dwAddress < dwEndAddr) && ((dwAddress + mbi.RegionSize) > dwAddress))
	{

		if ((mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_GUARD) == 0) && (mbi.Protect != PAGE_NOACCESS) && ((mbi.AllocationProtect & PAGE_NOCACHE) != PAGE_NOCACHE))
		{

			MEMORY_REGION mData = { 0 };
			mData.dwBaseAddr = (DWORD_PTR)mbi.BaseAddress;
			mData.dwMemorySize = mbi.RegionSize;
			m_vMemoryRegion.push_back(mData);

		}
		dwAddress = (DWORD)mbi.BaseAddress + mbi.RegionSize;

	}


	std::vector<MEMORY_REGION>::iterator it;
	for (it = m_vMemoryRegion.begin(); it != m_vMemoryRegion.end(); it++)
	{
		MEMORY_REGION mData = *it;


		DWORD_PTR dwNumberOfBytesRead = 0;

		if (bIsCurrProcess)
		{
			pCurrMemoryData = (BYTE*)mData.dwBaseAddr;
			dwNumberOfBytesRead = mData.dwMemorySize;
		}
		else
		{

			pCurrMemoryData = new BYTE[mData.dwMemorySize];
			ZeroMemory(pCurrMemoryData, mData.dwMemorySize);
			ReadProcessMemory(phandle, (LPCVOID)mData.dwBaseAddr, pCurrMemoryData, mData.dwMemorySize, &dwNumberOfBytesRead);

			if ((int)dwNumberOfBytesRead <= 0)
			{
				delete[] pCurrMemoryData;
				continue;
			}
		}
		if (iSearchMode == 0)
		{
			DWORD_PTR dwOffset = 0;
			int iOffset = MemFind(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);
			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}
		}
		else if (iSearchMode == 1)
		{

			DWORD_PTR dwOffset = 0;
			int iOffset = SundaySearch(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);

			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}

		}

		if (!bIsCurrProcess && (pCurrMemoryData != NULL))
		{
			delete[] pCurrMemoryData;
			pCurrMemoryData = NULL;
		}

	}
	return TRUE;
}
inline bool exists(const std::string& name) {
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}

LONG GetDWORDRegKey(HKEY hKey, const std::wstring& strValueName, DWORD& nValue, DWORD nDefaultValue)
{
	nValue = nDefaultValue;
	DWORD dwBufferSize(sizeof(DWORD));
	DWORD nResult(0);
	LONG nError = ::RegQueryValueExW(hKey,
		strValueName.c_str(),
		0,
		NULL,
		reinterpret_cast<LPBYTE>(&nResult),
		&dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		nValue = nResult;
	}
	return nError;
}


LONG GetBoolRegKey(HKEY hKey, const std::wstring& strValueName, bool& bValue, bool bDefaultValue)
{
	DWORD nDefValue((bDefaultValue) ? 1 : 0);
	DWORD nResult(nDefValue);
	LONG nError = GetDWORDRegKey(hKey, strValueName.c_str(), nResult, nDefValue);
	if (ERROR_SUCCESS == nError)
	{
		bValue = (nResult != 0) ? true : false;
	}
	return nError;
}


LONG GetStringRegKey(HKEY hKey, const std::wstring& strValueName, std::wstring& strValue, const std::wstring& strDefaultValue)
{
	strValue = strDefaultValue;
	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		strValue = szBuffer;
	}
	return nError;
}


void StartDriver(LPCWSTR DriverName, LPCWSTR DriverPath)
{
	if (CheckDriver(DriverName) != 4)
	{
		wstring temp1(DriverPath);
		string DriverPath = string(temp1.begin(), temp1.end());
		wstring temp2(DriverName);
		string DriverName = string(temp2.begin(), temp2.end());
		UnloadDriver(DriverName.c_str());
		if (exists(DriverPath))
		{
			LoadDriver((PCHAR)DriverPath.c_str(), DriverName.c_str());
		}
		else
		{
			WriteResToDisk(DriverPath, MAKEINTRESOURCE(IDR_RCDATA3));
			LoadDriver((PCHAR)DriverPath.c_str(), DriverName.c_str());
		}
	}
}
bool FileExits(string namefile) {
	fstream my_file;
	my_file.open(namefile, ios::out);
	if (!my_file) {
		return false;
	}
	else {
		return true;
	}
}

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);

typedef LONG(WINAPI* RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);


void suspend(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
		GetModuleHandleA("ntdll"), "NtSuspendProcess");

	pfnNtSuspendProcess(processHandle);
	CloseHandle(processHandle);
}

typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);

typedef LONG(WINAPI* RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);

void resume(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(
		GetModuleHandleA("ntdll"), "NtResumeProcess");

	pfnNtResumeProcess(processHandle);
	CloseHandle(processHandle);
}

void WriteBytes(HANDLE phandle, DWORD addr, BYTE* write)
{
    DWORD size = sizeof(write);
    unsigned long OldProtect;
    unsigned long OldProtect2;
    VirtualProtectEx(phandle, (BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &OldProtect);
    WriteProcessMemory(phandle, (BYTE*)addr, write, size, NULL);
    VirtualProtectEx(phandle, (BYTE*)addr, size, OldProtect, &OldProtect2);
}


int AOBSCAN(HANDLE phandle, BYTE BypaRep[], SIZE_T size)
{
	std::vector<DWORD_PTR> FoundBase;
	MemSearch(phandle, BypaRep, size, 0x2600000, 0xB0000000, false, 0, FoundBase);

	if (FoundBase.size() != 0) {
		return FoundBase[0];
    }
}
//int AOBSCAN2(DWORD pid, BYTE BypaRep[], SIZE_T size)
//{
//	std::vector<DWORD_PTR> FoundBase;
//	MemSearch(phandle, pid, BypaRep, size, 0x0, 0xB0000000, false, 0, FoundBase);
//
//	if (FoundBase.size() != 0) {
//		return FoundBase[0];
//	}
//}

//int AOBRep(DWORD pid, BYTE* scan, BYTE* write) {
//    vector<DWORD_PTR> FoundBase;
//    MemSearch(phandle, pid, scan, sizeof(scan), 0x2600000, 0xB0000000, false, 0, FoundBase);
//
//    if (FoundBase.size() != 0) {
//
//        for (DWORD_PTR& address : FoundBase)
//        {
//            cout << "Write address: 0x" << address << hex << endl;
//            WriteBytes(pid, address, write);
//            
//        }
//    }
//    else {
//          cout << "no results found" << endl;
//    }
//    
//}

template <class dataType>
dataType ReadMemory(HANDLE phandle, DWORD addressToRead)
{
    dataType rpmbuffer;
    ReadProcessMemory(phandle, (PVOID)addressToRead, &rpmbuffer, sizeof(dataType), 0);

    return rpmbuffer;
}

DWORD GetUe4(HANDLE phandle)
{
    unsigned int libue4header = 0;
    BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x60, 0x10, 0x02, 0x34, 0x00, 0x00, 0x00, 0x48, 0xA5, 0x75, 0x08, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0D, 0x00, 0x28, 0x00, 0x1A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03 };
    libue4header = AOBSCAN(phandle, ue4head, sizeof(ue4head));
    return libue4header;
}

DWORD suit(HANDLE phandle) {
    BYTE suitPattern[] = { 0x41, 0x5D, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    DWORD suit = AOBSCAN(phandle, suitPattern, sizeof(suitPattern));
    cout << "Found and write 0x" << hex << suit << endl;
    return suit;
}

DWORD m416(HANDLE phandle) {
    BYTE m416Pattern[] = { 0xB0, 0x1E, 0x9A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    DWORD m416 = AOBSCAN(phandle, m416Pattern, sizeof(m416Pattern));
    cout << "Found and write 0x" << hex << m416 << endl;
    return m416;
}

DWORD m416_1(HANDLE phandle) {
    BYTE m416_1Pattern[] = { 0x70 ,0x09 ,0xBC ,0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    DWORD m416_1 = AOBSCAN(phandle, m416_1Pattern, sizeof(m416_1Pattern));
    cout << "Found and write 0x" << hex << m416_1 << endl;
    return m416_1;
}


DWORD m416_2(HANDLE phandle) {
    BYTE m416_2Pattern[] = { 0x00, 0xC4, 0x35, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    DWORD m416_2 = AOBSCAN(phandle, m416_2Pattern, sizeof(m416_2Pattern));
    cout << "Found and write 0x" << hex << m416_2 << endl;
    return m416_2;
}
DWORD m416_3(HANDLE phandle) {
    BYTE m416_3Pattern[] = { 0xE8, 0xCE, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    DWORD m416_3 = AOBSCAN(phandle, m416_3Pattern, sizeof(m416_3Pattern));
    cout << "Found and write 0x" << hex << m416_3 << endl;
    return m416_3;
}
DWORD m416_4(HANDLE phandle) {
    BYTE m416_4Pattern[] = { 0x14, 0xD0, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    DWORD m416_4 = AOBSCAN(phandle, m416_4Pattern, sizeof(m416_4Pattern));
    cout << "Found and write 0x" << hex << m416_4 << endl;
    return m416_4;
}


void Mod(HANDLE phandle, DWORD UE4) {
    cout << "Mod ready. Waitting new match..." << endl;
    while (true) {
        bool run = false;
        int lobby = ReadMemory<int>(phandle, UE4 + 0x8595D68);
        if (lobby == 0) {
            cout << " > Found new match" << endl;

            
            WriteBytes(phandle, m416(phandle), new  BYTE[]{ 0x0E, 0xFD, 0x9F, 0x41 });
            WriteBytes(phandle, m416_1(phandle), new  BYTE[]{ 0x8D, 0xFE, 0x33, 0x3C });
            WriteBytes(phandle, m416_2(phandle), new  BYTE[]{ 0x84, 0xFE, 0x33, 0x3C });
            WriteBytes(phandle, m416_3(phandle), new  BYTE[]{ 0x8F, 0xFE, 0x33, 0x3C });
            WriteBytes(phandle, m416_4(phandle), new  BYTE[]{ 0x8F, 0xFE, 0x33, 0x3C });
            WriteBytes(phandle, suit(phandle), new  BYTE[]{ 0x6F, 0x5F, 0x15 });
            cout << "Mod done! Wait new match..." << endl;
            while (true) {
                lobby = ReadMemory<int>(phandle, UE4 + 0x8595D68);
                if (lobby == 1) {
                    Mod(phandle, UE4);
                }
                Sleep(3000);
                continue;
            }
            
        }
        Sleep(1500);
    }
}


void OpenGame()
{
    StartDriver(L"AOWBP_1", L"C:\\AOWBP_1.sys");
	int procId = 0;
	while (true)
	{
		procId = gettrueaow();
		if (procId > 0) {
            ColorWrite1("", 10);
            cout << "Found game process id: " << procId << endl;
            break;
		}
		Sleep(500);
		continue;	
	}
    HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
    if (phandle == NULL) {
        cout << "Fail to attack process: " << procId << endl;
        system("pause");
    }
    else {
        DWORD UE4 = GetUe4(phandle);
        cout << "Found ue4 base address: 0x" << hex << UE4 << endl;
        Mod(phandle, UE4);
    }
   
}


int main()
{
    SetConsoleTitle(_T("HYDRA MOD | Discord: hanguyxn#7613"));
    g_Discord->Initialize();
    g_Discord->Update();
    OpenGame();
}

