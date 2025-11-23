#define WIN32_LEAN_AND_MEAN // 헤더 충돌 방지

#include <winsock2.h>
#include <windows.h>  
#include <urlmon.h>
#include <stdio.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")


void force_iat_references()
{

    volatile FARPROC pfnArray[20];
    int i = 0;

    pfnArray[i++] = (FARPROC)OpenProcess;
    pfnArray[i++] = (FARPROC)VirtualAllocEx;
    pfnArray[i++] = (FARPROC)WriteProcessMemory;
    pfnArray[i++] = (FARPROC)CreateRemoteThread;

    // [High] 룰 2: 키로깅
    pfnArray[i++] = (FARPROC)SetWindowsHookExA;
    pfnArray[i++] = (FARPROC)GetMessageA;

    // [Medium] 룰 3: 다운로더
    pfnArray[i++] = (FARPROC)URLDownloadToFileA;

    // [Medium] 룰 4: 봇/백도어
    pfnArray[i++] = (FARPROC)socket;
    pfnArray[i++] = (FARPROC)connect;

    // [Medium] 룰 5: 지속성 (레지스트리)
    pfnArray[i++] = (FARPROC)RegOpenKeyExA;
    pfnArray[i++] = (FARPROC)RegSetValueExA;

    // [Low] 룰 6: 동적 로드 (분석 회피)
    pfnArray[i++] = (FARPROC)LoadLibraryA;
    pfnArray[i++] = (FARPROC)GetProcAddress;

    // [Low] 룰 7: 디버거 탐지 (분석 회피)
    pfnArray[i++] = (FARPROC)IsDebuggerPresent;
}


int main()
{
    printf("=========================================\n");
    printf("  Benign Test File for PE Analyzer (v3)\n");
    printf("  This file is built to import 'dangerous' APIs\n");
    printf("  It does NOT perform any malicious actions.\n");
    printf("=========================================\n");
    force_iat_references();
    
    return 0;
}


