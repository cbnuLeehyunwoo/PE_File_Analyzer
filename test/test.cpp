// [최종 수정본]
// 
#define WIN32_LEAN_AND_MEAN // 헤더 충돌 방지

#include <winsock2.h> // 1. winsock2.h
#include <windows.h>  // 2. windows.h (순서 중요)
#include <urlmon.h>
#include <stdio.h>

// 라이브러리 링킹
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")

/*
  [최종 테스트 코드]
  
  컴파일러 최적화를 완벽하게 무시하기 위해,
  함수 포인터(주소)를 'volatile' 배열에 저장합니다.
  'volatile' 키워드는 컴파일러가 해당 메모리 접근을
  절대로 최적화(삭제)하지 못하도록 강제합니다.
*/
void force_iat_references()
{
    // FARPROC은 Windows.h에 정의된 '함수 포인터'의 일반적인 타입입니다.
    // volatile 키워드로 컴파일러가 이 배열을 최적화하지 못하게 막습니다.
    volatile FARPROC pfnArray[20];
    int i = 0;

    // [High] 룰 1: 프로세스 인젝션
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

    // 함수가 최적화로 삭제되는 것을 막기 위해 명시적으로 호출
    force_iat_references();
    
    return 0;
}


