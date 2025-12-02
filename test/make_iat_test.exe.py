import lief
import os
import sys

MALWARE_CONFIG = {
    "kernel32.dll": [
        "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", 
        "VirtualProtect", "VirtualAlloc", 
        "DeleteFileA", "MoveFileExA", 
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "GetTickCount"
    ],
    "user32.dll": [
        "SetWindowsHookExA", "GetAsyncKeyState", 
        "GetDC"
    ],
    "gdi32.dll": [
        "BitBlt"
    ],
    "advapi32.dll": [
        "RegCreateKeyExA", "RegSetValueExA", 
        "AdjustTokenPrivileges", "OpenProcessToken",
        "CreateServiceA", "StartServiceA"
    ],
    "urlmon.dll": [
        "URLDownloadToFileA", "URLDownloadToFileW"
    ],
    "wininet.dll": [
        "InternetOpenA", "InternetOpenUrlA"
    ]
}

def generate_malware(output_filename="test_malware_gen.exe"):
    template_path = sys.executable 
    print(f"[*] 템플릿 복제 중: {template_path} -> {output_filename}")

    try:
        # 1. LIEF로 파이썬 실행파일 파싱
        binary = lief.PE.parse(template_path)
        if binary is None:
            print("[!] 오류: 템플릿 파일을 파싱할 수 없습니다.")
            return

        # 2. 악성 API 주입
        print(f"[*] 악성 API 주입 중... (총 {sum(len(v) for v in MALWARE_CONFIG.values())}개)")
        
        for dll_name, functions in MALWARE_CONFIG.items():
            lib = binary.add_import(dll_name)
            for func in functions:
                lib.add_entry(func)

        # 3. Builder 설정 
        config = lief.PE.Builder.config_t()
        config.imports = True
        
        # 4. 빌더 생성 및 저장
        builder = lief.PE.Builder(binary, config)
        builder.build()
        builder.write(output_filename)
        
        print(f"[+] 생성 완료: {os.path.abspath(output_filename)}")

    except Exception as e:
        print(f"[!] 생성 중 에러 발생: {e}")

if __name__ == "__main__":
    output = "test_malware_gen.exe"
    if len(sys.argv) > 1:
        output = sys.argv[1]
    
    generate_malware(output)