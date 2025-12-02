import os
import shutil
import random

# 1. 윈도우 계산기(calc.exe)를 기반으로 사용
system_calc = r"C:\Windows\System32\calc.exe"
# 만약 calc.exe 접근 권한 문제가 생기면 python.exe를 사용하세요
if not os.path.exists(system_calc):
    system_calc = sys.executable 

print(f"[*] 원본 파일 복사 중: {system_calc}")

# --- CASE 1: 정상 파일 (Normal) ---
shutil.copy(system_calc, "test_normal.exe")
print("[+] 'test_normal.exe' 생성 완료 (정상)")

# --- CASE 2: 고엔트로피 파일 (High Entropy - Simulated) ---
with open("test_packed.exe", "wb") as f:
    # 원본 데이터 일부
    with open(system_calc, "rb") as org:
        f.write(org.read())
    # 고엔트로피 데이터 (Random Bytes) 추가
    f.write(os.urandom(1024 * 1024 * 2)) # 2MB Random Data
print("[+] 'test_packed.exe' 생성 완료 (전체 고엔트로피)")

# --- CASE 3: 저엔트로피 은닉 파일 (Hidden Payload / Low Avg Entropy) ---
# 시나리오: [정상 코드] + [암호화된 쉘코드(고엔트로피)] + [엄청난 00패딩(저엔트로피)]
with open("test_hidden.exe", "wb") as f:
    # 1. 원본 데이터
    with open(system_calc, "rb") as org:
        f.write(org.read())
    
    # 2. 은닉된 악성 코드 시뮬레이션 (고엔트로피 구간 - 50KB)
    hidden_payload = os.urandom(1024 * 50) 
    f.write(hidden_payload)
    # 0을 잔뜩 채워서 전체 평균 엔트로피를 4~5점으로 떨어뜨림
    f.write(b'\x00' * (1024 * 1024 * 5)) 

print("[+] 'test_hidden.exe' 생성 완료 (저엔트로피 패커 시뮬레이션)")
print("\n[*] 준비 완료! 이제 분석기를 돌려보세요.")