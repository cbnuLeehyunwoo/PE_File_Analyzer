import pefile
import json
import sys
import os

class PEAnalyzer:
    """
    PE 파일의 IAT를 분석하여 잠재적 위협 행위를 예측하는 도구
    """

    def __init__(self, rules_file):
        """
        분석기 초기화 시, 위협 행위 룰을 로드합니다.
        """
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                self.rules = json.load(f)['signatures']
            print(f"✅ {len(self.rules)}개의 위협 시그니처를 로드했습니다.\n")
        except FileNotFoundError:
            print(f"[오류] 룰 파일({rules_file})을 찾을 수 없습니다.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"[오류] 룰 파일({rules_file})의 형식이 올바르지 않습니다.")
            sys.exit(1)

    def parse_iat(self, filepath):
        """
        PE 파일의 IAT를 파싱하여 {DLL: [API1, API2, ...]} 딕셔너리를 반환합니다.
        (수정됨: finally 블록에서 pe.close()를 호출하여 파일 핸들을 해제)
        """
        iat_info = {}
        imported_apis = set()
        pe = None

        try:
            pe = pefile.PE(filepath)
            
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                print("⚠️  임포트 테이블(IAT)을 찾을 수 없습니다. (패킹된 파일 가능성)")
                return {}, set()

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8').lower()
                apis = []
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8')
                        apis.append(api_name)
                        imported_apis.add(api_name)
                
                iat_info[dll_name] = apis
            
            return iat_info, imported_apis

        except pefile.PEFormatError as e:
            print(f"[오류] 유효한 PE 파일이 아닙니다: {e}")
            # ★★★ 웹 앱과의 연동을 위해 에러를 다시 발생시켜 app.py에서 잡도록 함
            raise
        except Exception as e:
            print(f"[오류] 파일 파싱 중 예외 발생: {e}")
            raise
        finally:
            if pe:
                pe.close()
    
    # ↓↓↓ 들여쓰기를 수정하여 클래스 안으로 넣었습니다. ↓↓↓
    def analyze_file(self, filepath):
        """
        파일의 IAT와 룰을 매칭하여 위협 리포트를 생성합니다. (수정됨: 결과를 반환)
        """
        if not os.path.exists(filepath):
            print(f"[오류] 분석할 파일({filepath})을 찾을 수 없습니다.")
            return os.path.basename(filepath), []

        iat_info, imported_apis = self.parse_iat(filepath)

        if not imported_apis:
            print("⚠️  임포트된 API가 없습니다.")
            return os.path.basename(filepath), []

        detected_threats = []
        for rule in self.rules:
            rule_apis = set(rule['apis'])
            if imported_apis.issuperset(rule_apis):
                detected_threats.append(rule)

        danger_order = {"High": 3, "Medium": 2, "Low": 1}
        sorted_threats = sorted(
            detected_threats, 
            key=lambda x: danger_order.get(x['danger'], 0), 
            reverse=True
        )
        
        return os.path.basename(filepath), sorted_threats
    
    # ↓↓↓ 들여쓰기를 수정하여 클래스 안으로 넣었습니다. ↓↓↓
    def print_report(self, filename, detected_threats):
        """
        분석 결과를 포맷에 맞춰 출력합니다.
        """
        print(f"\n--- [ {filename} ] 최종 분석 리포트 ---")

        if not detected_threats:
            print("✅ 특이한 위협 행위가 발견되지 않았습니다. (정상 파일 가능성 높음)")
            print("========================================")
            return

        danger_order = {"High": 3, "Medium": 2, "Low": 1}
        sorted_threats = sorted(
            detected_threats, 
            key=lambda x: danger_order.get(x['danger'], 0), 
            reverse=True
        )

        print(f"🚨 총 {len(sorted_threats)}개의 잠재적 위협 행위가 탐지되었습니다.")
        
        for threat in sorted_threats:
            print("\n" + ("-"*30))
            print(f"  위협명: {threat['name']} (위험도: {threat['danger']})")
            print(f"  설명: {threat['description']}")
            print(f"  근거 API: {', '.join(threat['apis'])}")
            
        print("\n========================================")


# --- 스크립트 실행 (이 부분은 웹 앱과 무관, 단독 실행 시에만 사용됨) ---
if __name__ == "__main__":
    RULES_JSON_PATH = "rules.json"
    analyzer = PEAnalyzer(RULES_JSON_PATH)

    if len(sys.argv) < 2:
        print("\n[사용법] python pe_analyzer.py <분석할_파일.exe>")
        print("\n[테스트] 윈도우 계산기(calc.exe)를 분석합니다...")
        filename, results = analyzer.analyze_file(r"C:\Windows\System32\calc.exe")
        analyzer.print_report(filename, results) # 결과를 받아서 출력하도록 수정
    else:
        target_file = sys.argv[1]
        filename, results = analyzer.analyze_file(target_file)
        analyzer.print_report(filename, results) # 결과를 받아서 출력하도록 수정