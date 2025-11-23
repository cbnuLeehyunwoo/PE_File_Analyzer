import pefile
import json
import os
import math
import joblib
import numpy as np
from collections import Counter

# --- ML 라이브러리 로드 시도 (없어도 실행 가능하도록 처리) ---
try:
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("⚠️ scikit-learn 미설치: ML 기능이 비활성화됩니다. (pip install scikit-learn)")

class PEAnalyzer:
    def __init__(self, rules_file='rules.json', model_path='pe_model.pkl'):
        """
        초기화 단계: 시그니처 룰 로드 및 ML 모델 준비
        """
        self.rules = []
        self.model_path = model_path
        
        # 1. 룰 파일 로드
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    self.rules = json.load(f).get('signatures', [])
            except Exception as e:
                print(f"[!] 룰 로드 실패: {e}")
        
        # 2. ML 모델 초기화 (Layer 3)
        self.model = None
        if ML_AVAILABLE:
            self.load_or_train_model()

    def _calculate_entropy(self, data):
        """Layer 1: 섀넌 엔트로피 계산 (무작위성 측정)"""
        if not data: return 0.0
        occ = Counter(data)
        length = len(data)
        return -sum((c/length) * math.log2(c/length) for c in occ.values())

    def load_or_train_model(self):
        """ML 모델 로드 또는 데모용 즉석 학습"""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                return
            except: pass

        # 모델이 없으면 데모 데이터로 학습 (보고서용 데모 로직)
        # Features: [AvgEntropy, Sections, Imports, Ratio, SuspiciousName]
        print("[*] 학습된 모델이 없어 데모 데이터로 학습을 진행합니다...")
        X = [
            [4.5, 5, 120, 0.95, 0], # 정상 예시
            [5.2, 4, 80, 0.98, 0],  # 정상 예시
            [7.8, 8, 5, 0.2, 1],    # 악성 예시 (고엔트로피, 적은 임포트)
            [7.2, 3, 10, 0.1, 1]    # 악성 예시
        ]
        y = [0, 0, 1, 1] # 0:정상, 1:악성
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.model.fit(X, y)
        joblib.dump(self.model, self.model_path)

    def extract_ml_features(self, pe):
        """ML 분석을 위한 특징 벡터 추출"""
        # 1. 엔트로피 특징
        entropies = [self._calculate_entropy(s.get_data()) for s in pe.sections]
        avg_entropy = sum(entropies)/len(entropies) if entropies else 0
        
        # 2. 임포트 함수 개수
        num_imports = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                num_imports += len(entry.imports)
        
        # 3. 데이터 비율 (Raw vs Virtual)
        ratios = [s.SizeOfRawData / s.Misc_VirtualSize for s in pe.sections if s.Misc_VirtualSize > 0]
        avg_ratio = sum(ratios)/len(ratios) if ratios else 0
        
        # 4. 의심스러운 섹션명
        suspicious_names = ['UPX', '.packed', '.aspack', 'FSG', 'TE']
        has_suspicious = 0
        for sec in pe.sections:
            sec_name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
            if any(s in sec_name for s in suspicious_names):
                has_suspicious = 1
                break
        
        return [avg_entropy, len(pe.sections), num_imports, avg_ratio, has_suspicious]

    def analyze_file(self, filepath):
        """
        [핵심 로직] 3-Layer 분석 수행
        Layer 1: 엔트로피 -> Layer 2: 정적 분석(Rule) -> Layer 3: ML 예측
        """
        report = {
            "filename": os.path.basename(filepath),
            "threats": [],
            "risk_score": 0,
            "risk_details": [],
            "ml_probability": -1, 
            "ml_features": [],
            "status": "clean"
        }

        if not os.path.exists(filepath):
            report["error"] = "파일을 찾을 수 없습니다."
            return report

        try:
            pe = pefile.PE(filepath)
            
            # === Layer 1 & 2: 엔트로피 및 정적 분석 ===
            score = 0
            details = []
            
            # [1] 섹션 분석
            for sec in pe.sections:
                e = self._calculate_entropy(sec.get_data())
                name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                # Layer 1: 엔트로피 기반 탐지
                if e > 7.2:
                    score += 30
                    details.append(f"높은 엔트로피 감지: {name} ({e:.2f}) - 패킹/암호화 의심")
                
                # Layer 2: 정적 시그니처 (섹션명)
                if 'UPX' in name.upper():
                    score += 20
                    details.append(f"알려진 패커 섹션 발견: {name}")

            # [2] IAT(Import Address Table) 분석 (보완된 로직)
            iat_apis = set()
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                iat_apis.add(imp.name.decode('utf-8', errors='ignore'))
                    
                    # API가 너무 적으면 패킹 의심
                    if len(iat_apis) < 10:
                        score += 20
                        details.append(f"임포트 API 부족 ({len(iat_apis)}개) - 정보 은닉 의심")
            except Exception as e:
                # IAT 파싱 실패 시 높은 가산점 (Anti-Analysis 기법 대응)
                score += 50
                details.append(f"IAT 파싱 치명적 오류 (손상된 헤더): {str(e)}")

            # [3] 사용자 정의 룰 매칭 (Layer 2)
            for rule in self.rules:
                if set(rule['apis']).issubset(iat_apis):
                    report["threats"].append(rule['name'])
                    score += rule.get('score', 10)
                    details.append(f"악성 행위 시그니처 탐지: {rule['name']}")

            report["risk_score"] = min(score, 100)
            report["risk_details"] = details

            # === Layer 3: Machine Learning 예측 ===
            if self.model and ML_AVAILABLE:
                try:
                    feats = self.extract_ml_features(pe)
                    # 악성(1)일 확률 계산
                    prob = self.model.predict_proba([feats])[0][1] * 100
                    report["ml_probability"] = round(prob, 2)
                    report["ml_features"] = feats
                except Exception as e:
                    details.append(f"ML 분석 중 오류: {e}")

            # === 종합 판정 ===
            # 정적 분석 점수가 높거나 ML 확률이 높으면 위험으로 판단
            if report["risk_score"] >= 60 or report["ml_probability"] > 75:
                report["status"] = "danger"
            elif report["risk_score"] >= 30 or report["ml_probability"] > 45:
                report["status"] = "warning"

            pe.close()
            return report

        except Exception as e:
            report["error"] = f"PE 파일 분석 실패: {str(e)}"
            return report

# --- 실행 테스트 코드 ---
if __name__ == "__main__":
    # 1. 테스트용 룰 파일 생성 (없을 경우)
    if not os.path.exists("rules.json"):
        dummy_rules = {
            "signatures": [
                {"name": "Process Injection", "apis": ["VirtualAllocEx", "WriteProcessMemory"], "score": 20},
                {"name": "Keylogging", "apis": ["GetAsyncKeyState", "SetWindowsHookExA"], "score": 15}
            ]
        }
        with open("rules.json", "w") as f:
            json.dump(dummy_rules, f)
        print("[*] 테스트용 rules.json 생성됨")

    # 2. 분석기 초기화
    analyzer = PEAnalyzer()
    
    # 3. 분석할 파일 경로 (현재 실행 중인 자기 자신을 분석하거나, 특정 exe 경로 입력)
    # 예: target_file = "C:\\Windows\\System32\\calc.exe"
    import sys
    target_file = sys.executable # 현재 파이썬 인터프리터를 테스트로 분석
    
    print(f"\n[*] 분석 시작: {target_file}")
    result = analyzer.analyze_file(target_file)
    
    print(json.dumps(result, indent=2, ensure_ascii=False))