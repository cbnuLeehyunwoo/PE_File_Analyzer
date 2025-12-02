import pefile
import json
import os
import math
import joblib
import sys
from collections import Counter

# ML 라이브러리 임포트 확인 및 변수 설정
try:
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    print("[!] scikit-learn이 설치되지 않았습니다. ML 기능이 비활성화됩니다.")
    print("[!] pip install scikit-learn 명령어로 설치해주세요.")
    ML_AVAILABLE = False
    RandomForestClassifier = None

class PEAnalyzer:
    def __init__(self, rules_file='rules.json', yara_file=None, model_path='pe_model.pkl'):
        self.rules = []
        self.model_path = model_path
        self.yara_file = yara_file 
        
        # 1. 룰 파일 로드
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    self.rules = json.load(f).get('signatures', [])
            except Exception as e:
                print(f"[!] 룰 로드 실패: {e}")
        
        # 2. ML 모델 초기화
        self.model = None
        if ML_AVAILABLE:
            self.load_or_train_model()

    def _calculate_entropy(self, data):
        """기본 섀넌 엔트로피 계산 (0.0 ~ 8.0)"""
        if not data: return 0.0
        occ = Counter(data)
        length = len(data)
        return -sum((c/length) * math.log2(c/length) for c in occ.values())

    def _calculate_sliding_window_entropy(self, data, window_size=256, step=128):
        """슬라이딩 윈도우 엔트로피 분석"""
        if not data or len(data) < window_size:
            return 0.0, []

        max_entropy = 0.0
        entropy_trace = []
        
        if len(data) > 1024 * 1024:  # 1MB 이상 최적화
            step = 1024

        for i in range(0, len(data) - window_size, step):
            chunk = data[i:i + window_size]
            entropy = self._calculate_entropy(chunk)
            entropy_trace.append(entropy)
            if entropy > max_entropy:
                max_entropy = entropy
        
        return max_entropy, entropy_trace

    def load_or_train_model(self, force_retrain=False):
        """데모용 ML 모델 학습 (force_retrain=True일 경우 무조건 새로 학습)"""
        
        # 강제 재학습이 아니고 파일이 있으면 로드 시도
        if not force_retrain and os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                return
            except: pass

        if not ML_AVAILABLE:
            return

        print("[*] 새 모델 학습을 진행합니다...")
        
        # 기존 파일이 있다면 삭제 (충돌 방지)
        if os.path.exists(self.model_path):
            try:
                os.remove(self.model_path)
            except: pass

        # Feature: [AvgEntropy, MaxLocalEntropy, NumSections, NumImports, Ratio]
        # (현재 코드의 extract_ml_features가 5개를 반환하므로 학습 데이터도 5개여야 함)
        X = [
            [4.5, 4.8, 5, 120, 0.95], # 정상
            [5.2, 5.5, 4, 80, 0.98],  # 정상
            [7.8, 7.9, 8, 5, 0.2],    # 악성
            [4.2, 7.9, 6, 10, 0.4]    # 악성 (저엔트로피 패커)
        ]
        y = [0, 0, 1, 1] 
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.model.fit(X, y)
        try:
            joblib.dump(self.model, self.model_path)
            print("[*] 모델 저장 완료")
        except Exception as e:
            print(f"[!] 모델 저장 실패: {e}")

    def extract_ml_features(self, pe):
        """ML 입력용 특징 벡터 추출 (5개 Feature)"""
        # 1. 엔트로피
        total_data = b''
        for sec in pe.sections:
            total_data += sec.get_data()
            
        avg_entropy = self._calculate_entropy(total_data)
        max_local, _ = self._calculate_sliding_window_entropy(total_data, step=1024)
        
        # 2. 임포트 개수
        num_imports = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                num_imports += len(entry.imports)
        
        # 3. 데이터 비율
        ratios = [s.SizeOfRawData / s.Misc_VirtualSize for s in pe.sections if s.Misc_VirtualSize > 0]
        avg_ratio = sum(ratios)/len(ratios) if ratios else 0
        
        return [avg_entropy, max_local, len(pe.sections), num_imports, avg_ratio]

    def analyze_file(self, filepath):
        """분석 파이프라인"""
        report = {
            "filename": os.path.basename(filepath),
            "risk_score": 0,
            "status": "clean",
            "detection_log": [],
            "section_details": [],
            "ml_probability": 0,
            "ml_features": [0, 0, 0, 0, 0]
        }

        if not os.path.exists(filepath):
            report["error"] = "파일 없음"
            return report

        try:
            pe = pefile.PE(filepath)
            score = 0
            
            # === Step 1: 심층 엔트로피 분석 ===
            for sec in pe.sections:
                sec_name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
                sec_data = sec.get_data()
                
                avg_e = self._calculate_entropy(sec_data)
                max_local_e, _ = self._calculate_sliding_window_entropy(sec_data)
                
                sec_info = {
                    "name": sec_name,
                    "avg_entropy": round(avg_e, 2),
                    "max_local_entropy": round(max_local_e, 2)
                }
                report["section_details"].append(sec_info)

                if avg_e > 7.2:
                    score += 20
                    report["detection_log"].append(f"[Step1] 고엔트로피 섹션 발견: {sec_name} (Avg: {avg_e:.2f})")
                
                elif avg_e < 6.0 and max_local_e > 7.8:
                    score += 40
                    report["detection_log"].append(f"[Step1] 은닉된 암호화 패턴 감지: {sec_name} (Max Local: {max_local_e:.2f})")

            # === Step 2: IAT 및 룰 분석 ===
            iat_apis = set()
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                iat_apis.add(imp.name.decode('utf-8', errors='ignore'))
                    
                    if len(iat_apis) < 5:
                        score += 30
                        report["detection_log"].append(f"[Step2] IAT API 부족 ({len(iat_apis)}개) - 임포트 은닉 의심")
            except:
                score += 50
                report["detection_log"].append("[Step2] IAT 파싱 실패 - 헤더 손상 의심")

            for rule in self.rules:
                if set(rule['apis']).issubset(iat_apis):
                    score += rule.get('score', 10)
                    report["detection_log"].append(f"[Step2] 악성 행위 룰 매칭: {rule['name']}")

            report["risk_score"] = min(score, 100)

            # === Step 3: ML 예측 (자동 복구 로직 추가) ===
            if self.model and ML_AVAILABLE:
                try:
                    feats = self.extract_ml_features(pe)
                    report["ml_features"] = feats
                    
                    try:
                        # 예측 시도
                        prob = self.model.predict_proba([feats])[0][1] * 100
                    except ValueError as ve:
                        # [오류 해결 핵심] 차원 불일치(22 features vs 5 features) 발생 시
                        print(f"[!] 모델 차원 불일치 감지({ve}). 모델 재학습을 수행합니다...")
                        self.load_or_train_model(force_retrain=True)
                        # 재학습 후 다시 예측
                        prob = self.model.predict_proba([feats])[0][1] * 100

                    report["ml_probability"] = round(prob, 2)
                    
                    if prob > 80:
                        report["detection_log"].append(f"[Step3] ML 모델 고위험 예측 ({prob:.1f}%)")
                except Exception as e:
                    print(f"ML Final Error: {e}")
            else:
                try:
                    report["ml_features"] = self.extract_ml_features(pe)
                except: pass

            # 최종 상태 결정
            if report["risk_score"] >= 60 or report["ml_probability"] > 80:
                report["status"] = "DANGER (악성 의심)"
            elif report["risk_score"] >= 30 or report["ml_probability"] > 50:
                report["status"] = "WARNING (주의)"
            
            pe.close()
            return report

        except Exception as e:
            report["error"] = str(e)
            return report

if __name__ == "__main__":
    if not os.path.exists("rules.json"):
        with open("rules.json", "w") as f:
            json.dump({"signatures": [{"name": "Injection", "apis": ["VirtualAlloc", "CreateRemoteThread"], "score": 30}]}, f)

    analyzer = PEAnalyzer()
    target = sys.executable 
    print(f"[*] 분석 대상: {target}")
    res = analyzer.analyze_file(target)
    print(json.dumps(res, indent=2, ensure_ascii=False))