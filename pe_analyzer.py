import pefile
import json
import os
import math
import joblib
import sys
import numpy as np
from collections import Counter

# ML 라이브러리 확인
try:
    from sklearn.ensemble import RandomForestClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class PEAnalyzer:
    def __init__(self, rules_file='rules.json', model_path='pe_model.pkl'):
        self.rules = []
        self.model_path = model_path
        self.model = None

        # 1. 룰 로드
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r', encoding='utf-8') as f:
                    self.rules = json.load(f).get('signatures', [])
            except: pass
        
        # 2. ML 모델 로드
        if ML_AVAILABLE:
            if os.path.exists(self.model_path):
                try:
                    self.model = joblib.load(self.model_path)
                except:
                    self.train_dummy_model_22()
            else:
                self.train_dummy_model_22()

    def train_dummy_model_22(self):
        if not ML_AVAILABLE: return
        print("[*] 22개 특징 전용 모델을 새로 생성합니다...")
        X = [[0.0]*22, [1.0]*22]
        y = [0, 1]
        clf = RandomForestClassifier(n_estimators=10, random_state=42)
        clf.fit(X, y)
        joblib.dump(clf, self.model_path)
        self.model = clf

    def _calculate_entropy(self, data):
        if not data: return 0.0
        occ = Counter(data)
        length = len(data)
        return -sum((c/length) * math.log2(c/length) for c in occ.values())

    def _calculate_max_window_entropy(self, data, window_size=1024, step=512):
        """[복구됨] 슬라이딩 윈도우 엔트로피 (Window > 7.5 감지용)"""
        if not data or len(data) < window_size:
            return self._calculate_entropy(data)
        
        max_entropy = 0.0
        # 속도를 위해 데이터가 너무 크면 step을 늘림
        if len(data) > 5 * 1024 * 1024: step = 4096 
        
        for i in range(0, len(data) - window_size, step):
            chunk = data[i:i + window_size]
            entropy = self._calculate_entropy(chunk)
            if entropy > max_entropy:
                max_entropy = entropy
                if max_entropy > 7.99: break 
        
        return max_entropy

    def _has_digital_signature(self, pe):
        try:
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            return security_dir.VirtualAddress != 0 and security_dir.Size > 0
        except:
            return False

    def extract_features_22(self, pe, raw_data):
        """ML 입력용 22개 특징 추출"""
        try:
            vec = []
            # [1] Byte Stats (4)
            arr = np.frombuffer(raw_data, dtype=np.uint8)
            vec.extend([np.mean(arr), np.std(arr), np.max(arr), np.min(arr)])
            # [2] Entropy (4)
            counts = np.bincount(arr, minlength=256)
            probs = counts[counts > 0] / len(arr)
            ent = -np.sum(probs * np.log2(probs))
            vec.extend([ent, 0, ent, ent])
            # [3] General (6)
            vsize = sum(s.Misc_VirtualSize for s in pe.sections)
            n_imp = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            n_exp = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
            has_sig = 1 if self._has_digital_signature(pe) else 0
            has_tls = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS else 0
            vec.extend([len(raw_data), vsize, n_imp, n_exp, has_sig, has_tls])
            # [4] Sections (4)
            entropies = [s.get_entropy() for s in pe.sections]
            sizes = [len(s.get_data()) for s in pe.sections]
            vsizes = [s.Misc_VirtualSize for s in pe.sections]
            if entropies:
                vec.extend([np.mean(entropies), np.max(entropies), np.mean(sizes), np.mean(vsizes)])
            else:
                vec.extend([0.0]*4)
            # [5] Imports (3) & Exports (1)
            vec.extend([0.0, 0.0, 0.0, float(n_exp)])
            
            if len(vec) < 22: vec.extend([0]*(22-len(vec)))
            return vec[:22]
        except:
            return [0]*22

    def analyze_file(self, filepath):
        report = {
            "filename": os.path.basename(filepath),
            "status": "CLEAN",
            "risk_score": 0,
            "entropy_info": {"avg": 0.0, "max_local": 0.0},
            "detection_log": [],
            "ml_probability": -1
        }

        if not os.path.exists(filepath):
            report["error"] = "파일 없음"
            return report

        try:
            raw_data = open(filepath, 'rb').read()
            pe = pefile.PE(data=raw_data)
        except Exception as e:
            report["error"] = f"PE 파싱 실패: {e}"
            return report

        score = 0
        has_signature = self._has_digital_signature(pe)

        # 1. 파일 전체 엔트로피
        avg_entropy = self._calculate_entropy(raw_data)
        
        # 2. 슬라이딩 윈도우 (Window) > 7.5 확인
        max_window_entropy = self._calculate_max_window_entropy(raw_data)

        report["entropy_info"]["avg"] = round(avg_entropy, 2)
        report["entropy_info"]["max_local"] = round(max_window_entropy, 2)

        # 기준 1: 파일 전체 > 7.2
        if avg_entropy > 7.2:
            if not has_signature:
                score += 20
                report["detection_log"].append(f"[Entropy] 파일 전체 엔트로피 과도({avg_entropy:.2f}) - 전체 패킹 의심")

        # 기준 2: 슬라이딩 윈도우 > 7.5
        if max_window_entropy > 7.5:
             if not has_signature:
                score += 30
                report["detection_log"].append(f"[Entropy] 국소 영역 엔트로피 초과({max_window_entropy:.2f}) - 암호화된 페이로드 은닉 가능성")

        # 기준 3: 섹션별 정밀 검사 (.text > 6.8 / .rsrc > 7.4)
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_ent = section.get_entropy()
            
            if ".text" in sec_name.lower() and sec_ent > 6.8:
                score += 20
                report["detection_log"].append(f"[Entropy] .text 섹션 엔트로피 높음({sec_ent:.2f}) - 코드 영역 패킹 의심")
            
            elif ".rsrc" in sec_name.lower() and sec_ent > 7.4:
                score += 10
                report["detection_log"].append(f"[Entropy] .rsrc 섹션 엔트로피 높음({sec_ent:.2f}) - 리소스 내 데이터 은닉 의심")

        iat_apis = set()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        iat_apis.add(imp.name.decode('utf-8', errors='ignore'))
        
        for rule in self.rules:
            rule_apis = set(rule['apis'])
            matched = rule_apis.intersection(iat_apis)
            
            threshold = max(2, len(rule_apis) * 0.5)
            if len(rule_apis) == 1: threshold = 1
            
            if len(matched) >= threshold:
                danger_map = {"High": 50, "Medium": 30, "Low": 10}
                s_val = danger_map.get(rule.get("danger", "Low"), 10)
                
                ratio = len(matched) / len(rule_apis)
                final_rule_score = int(s_val * (0.5 + ratio))
                score += final_rule_score
                report["detection_log"].append(f"[Rule] {rule['name']} 패턴 발견 ({len(matched)}개 API 일치)")

        if self.model:
            try:
                feats = self.extract_features_22(pe, raw_data)
                prob = self.model.predict_proba([feats])[0][1] * 100
                report["ml_probability"] = round(prob, 2)
                
                if prob > 80:
                    report["detection_log"].append(f"[ML] 악성 확률 매우 높음 ({prob:.1f}%)")
                    score += int(prob * 0.5)
            except: pass

        # 서명 있으면 점수 감경 (오탐 방지)
        if has_signature and score < 60:
            score = int(score * 0.2)
            report["detection_log"].append("[Info] 디지털 서명이 확인되어 위험도가 하향 조정되었습니다.")

        report["risk_score"] = min(score, 100)
        
        if report["risk_score"] >= 80: report["status"] = "DANGER"
        elif report["risk_score"] >= 40: report["status"] = "WARNING"
        else: report["status"] = "CLEAN"

        pe.close()
        return report

if __name__ == "__main__":
    analyzer = PEAnalyzer()
    # 테스트용
    target = sys.executable 
    if len(sys.argv) > 1: target = sys.argv[1]
    res = analyzer.analyze_file(target)
    print(json.dumps(res, indent=2, ensure_ascii=False))