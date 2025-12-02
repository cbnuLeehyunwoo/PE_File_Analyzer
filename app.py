import os
import sys
import json
import joblib
import pefile
import numpy as np
import traceback
from flask import Flask, request, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)

# [경로 설정] 현재 app.py가 있는 폴더 기준 절대 경로
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
MODEL_PATH = os.path.join(BASE_DIR, "pe_model.pkl")
RULES_PATH = os.path.join(BASE_DIR, "rules.json")

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ML_MODEL = None

print(f"[*] 모델 경로 확인: {MODEL_PATH}")

if os.path.exists(MODEL_PATH):
    try:
        # 파일 로드 시도
        ML_MODEL = joblib.load(MODEL_PATH)
        print(f"[+] ML 모델 로드 성공!")
    except Exception as e:
        print("\n" + "="*50)
        print("[!!!!] 모델 로드 실패 (치명적 에러)")
        print(f"에러 내용: {e}")
        print("-" * 20)
        traceback.print_exc() 
        print("="*50 + "\n")
        print(">> 주의: scikit-learn 버전이 모델을 만든 환경과 다르면 로드되지 않습니다.")
        print(">> 모델 로드 실패로 인해 ML 예측 기능은 비활성화됩니다.")
        ML_MODEL = None
else:
    print(f"[!!!!] 모델 파일이 없습니다: {MODEL_PATH}")
    print(">> 루트 디렉토리에 pe_model.pkl 파일이 있는지 확인해주세요.")


class PEAnalyzer:
    def __init__(self, model, rules_path):
        self.model = model
        self.rules = []
        if os.path.exists(rules_path):
            try:
                with open(rules_path, 'r', encoding='utf-8') as f:
                    self.rules = json.load(f).get('signatures', [])
                print(f"[+] 룰 파일 로드 성공 ({len(self.rules)}개)")
            except Exception as e:
                print(f"[!] 룰 파일 로드 에러: {e}")

    def extract_features_22(self, raw_data, pe):
        try:
            vec = []
            # 1. Byte Stats
            arr = np.frombuffer(raw_data, dtype=np.uint8)
            vec.extend([np.mean(arr), np.std(arr), np.max(arr), np.min(arr)])
            # 2. Entropy
            counts = np.bincount(arr, minlength=256)
            probs = counts[counts > 0] / len(arr)
            ent = -np.sum(probs * np.log2(probs))
            vec.extend([ent, 0, ent, ent]) 
            # 3. General
            vsize = sum(s.Misc_VirtualSize for s in pe.sections)
            n_imp = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            n_exp = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
            vec.extend([len(raw_data), vsize, n_imp, n_exp, 0, 0])
            # 4. Sections
            entropies = [s.get_entropy() for s in pe.sections]
            vec.extend([np.mean(entropies), np.max(entropies), 0, 0])
            # 5. Imports & Exports
            vec.extend([0, 0, 0, n_exp])
            
            if len(vec) < 22: vec.extend([0]*(22-len(vec)))
            return vec[:22]
        except:
            return [0]*22

    def analyze(self, filepath):
        report = {
            "filename": os.path.basename(filepath),
            "status": "CLEAN",
            "risk_score": 0,
            "entropy_info": {"avg": 0, "max_local": 0},
            "ml_probability": -1,
            "detection_log": [],
            "error": None
        }

        try:
            raw_data = open(filepath, 'rb').read()
            pe = pefile.PE(data=raw_data)
        except Exception as e:
            report["error"] = str(e)
            return report

        iat_apis = set()
        rule_score = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        iat_apis.add(imp.name.decode('utf-8', errors='ignore'))
        
        for rule in self.rules:
            rule_apis = set(rule['apis'])
            matched = rule_apis.intersection(iat_apis)
            threshold = max(2, len(rule_apis) * 0.5)
            if len(rule_apis) == 1:
                threshold = 1

            if len(matched) >= threshold:
                match_rate = len(matched) / len(rule_apis)
                base_score = {"High": 50, "Medium": 30, "Low": 10}.get(rule.get("danger"), 10)
                added_score = int(base_score * (0.5 + match_rate))
                rule_score += added_score
                
                # 로그에 매칭된 API 목록 표시
                matched_str = ', '.join(list(matched)[:3])
                report["detection_log"].append(
                    f"[Rule] {rule['name']} 의심 ({len(matched)}/{len(rule_apis)} 매칭) - [{matched_str}]"
                )

        # [ML Engine]
        feats = self.extract_features_22(raw_data, pe)
        report["entropy_info"]["avg"] = round(feats[4], 2)
        report["entropy_info"]["max_local"] = round(feats[6], 2)

        ml_score = 0
        if self.model:
            try:
                prob = self.model.predict_proba([feats])[0][1] * 100
                report["ml_probability"] = round(prob, 2)
                ml_score = int(prob)
                
                # ML 기준도 조금 완화 (60% 이상일 때만 로그 출력)
                if prob > 80: 
                    report["detection_log"].append(f"[ML] 악성 확률 매우 높음 ({prob:.1f}%)")
                elif prob > 60: 
                    report["detection_log"].append(f"[ML] 악성 의심 ({prob:.1f}%)")
                else: 
                    # 60% 미만이면 정상으로 간주하고 로그에 안 띄움 (오탐 방지)
                    pass 
                    
            except Exception as e:
                report["detection_log"].append(f"ML 예측 에러: {e}")

        # 최종 점수 계산
        final_score = min(rule_score + ml_score, 100)
        
        # ML 점수가 낮으면(정상 범위), 룰 점수가 있어도 최종 점수를 좀 깎음 (보정)
        if ml_score < 40 and final_score > 0:
            final_score = int(final_score * 0.7)

        report["risk_score"] = final_score
        
        if final_score >= 80: report["status"] = "DANGER"
        elif final_score >= 40: report["status"] = "WARNING"
        else: report["status"] = "CLEAN"

        pe.close()
        return report

analyzer = PEAnalyzer(ML_MODEL, RULES_PATH)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', report=None)

@app.route('/analyze', methods=['POST'])
def analyze_endpoint():
    if 'file' not in request.files: return "No file"
    f = request.files['file']
    if f.filename == '': return "No filename"
    path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename))
    f.save(path)
    return render_template('index.html', report=analyzer.analyze(path))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)