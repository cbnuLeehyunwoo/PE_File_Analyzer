import sys
import os
import glob
import numpy as np
import joblib
import time
from tqdm import tqdm

sys.stdout.reconfigure(encoding='utf-8')

try:
    import orjson as json
except ImportError:
    import json

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from joblib import Parallel, delayed

DATA_DIR = "./model"
MODEL_PATH = "pe_model.pkl"

def flatten_features(sample):
    feat = sample.get("features", sample)
    vec = []
    
    try:
        # --- 1. Byte Histogram ---
        # 키 이름이 histogram 또는 byte_histogram 둘 중 하나임
        bh_data = feat.get("histogram", feat.get("byte_histogram"))
        if bh_data:
            bh = np.array(bh_data, dtype=np.float32)
            vec.extend([bh.mean(), bh.std(), bh.max(), bh.min()])
        else:
            vec.extend([0.0, 0.0, 0.0, 0.0])

        # --- 2. Byte Entropy ---
        be_data = feat.get("byteentropy")
        if be_data:
            be = np.array(be_data, dtype=np.float32)
            vec.extend([be.mean(), be.std(), be.max(), be.min()])
        else:
            vec.extend([0.0, 0.0, 0.0, 0.0])

        # --- 3. General ---
        g = feat.get("general", {})
        vec.extend([
            g.get("size", 0), g.get("vsize", 0), g.get("imports", 0), g.get("exports", 0),
            g.get("has_signature", 0), g.get("has_tls", 0)
        ])

        # --- 4. Section (여기가 에러 원인이었음) ---
        sec = feat.get("section", {})
        sec_vec = [0.0, 0.0, 0.0, 0.0] # mean_ent, max_ent, mean_size, mean_vsize
        
        # Case A: 이미 통계 리스트로 되어 있는 경우 (EMBER Vectorized)
        if isinstance(sec, dict) and "entropy" in sec and isinstance(sec["entropy"], list):
             sec_vec = [
                np.mean(sec["entropy"]), np.max(sec["entropy"]),
                np.mean(sec["size"]), np.mean(sec["virtual_size"])
            ]
        # Case B: 섹션 정보 리스트인 경우 (Raw Data) - 'sections' 키 안에 리스트가 있거나, sec 자체가 리스트
        else:
            # 리스트 찾기
            sec_list = sec.get("sections", []) if isinstance(sec, dict) else (sec if isinstance(sec, list) else [])
            
            if sec_list and len(sec_list) > 0 and isinstance(sec_list[0], dict):
                # 각 섹션 딕셔너리에서 entropy, size 추출
                entropies = [s.get("entropy", 0) for s in sec_list]
                sizes = [s.get("size", 0) for s in sec_list]
                vsizes = [s.get("virtual_size", 0) for s in sec_list]
                
                if entropies:
                    sec_vec = [np.mean(entropies), np.max(entropies), np.mean(sizes), np.mean(vsizes)]

        vec.extend(sec_vec)

        # --- 5. Imports ---
        imp = feat.get("imports", {})
        imp_vec = [0.0, 0.0, 0.0] 
        
        # Case A: EMBER histogram 통계가 있는 경우
        if isinstance(imp, dict) and "histogram" in imp:
            ih = np.array(imp["histogram"], dtype=np.float32)
            imp_vec = [ih.sum(), ih.mean(), ih.max()]
        # Case B: {DLL: [함수들]} 형태인 경우 (Raw Data)
        elif isinstance(imp, dict):
            # DLL별 함수 개수를 세서 통계로 변환
            counts = [len(funcs) for funcs in imp.values()]
            if not counts: counts = [0]
            counts = np.array(counts, dtype=np.float32)
            imp_vec = [counts.sum(), counts.mean(), counts.max()]
            
        vec.extend(imp_vec)

        # --- 6. Exports ---
        exp = feat.get("exports", [])
        # 리스트 길이를 특징으로 사용 
        vec.append(float(len(exp)))
        
    except Exception:
        return []

    return vec

# ------------------------
# Worker Function
# ------------------------
def process_single_file(file_path):
    local_X = []
    local_y = []

    try:
        mode = "rb" if "orjson" in str(json) else "r"
        with open(file_path, mode) as f:
            for line in f:
                try:
                    sample = json.loads(line)
                    
                    label = sample.get("label", -1)
                    if label == -1: 
                        continue
                        
                    vec = flatten_features(sample)
                    if vec: 
                        local_X.append(vec)
                        local_y.append(label)
                    
                except Exception:
                    continue
    except Exception:
        pass
        
    return local_X, local_y

# ------------------------
# Main Loader
# ------------------------
def load_and_vectorize(data_dir):
    files = sorted(glob.glob(f"{data_dir}/train_features_*.jsonl"))
    print(f"[+] Found {len(files)} files.")
    
    start_time = time.time()
    print(f"[+] Starting parallel processing (Threading Mode)...")
    results = Parallel(n_jobs=-1, verbose=0, backend="threading")(
        delayed(process_single_file)(f) for f in tqdm(files, desc="Processing", ascii=True)
    )
    
    print("[+] Merging results...")
    X_all = []
    y_all = []
    
    for x_part, y_part in results:
        X_all.extend(x_part)
        y_all.extend(y_part)
        
    X = np.array(X_all, dtype=np.float32)
    y = np.array(y_all, dtype=np.int32)
    
    duration = time.time() - start_time
    print(f"[+] Loading Done: {duration:.2f} sec")
    print(f"    X shape: {X.shape}")
    print(f"    y count: {len(y)}")
    
    return X, y

# ------------------------
# Main Execution
# ------------------------
if __name__ == "__main__":
    try:
        X, y = load_and_vectorize(DATA_DIR)
    except Exception as e:
        print(f"Error: {e}")
        exit()

    if len(y) == 0:
        print("❌ No data loaded. All samples were skipped.")
        print("   -> Tip: Check if 'label' is -1 (unlabeled).")
        exit()

    print("\n==== Training Model ====")
    # 학습 데이터 분할
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 모델 생성
    clf = RandomForestClassifier(
        n_estimators=50, 
        max_depth=12, 
        n_jobs=-1,
        random_state=42,
        verbose=1
    )
    
    # 학습
    clf.fit(X_train, y_train)

    print("\n==== Evaluation ====")
    print(classification_report(y_test, clf.predict(X_test)))

    # 저장
    joblib.dump(clf, MODEL_PATH)
    print(f"🎯 Model Saved: {MODEL_PATH}")