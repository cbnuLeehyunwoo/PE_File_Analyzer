# 🧩 Windows File Analyzer
- 윈도우 실행 파일(EXE, DLL)의 구조를 분석하여 **실행하지 않고도 파일의 동작을 예측**할 수 있는 정적 분석 도구입니다.  

- 사용자가 직접 파일을 선택해 검증할 수 있는 **사용자 주도형 보안 분석기(User-driven Security Tool)** 입니다.
  
- 시그니처 탐지 방식(IAT) + 엔트로피 수치 + 머신러닝 모델을 결합한 하이브리드 탐지 엔진을 구현하여 진단합니다. 

## 📘 프로젝트 개요
- 이 프로젝트는 Windows PE(Portable Executable) 파일의 **Import Address Table (IAT)** 을 파싱하여 
해당 프로그램이 어떤 **DLL과 API 함수**를 사용하는지 추출합니다.  

- 추출된 API 정보를 기반으로 **잠재적인 행위(예: 네트워크 통신, 파일 조작, 권한 상승 등)** 를 예측합니다.

- 파일 내부의 엔트로피를 계산하여 패킹 및 암호화 여부를 진단합니다.
- 정상 파일 분석 (winhlp32.exe)<img width="682" height="386" alt="image" src="https://github.com/user-attachments/assets/7ef46ca4-e40a-404d-b419-8613a0034ba0" />

- 악성 코드 분석 시(Cryptolocker)<img width="671" height="392" alt="Cryptolocker" src="https://github.com/user-attachments/assets/f52416b2-2dc6-4601-abf5-b03c11e9babe" />

- 목업 악성 코드 분석<img width="811" height="878" alt="화면 캡처 2025-12-02 021955" src="https://github.com/user-attachments/assets/3dd318d7-92fa-47d9-b26a-63ccc08e903d" />

## ⚙️ 주요 기능
- **PE 구조 파싱**: `pefile` 라이브러리를 활용해 DLL 및 API 함수 목록 추출  
- **위협 매칭 엔진**: 주요 악성 행위별 API 시그니처를 `rules.json`으로 관리  
- **파일 업로드 인터페이스**: 사용자가 직접 파일을 업로드하여 분석 수행
- **패킹 및 암호화 탐지**: 파일의 섀년 엔트로피를 계산하여 7.2 이상일 경우 패킹/암호화된 악성코드로 의심합니다. 특히 저 엔트로피 패커를 탐지하기 위해 전체 평균 엔트로피, 슬라이딩 윈도우(1024Byte) 기반 엔트로피를 모두 측정합니다.
- **결과 리포트 생성**: Rule 점수와 ML 확률을 합산하여 최종 위험도(0~100)를 산출합니다.
- 목업 악성코드 생성: lief 라이브러리를 활용해 템플릿 없이도 즉석에서 패킹되어있거나 악성 API가 주입되기만 한 테스트용 EXE 파일을 생성할 수 있습니다.

##  💡 기술 스택
- Backend: Python, Flask

- Analysis Core: pefile (PE Header Parsing), lief (Binary Modification)

- Machine Learning: scikit-learn (Random Forest Classifier), joblib, numpy

- Frontend: HTML5, TailwindCSS (CDN)


## 📂 프로젝트 구조
```
PE_Analyzer/
│
├── app.py                 # [Main] Flask 웹 서버 및 엔드포인트
├── pe_analyzer.py         # [Core] 분석 엔진 (Feature Extraction + Logic)
├── pe_model.pkl           # [Model] 학습된 Random Forest 모델 파일
├── rules.json             # [Config] 악성 행위 탐지 시그니처 모음
│
├── scripts/               # [Training] ML 모델 학습 스크립트
│   └── train_ember_model.py     # EMBER 데이터셋 로드 및 모델 학습 코드
│
├── test/                  # [Testing] 테스트 도구
│   └── generate_malware.py # 가짜 악성코드(IAT 변조) 생성기
│
├── templates/             # [View] 웹 UI (HTML)
├── uploads/               # [Data] 사용자 업로드 파일 저장소
└── .gitignore             # Git 설정 파일
```

## 🚀 실행 방법
### 1. 필요한 라이브러리 설치
``` bash
pip install flask pefile scikit-learn joblib numpy lief
```
### 2. EMBER 데이터셋 다운로드 
| Year | Feature Version | Filename                     | URL                                                                                                            | sha256                                                             |
|------|-----------------|------------------------------|----------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| 2017 | 1               | ember_dataset.tar.bz2        | [https://ember.elastic.co/ember_dataset.tar.bz2](https://ember.elastic.co/ember_dataset.tar.bz2)               | `a5603de2f34f02ab6e21df7a0f97ec4ac84ddc65caee33fb610093dd6f9e1df9` |
| 2017 | 2               | ember_dataset_2017_2.tar.bz2 | [https://ember.elastic.co/ember_dataset_2017_2.tar.bz2](https://ember.elastic.co/ember_dataset_2017_2.tar.bz2) | `60142493c44c11bc3fef292b216a293841283d86ff58384b5dc2d88194c87a6d` |
| 2018 | 2               | ember_dataset_2018_2.tar.bz2 | [https://ember.elastic.co/ember_dataset_2018_2.tar.bz2](https://ember.elastic.co/ember_dataset_2018_2.tar.bz2) | `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812` |

### 3. 프로젝트 디렉터리에 압축 해제 
- `script/data/` 디렉터리에 압축 해제
  
### 4. ML 모델 학습 
``` bash
# scripts 폴더의 학습 코드를 실행하여 pe_model.pkl 생성
python scripts/train_ember_model.py
```

# 5. 웹 서버 실행
``` bash
python app.py
``` 
- 서버가 시작되면 `http://localhost:5000`로 접속

## ⚠️주의사항
- 해당 도구는 정적 분석 도구이므로 실행 시 동적으로 API를 로딩하는 고도화된 악성코드는 탐지가 제한될 수 있습니다.
