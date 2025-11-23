# 🧩 Windows File Analyzer
윈도우 실행 파일(EXE, DLL)의 구조를 분석하여 **실행하지 않고도 파일의 동작을 예측**할 수 있는 정적 분석 도구입니다.  
사용자가 직접 파일을 선택해 검증할 수 있는 **사용자 주도형 보안 분석기(User-driven Security Tool)** 입니다.


## 📘 프로젝트 개요
이 프로젝트는 Windows PE(Portable Executable) 파일의 **Import Address Table (IAT)** 을 파싱하여  
해당 프로그램이 어떤 **DLL과 API 함수**를 사용하는지 추출합니다.  
추출된 API 정보를 기반으로 **잠재적인 행위(예: 네트워크 통신, 파일 조작, 권한 상승 등)** 를 예측합니다.


## ⚙️ 주요 기능
- **PE 구조 파싱**: `pefile` 라이브러리를 활용해 DLL 및 API 함수 목록 추출  
- **위협 매칭 엔진**: 주요 악성 행위별 API 시그니처를 `rules.json`으로 관리  
- **파일 업로드 인터페이스**: 사용자가 직접 파일을 업로드하여 분석 수행  
- **결과 리포트 생성**: 위험도 및 행위 예측 결과를 시각화하여 출력  


##  💡 기술 스택
- **Language:** Python 3.x  
- **Core Library:** `pefile`, `json`, `flask`  
- **IDE:** Visual Studio Code  


## 📂 프로젝트 구조
```
project_root/
│
├── app.py # Flask 웹 서버
├── pe_analyzer.py # PE 구조 분석 로직
├── rules.json # 악성 행위별 API 매칭 규칙
├── templates/
│ └── index.html # 웹 인터페이스
├── uploads/ # 사용자 업로드 파일 (자동 생성)
├── test/ # 테스트용 exe 파일 
└── .gitignore
```

## 🚀 실행 방법
```bash
# 1. 필요한 라이브러리 설치
pip install flask pefile

# 2. 서버 실행
python app.py

# 3. 웹 브라우저에서 실행
http://localhost:5000
