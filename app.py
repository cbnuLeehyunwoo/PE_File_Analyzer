import os
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from pe_analyzer import PEAnalyzer  # <-- 우리가 수정한 pe_analyzer.py 임포트

# 0. Flask 앱 설정
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/' # 업로드 폴더
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 제한

# 1. 분석기 인스턴스 생성 (룰 로드)
RULES_JSON_PATH = "rules.json"
if not os.path.exists(RULES_JSON_PATH):
    print(f"[오류] rules.json을 찾을 수 없습니다.")
    exit()
analyzer = PEAnalyzer(RULES_JSON_PATH)

# 2. 메인 페이지 (/) : 파일 업로드 폼 보여주기
@app.route('/')
def index():
    # index.html을 렌더링 (결과는 아직 없음)
    return render_template('index.html', results=None)

# 3. 분석 실행 (/analyze) : 파일 받아서 분석하기
@app.route('/analyze', methods=['POST'])
def upload_and_analyze():
    if 'file' not in request.files:
        return redirect(url_for('index')) # 파일이 없으면 메인으로

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index')) # 파일이 없으면 메인으로

    if file:
        # 1. 업로드 폴더에 파일 임시 저장
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # 2. PEAnalyzer로 분석 실행 (수정된 함수 호출)
        try:
            analyzed_filename, results = analyzer.analyze_file(filepath)
        except Exception as e:
            print(f"[분석 오류] {e}")
            results = [{"name": "분석 오류", "danger": "High", "description": "PE 파일이 아니거나 손상된 파일입니다.", "apis": []}]
            analyzed_filename = filename

        # 3. 임시 파일 삭제
        if os.path.exists(filepath):
            os.remove(filepath)

        # 4. 분석 결과를 포함하여 index.html을 다시 렌더링
        return render_template('index.html', 
                               filename=analyzed_filename,
                               results=results)

if __name__ == '__main__':
    # 4. uploads, templates 폴더가 없으면 생성
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    print("웹 서버가 http://127.0.0.1:5000 에서 실행됩니다.")
    app.run(debug=True) # debug=True로 개발 모드 실행