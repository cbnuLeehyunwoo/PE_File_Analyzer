import os
import time
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from pe_analyzer import PEAnalyzer 

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# 분석기 초기화
RULES_JSON_PATH = "rules.json"
analyzer = PEAnalyzer(RULES_JSON_PATH)

@app.route('/')
def index():
    return render_template('index.html', report=None)

@app.route('/analyze', methods=['POST'])
def upload_and_analyze():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        file.save(filepath)

        # 분석 수행 (이제 report는 딕셔너리입니다)
        report = analyzer.analyze_file(filepath)
        
        # 파일 삭제
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except: pass # 파일 잠금 문제 등 무시

        return render_template('index.html', report=report)

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    app.run(debug=True, port=5000)