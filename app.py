import os
import requests
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

API_TOKEN = os.getenv('ANALYZE_API_TOKEN')
API_BASE = os.getenv('ANALYZE_API_BASE')  # e.g. https://your.appliance.com
SUBMIT_URL = f"{API_BASE}/api/submit/file/"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify(success=False, message='No file part'), 400

    infile = request.files['file']
    if infile.filename == '':
        return jsonify(success=False, message='No selected file'), 400

    filename = secure_filename(infile.filename)
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    infile.save(temp_path)

    files = {'file': (filename, open(temp_path, 'rb'))}

    headers = {
        "Authorization": f"Token {API_TOKEN}"
    }

    try:
        resp = requests.post(SUBMIT_URL, files=files, headers=headers)
    finally:
        files['file'][1].close()
        os.remove(temp_path)

    if resp.status_code in (200, 201):
        body = resp.json()
        task = body.get('detail', {})
        return jsonify(success=True,
                       message=f"Submitted! ID={task.get('id')} SHA1={task.get('sha1')}")
    else:
        return jsonify(success=False, message=f"{resp.status_code}: {resp.text}"), resp.status_code


if __name__ == '__main__':
    app.run(debug=True)
