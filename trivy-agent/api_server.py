#!/usr/bin/env python3
"""
🤖 Trivy Agent HTTP API Server
웹서버에서 직접 호출 가능한 HTTP API 제공
"""

import os
import json
import subprocess
import threading
from flask import Flask, request, jsonify

app = Flask(__name__)

# 환경 변수
AGENT_TOKEN = os.environ.get('AGENT_TOKEN', 'default-agent-token')
AGENT_ID = os.environ.get('AGENT_ID', 'local-agent')

def verify_token():
    """토큰 검증"""
    token = request.headers.get('X-Agent-Token', '')
    if token != AGENT_TOKEN:
        return False
    return True

def run_command(cmd, timeout=300):
    """명령 실행"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', 'Timeout', -1
    except Exception as e:
        return '', str(e), -1

@app.route('/health', methods=['GET'])
def health():
    """헬스체크"""
    return jsonify({'status': 'ok', 'agent_id': AGENT_ID})

@app.route('/scan/image', methods=['POST'])
def scan_image():
    """이미지 스캔"""
    if not verify_token():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    data = request.get_json() or {}
    image = data.get('image', '')
    severity = data.get('severity', 'HIGH,CRITICAL')
    security_checks = data.get('security_checks', 'vuln,config')
    
    if not image:
        return jsonify({'success': False, 'error': 'Image required'})
    
    # 이미지명 안전 처리
    safe_image = image.replace(';', '').replace('&', '').replace('|', '')
    
    cmd = f"trivy image --security-checks {security_checks} --severity {severity} --format json {safe_image} 2>/dev/null"
    stdout, stderr, code = run_command(cmd)
    
    if code == 0 and stdout:
        try:
            result = json.loads(stdout)
            return jsonify({'success': True, 'result': result, 'image': image})
        except json.JSONDecodeError:
            return jsonify({'success': False, 'error': 'Invalid JSON response', 'raw': stdout[:500]})
    else:
        return jsonify({'success': False, 'error': stderr or 'Scan failed', 'code': code})

@app.route('/scan/sbom', methods=['POST'])
def scan_sbom():
    """SBOM 생성"""
    if not verify_token():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    data = request.get_json() or {}
    image = data.get('image', '')
    format_type = data.get('format', 'cyclonedx')  # cyclonedx, spdx, spdx-json
    
    if not image:
        return jsonify({'success': False, 'error': 'Image required'})
    
    safe_image = image.replace(';', '').replace('&', '').replace('|', '')
    
    cmd = f"trivy image --format {format_type} {safe_image} 2>/dev/null"
    stdout, stderr, code = run_command(cmd)
    
    if code == 0 and stdout:
        return jsonify({'success': True, 'sbom': stdout, 'image': image, 'format': format_type})
    else:
        return jsonify({'success': False, 'error': stderr or 'SBOM generation failed'})

@app.route('/scan/config', methods=['POST'])
def scan_config():
    """설정 스캔 (Dockerfile, K8s yaml 등)"""
    if not verify_token():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    data = request.get_json() or {}
    image = data.get('image', '')
    security_checks = data.get('security_checks', 'config')
    
    if not image:
        return jsonify({'success': False, 'error': 'Image required'})
    
    safe_image = image.replace(';', '').replace('&', '').replace('|', '')
    
    cmd = f"trivy image --security-checks {security_checks} --format json {safe_image} 2>/dev/null"
    stdout, stderr, code = run_command(cmd)
    
    if code == 0 and stdout:
        try:
            result = json.loads(stdout)
            return jsonify({'success': True, 'result': result, 'image': image})
        except json.JSONDecodeError:
            return jsonify({'success': False, 'error': 'Invalid JSON'})
    else:
        return jsonify({'success': False, 'error': stderr or 'Config scan failed'})

@app.route('/docker/images', methods=['GET'])
def list_images():
    """Docker 이미지 목록"""
    if not verify_token():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    cmd = "docker images --format '{{json .}}'"
    stdout, stderr, code = run_command(cmd)
    
    if code == 0:
        images = []
        for line in stdout.strip().split('\n'):
            if line:
                try:
                    images.append(json.loads(line))
                except:
                    pass
        return jsonify({'success': True, 'images': images})
    return jsonify({'success': False, 'error': stderr})

@app.route('/docker/containers', methods=['GET'])
def list_containers():
    """Docker 컨테이너 목록"""
    if not verify_token():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    cmd = "docker ps -a --format '{{json .}}'"
    stdout, stderr, code = run_command(cmd)
    
    if code == 0:
        containers = []
        for line in stdout.strip().split('\n'):
            if line:
                try:
                    containers.append(json.loads(line))
                except:
                    pass
        return jsonify({'success': True, 'containers': containers})
    return jsonify({'success': False, 'error': stderr})

if __name__ == '__main__':
    port = int(os.environ.get('API_PORT', 8888))
    print(f"🤖 Trivy Agent API Server starting on port {port}")
    app.run(host='0.0.0.0', port=port, threaded=True)

