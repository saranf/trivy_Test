#!/usr/bin/env python3
"""
🤖 Simple Trivy Agent - 서버/컨테이너에 설치하는 경량 에이전트
Python 하나로 Central Server와 통신

설치 방법:
  curl -O http://central-server/simple_agent.py
  python3 simple_agent.py --url http://central-server/api/agent.php --token YOUR_TOKEN
"""

import os
import sys
import json
import time
import socket
import platform
import argparse
import urllib.request
import urllib.error
from datetime import datetime

def get_hostname():
    return socket.gethostname()

def get_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_os_info():
    return f"{platform.system()} {platform.release()}"

def api_call(base_url, action, token, data=None):
    """Central Server API 호출"""
    url = f"{base_url}?action={action}"
    headers = {
        'Content-Type': 'application/json',
        'X-Agent-Token': token
    }
    
    try:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {'success': False, 'error': f'HTTP {e.code}: {e.reason}'}
    except urllib.error.URLError as e:
        return {'success': False, 'error': f'URL Error: {e.reason}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def collect_system_info():
    """시스템 정보 수집"""
    info = {
        'hostname': get_hostname(),
        'ip_address': get_ip_address(),
        'os': get_os_info(),
        'python_version': platform.python_version(),
        'cpu_count': os.cpu_count(),
        'collected_at': datetime.now().isoformat()
    }
    
    # 메모리 정보 (Linux)
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal'):
                    info['memory_total'] = line.split()[1] + ' kB'
                    break
    except:
        pass
    
    return info

def main():
    parser = argparse.ArgumentParser(description='Simple Trivy Agent')
    parser.add_argument('--url', required=True, help='Central Server API URL')
    parser.add_argument('--token', required=True, help='Agent API Token')
    parser.add_argument('--interval', type=int, default=60, help='Heartbeat interval (seconds)')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    args = parser.parse_args()

    hostname = get_hostname()
    agent_id = hostname.lower().replace(' ', '-')
    
    print(f"🤖 Simple Trivy Agent")
    print(f"   Agent ID: {agent_id}")
    print(f"   Central Server: {args.url}")
    print(f"   Interval: {args.interval}s")
    print()

    # 에이전트 등록
    print("📡 Registering agent...")
    result = api_call(args.url, 'register', args.token, {
        'agent_id': agent_id,
        'hostname': hostname,
        'ip_address': get_ip_address(),
        'os_info': get_os_info(),
        'version': '1.0.0-simple'
    })
    
    if result.get('success'):
        print("✅ Registered successfully!")
    else:
        print(f"❌ Registration failed: {result.get('error')}")
        if not args.once:
            print("   Continuing anyway...")

    # 메인 루프
    while True:
        try:
            # 시스템 정보 수집 및 전송
            sys_info = collect_system_info()
            
            # 하트비트
            result = api_call(args.url, 'heartbeat', args.token, {'agent_id': agent_id})
            
            # 데이터 보고
            api_call(args.url, 'report', args.token, {
                'agent_id': agent_id,
                'data_type': 'system',
                'data': sys_info
            })
            
            status = "✅" if result.get('success') else "❌"
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {status} Heartbeat sent")
            
            if args.once:
                print("Done (--once mode)")
                break
                
            time.sleep(args.interval)
            
        except KeyboardInterrupt:
            print("\n👋 Agent stopped")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            if args.once:
                break
            time.sleep(10)

if __name__ == '__main__':
    main()

