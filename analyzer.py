import json
import requests
from collections import defaultdict
from datetime import datetime
import time
import os
from datetime import timezone

def get_country_from_ip(ip):
    """IPアドレスから国情報を取得する。"""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=country")
        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown')
        else:
            return 'Unknown'
    except requests.RequestException:
        return 'Unknown'

def analyze_caddy_logs_in_directory(directory, output_json_file):
    """指定されたディレクトリ内のすべてのCaddyログファイルを解析してデータを集計し、結果をJSONファイルに保存する。"""

    suspicious_paths = set()
    suspicious_ips = set()
    all_ips = set()
    all_paths = set()
    wordPress_paths = set()

    # 日ごとのレスポンス集計
    daily_responses = defaultdict(lambda: {"normal": 0, "error": 0})
    # 攻撃を行っていそうなIPリスト
    attack_ips = defaultdict(int)
    # 国ごとの攻撃カウント
    country_counts = defaultdict(int)

    # ディレクトリ内のすべてのファイルを処理
    for log_file in os.listdir(directory):
        log_file_path = os.path.join(directory, log_file)
        if os.path.isfile(log_file_path) and log_file.endswith('.log'):  # ログファイルのみ処理
            try:
                with open(log_file_path, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            all_ips.add(entry['request']['remote_ip'])
                            all_paths.add(entry['request']['uri'])

                            # 日付を抽出
                            timestamp = entry['ts']
                            date = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%Y-%m-%d')

                            status_code = entry['status']
                            if 200 <= status_code < 400:
                                daily_responses[date]["normal"] += 1
                            else:
                                daily_responses[date]["error"] += 1

                            # 404エラーを記録
                            if status_code == 404:
                                suspicious_paths.add(entry['request']['uri'])
                                suspicious_ips.add(entry['request']['remote_ip'])
                                # 攻撃の可能性があるIPリストにカウント
                                attack_ips[entry['request']['remote_ip']] += 1

                            # WordPress関連パスを記録
                            if "/wp-" in entry['request']['uri']:
                                wordPress_paths.add(entry['request']['uri'])
                        except json.JSONDecodeError:
                            print(f"無効なJSON行をスキップ: {line.strip()}")
            except FileNotFoundError:
                print(f"エラー: ログファイル '{log_file}' が見つかりません。")
                continue

    # 攻撃の可能性があるIPごとに国情報を取得し、国別カウント
    for ip, count in attack_ips.items():
        if count > 10:  # 10回以上の404エラーを発生させたIPのみ
            country = get_country_from_ip(ip)
            country_counts[country] += 1
            time.sleep(1)  # APIリクエストの速度を制限（1秒待機）

    # サマリー作成
    summary = {
        "total_ips": len(all_ips),
        "suspicious_ips_count": len(suspicious_ips),
        "suspicious_ips_sample": list(suspicious_ips)[:],  # 出力サイズを抑えるためのサンプル
        "total_paths": len(all_paths),
        "suspicious_paths_count": len(suspicious_paths),
        "suspicious_paths_sample": list(suspicious_paths)[:],  # 出力サイズを抑えるためのサンプル
        "wordpress_paths_count": len(wordPress_paths),
        "wordpress_paths_sample": list(wordPress_paths)[:],  # 出力サイズを抑えるためのサンプル
        "daily_responses": daily_responses,  # 日ごとのレスポンス統計
        "attack_ips": {ip: count for ip, count in attack_ips.items() if count > 10},  # 攻撃の可能性があるIPリスト
        "country_counts": dict(country_counts)  # 国ごとの攻撃カウント
    }

    # 結果をJSON形式で保存
    with open(output_json_file, 'w') as outfile:
        json.dump(summary, outfile, indent=4)

    print("Caddyログ解析結果:")
    print(f"総IP数: {len(all_ips)}")
    print(f"不審なIP（404エラー）: {len(suspicious_ips)} - {list(suspicious_ips)[:]}")  # 出力サイズを抑える
    print(f"総パス数: {len(all_paths)}")
    print(f"不審なパス（404エラー）: {len(suspicious_paths)} - {list(suspicious_paths)[:]}")  # 出力サイズを抑える
    print(f"WordPress関連のパス: {len(wordPress_paths)} - {list(wordPress_paths)[:]}")  # 出力サイズを抑える
    print(f"攻撃の可能性があるIPアドレス（10回以上の404エラー）: {len(summary['attack_ips'])}")
    print(f"攻撃が行われた国のカウント: {dict(country_counts)}")

    print(f"日ごとのレスポンス統計と攻撃の可能性があるIPリスト、国ごとの攻撃カウントを'{output_json_file}'に保存しました。")

    return summary

# 使用例:
log_directory = "./raw-caddy-logs"
output_json_file = "caddy_logs_summary_with_countries.json"
analyze_caddy_logs_in_directory(log_directory, output_json_file)
