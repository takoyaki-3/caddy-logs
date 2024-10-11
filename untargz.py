import os
import tarfile
import gzip
import shutil

# ベースディレクトリの設定
base_dir = '.'
raw_logs_dir = os.path.join(base_dir, 'raw-caddy-logs')

# ドメイン名を指定してそのドメインに関連するファイルを解凍する関数
def extract_logs_for_domain(domain_name):
    # base_dir の下にある caddy-logs ディレクトリ内のファイルをリスト化
    caddy_logs_dir = os.path.join(base_dir, 'caddy-logs')
    
    # raw_logs_dir が存在しない場合は作成
    if not os.path.exists(raw_logs_dir):
        os.makedirs(raw_logs_dir)

    # 指定されたドメインに関連する .gz ファイルを探す
    for filename in os.listdir(caddy_logs_dir):
        if filename.startswith(domain_name) and filename.endswith('.gz'):
            file_path = os.path.join(caddy_logs_dir, filename)
            extract_gz_file(file_path)

# .gz ファイルを解凍して raw_logs_dir に保存する関数
def extract_gz_file(file_path):
    file_name = os.path.basename(file_path)
    raw_file_path = os.path.join(raw_logs_dir, file_name.replace('.gz', ''))

    # .gz ファイルを解凍
    with gzip.open(file_path, 'rb') as gz_file:
        with open(raw_file_path, 'wb') as out_file:
            shutil.copyfileobj(gz_file, out_file)

    print(f'Extracted: {raw_file_path}')

# メインの実行
if __name__ == '__main__':
    domain_name = input('Please enter the domain name (e.g., takoyaki3.com): ')
    extract_logs_for_domain(domain_name)
