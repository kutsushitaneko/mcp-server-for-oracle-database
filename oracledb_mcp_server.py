import oracledb
import os
import re
import sqlparse
from dotenv import load_dotenv, find_dotenv
import time
from mcp.server.fastmcp import FastMCP
import json

# セキュリティ設定
MAX_QUERY_LENGTH = 1000000  # Oracle Database 23aiでは理論上は制限なしだが、パフォーマンスとセキュリティの観点から1MBに制限

# 危険なキーワードのリスト
DANGEROUS_KEYWORDS = [
    'drop', 'delete', 'update', 'insert', 'merge',
    'truncate', 'alter', 'create', 'grant', 'revoke',
    'execute', 'commit', 'rollback', 'savepoint'
]

def validate_query_length(query):
    """
    クエリの長さを検証する関数
    """
    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"クエリが長すぎます。最大長は{MAX_QUERY_LENGTH}文字です。")

def check_dangerous_keywords(query):
    """
    危険なキーワードが含まれていないかチェックする関数
    """
    # コメントを削除
    query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
    query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
    
    # 小文字に変換してチェック
    query_lower = query.lower()
    for keyword in DANGEROUS_KEYWORDS:
        # キーワードが単語として含まれているかチェック
        if re.search(r'\b' + keyword + r'\b', query_lower):
            raise ValueError(f"危険なキーワード '{keyword}' が検出されました")

def sanitize_input(params):
    """
    ユーザー入力のサニタイズを行う関数
    """
    if not params:
        return None
        
    sanitized_params = {}
    for key, value in params.items():
        # パラメータ名の検証
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', key):
            raise ValueError(f"無効なパラメータ名: {key}")
            
        # 値の型チェック
        if not isinstance(value, (str, int, float, bool, type(None))):
            raise ValueError(f"無効なパラメータ型: {type(value)}")
            
        # 文字列の場合は長さチェック
        if isinstance(value, str) and len(value) > 4000:  # OracleのVARCHAR2の最大長
            raise ValueError(f"文字列パラメータが長すぎます: {key}")
            
        sanitized_params[key] = value
        
    return sanitized_params

def is_select_query(query):
    """
    SQLクエリがSELECT文であることを確認する関数
    """
    # SQLクエリをパース
    parsed = sqlparse.parse(query)
    if not parsed:
        return False
    
    # 最初のステートメントを取得
    stmt = parsed[0]
    
    # DMLタイプを確認
    return stmt.get_type() == 'SELECT'

def validate_query(query):
    """
    SQLクエリを検証する関数
    """
    # SQLクエリをパース
    parsed = sqlparse.parse(query)
    if not parsed:
        raise ValueError("無効なSQLクエリです")
    
    # 複数のステートメントをチェック
    if len(parsed) > 1:
        raise ValueError("複数のSQLステートメントは許可されていません")
    
    # 最初のステートメントを取得
    stmt = parsed[0]
    
    # SELECT文であることを確認
    if stmt.get_type() != 'SELECT':
        raise ValueError("SELECT文以外のクエリは実行できません")
    
    # 危険なトークンをチェック
    for token in stmt.tokens:
        token_type = str(token.ttype).lower() if token.ttype else ''
        token_value = str(token.value).lower()
        
        # UNIONやその他の危険な操作をチェック
        if 'union' in token_value or 'into' in token_value:
            raise ValueError("許可されていない操作が含まれています")

def format_results(cursor, results, max_length=1000):
    """
    検索結果を整形して文字列として返す関数
    cursor: データベースカーソル
    results: 検索結果
    max_length: 出力テキスト全体の最大文字数（デフォルト: 1000）
    """
    if not results:
        return "検索結果はありません"
        
    # ヘッダー行の作成
    headers = [desc[0] for desc in cursor.description]
    
    # 出力テキストを構築
    output = []
    total_length = 0
    limit_reached = False
    
    for i, row in enumerate(results, 1):
        # 各レコードの出力を構築
        record_output = []
        record_output.append(f"\n{i}件目")
        
        for header, value in zip(headers, row):
            record_output.append(f"{header}:")
            try:
                # 値はすでに文字列に変換されているため、そのまま表示
                if isinstance(value, bytes):
                    record_output.append(value.decode('utf-8'))
                else:
                    record_output.append(str(value))
            except Exception as e:
                # エラーが発生した場合はエラーメッセージを表示
                record_output.append(f"<表示エラー: {str(e)}>")
            record_output.append("-" * 50)
        
        # このレコードの文字列長を計算
        record_text = "\n".join(record_output)
        record_length = len(record_text)
        
        # 制限を超えるかチェック
        if total_length + record_length > max_length:
            # 制限を超えた場合、現在のレコードを最大文字数まで表示
            remaining_length = max_length - total_length
            if remaining_length > 0:
                partial_text = record_text[:remaining_length]
                output.append(partial_text)
            limit_reached = True
            break
            
        output.extend(record_output)
        total_length += record_length
    
    # 結果を文字列として結合
    result_text = "\n".join(output)
    
    # 制限に達した場合のメッセージを追加
    if limit_reached:
        result_text += "\n... (文字数制限により以降は省略)"
    
    # 表示件数と合計件数を追加
    displayed_count = len(output) // (len(headers) * 3 + 2)  # 1レコードあたりの行数で割る
    result_text += f"\n\n完全表示: {displayed_count}件 / 合計: {len(results)}件"
    
    return result_text

def execute_query(cursor, query, params=None, max_rows=None):
    """
    SELECT文のみを実行する関数
    params: バインド変数に使用するパラメータ（辞書型）
    max_rows: 取得する最大行数
    """
    # クエリの検証
    validate_query(query)
    
    try:
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
            
        # 行数制限がある場合
        if max_rows is not None:
            cursor.arraysize = min(max_rows, 100)  # 一度に取得する行数を制限
            results = []
            while len(results) < max_rows:
                batch = cursor.fetchmany()
                if not batch:
                    break
                results.extend(batch)
                if len(results) >= max_rows:
                    results = results[:max_rows]
                    break
        else:
            results = cursor.fetchall()
            
        return results
    except oracledb.Error as e:
        raise ValueError(f"SQL実行エラー: {str(e)}")

def get_db_connection():
    """
    データベース接続を確立し、接続オブジェクトとカーソルを返す関数
    """
    # 環境変数を読み込む
    load_dotenv(find_dotenv())
    
    # 必要な環境変数のリスト
    required_env_vars = [
        "DB_USER",
        "DB_PASSWORD",
        "DB_DSN"
    ]
    
    # 環境変数の存在確認
    missing_vars = []
    for var in required_env_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"以下の環境変数が設定されていません: {', '.join(missing_vars)}")
    
    # 環境変数から設定を読み込む
    USERNAME = os.getenv("DB_USER")
    PASSWORD = os.getenv("DB_PASSWORD")
    DSN = os.getenv("DB_DSN")

    # データベース接続
    db_connection = oracledb.connect(user=USERNAME, password=PASSWORD, dsn=DSN)
    cursor = db_connection.cursor()
    
    return db_connection, cursor

def execute(query, params=None, max_length=1000, max_rows=10):
    """
    クエリを実行し、結果を整形して表示する関数
    query: 実行するSQLクエリ
    params: バインド変数に使用するパラメータ（辞書型）
    max_length: 各カラムの値の最大文字数（デフォルト: 1000）
    max_rows: 取得する最大行数（デフォルト: 10）
    """
    try:
        # データベース接続
        db_connection, cursor = get_db_connection()
        
        try:
            # クエリの実行と結果の表示
            results = execute_query(cursor, query, params, max_rows)
            
            # 結果を文字列に変換
            processed_results = []
            for row in results:
                processed_row = []
                for value in row:
                    try:
                        if isinstance(value, oracledb.LOB):
                            if hasattr(value, "type") and value.type == oracledb.DB_TYPE_BLOB:
                                # BLOBデータの場合はサイズを表示
                                processed_row.append(f"<BLOBデータ: {value.size()} bytes>")
                            elif hasattr(value, "type") and value.type == oracledb.DB_TYPE_CLOB:
                                processed_row.append(str(value))
                            elif hasattr(value, "type") and value.type == oracledb.DB_TYPE_BFILE:
                                processed_row.append(f"<BFILEデータです>")
                        elif value is None:
                            # NULL値の場合は空文字列を表示
                            processed_row.append("")
                        else:
                            # その他の値は文字列に変換
                            processed_row.append(str(value))
                    except Exception as e:
                        processed_row.append(f"<表示エラー: {str(e)}>")
                processed_results.append(tuple(processed_row))
            
            # 結果を表示
            formated_results = format_results(cursor, processed_results, max_length)
            return formated_results
            
        finally:
            # リソースの解放
            cursor.close()
            db_connection.close()
            
    except Exception as e:
        print(f"エラーが発生しました: {str(e)}")
        return None

mcp = FastMCP("ORACLE")

@mcp.tool(
    name = "execute_oracle",
    description = """
    Oracle Databaseに対してSQLクエリを実行し、結果をフォーマットして返す。
        Args:
            query: 実行するSQLクエリ（必須）
            params: バインド変数に使用するパラメータ（辞書型　例：{"parameter1": 5}）
            max_length: 応答の最大文字数（integer型、デフォルト: 1000）
            max_rows: 取得する最大行数（integer型、デフォルト: 10）
        ヒント:
            文字数制限にかかったときは、max_lengthを大きくしてください。
    """)
def execute_oracle(query: str, params: dict = None, max_length: int = 1000, max_rows: int = 10) -> str:
    try:
        result = execute(query, params, max_length, max_rows)
        # 結果をJSON形式で返す
        response = {
            "content": [
                {"type": "text", "text": result}
            ],
            "is_error": False,
            "encoding": "utf-8"
        }
        return json.dumps(response, ensure_ascii=False, indent=2)
    except Exception as e:
        error_response = {
            "content": [
                {"type": "text", "text": str(e)}
            ],
            "is_error": True,
            "encoding": "utf-8"
        }
        return json.dumps(error_response, ensure_ascii=False, indent=2)

@mcp.tool(
    name = "describe_table",
    description = """
    データベースのテーブルの構造を表示します。
        Args:
            table_name: テーブル名（必須）
    """)
def describe_table(table_name: str) -> str:
    try:
        # テーブル名の検証
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', table_name):
            raise ValueError(f"無効なテーブル名: {table_name}")
        
        # データベース接続
        db_connection, cursor = get_db_connection()
        
        try:
            # テーブルのカラム情報を取得（より安全なクエリ）
            query = """
            SELECT 
                column_name,
                data_type,
                CASE 
                    WHEN data_type IN ('VARCHAR2', 'CHAR', 'NVARCHAR2', 'NCHAR') 
                        THEN TO_CHAR(data_length)
                    WHEN data_type = 'NUMBER' AND data_precision IS NOT NULL 
                        THEN TO_CHAR(data_precision) || ',' || TO_CHAR(data_scale)
                    ELSE NULL
                END as data_length,
                nullable
            FROM user_tab_columns
            WHERE table_name = :1
            ORDER BY column_id
            """
            
            # コメント情報を取得
            comment_query = """
            SELECT column_name, comments
            FROM user_col_comments
            WHERE table_name = :1
            """
            
            # カラム情報を取得
            columns = execute_query(cursor, query, [table_name.upper()])
            if not columns:
                raise ValueError(f"テーブル '{table_name}' が見つかりません")
            
            # コメント情報を取得
            comments = execute_query(cursor, comment_query, [table_name.upper()])
            comments_dict = {row[0]: row[1] for row in comments}
            
            # 結果を整形
            output = []
            output.append(f"\nテーブル: {table_name}")
            output.append("-" * 80)
            output.append("名前\t\t\t\tNULL?\t型\t\t\t長さ\tコメント")
            output.append("-" * 80)
            
            for column in columns:
                column_name, data_type, data_length, nullable = column
                comment = comments_dict.get(column_name, "")
                
                # データ型の表示を整形
                if data_type in ('VARCHAR2', 'CHAR', 'NVARCHAR2', 'NCHAR'):
                    type_display = f"{data_type}({data_length})"
                elif data_type == 'NUMBER' and data_length:
                    type_display = f"NUMBER({data_length})"
                else:
                    type_display = data_type
                
                # NULL許可の表示
                nullable_display = "Y" if nullable == 'Y' else "N"
                
                # 行を整形
                output.append(f"{column_name.ljust(30)}\t{nullable_display}\t{type_display.ljust(20)}\t{data_length or ''}\t{comment}")
            
            result = "\n".join(output)
            
            # 結果をJSON形式で返す
            response = {
                "content": [
                    {"type": "text", "text": result}
                ],
                "is_error": False,
                "encoding": "utf-8"
            }
            return json.dumps(response, ensure_ascii=False, indent=2)
            
        finally:
            # リソースの解放
            cursor.close()
            db_connection.close()
            
    except Exception as e:
        error_response = {
            "content": [
                {"type": "text", "text": str(e)}
            ],
            "is_error": True,
            "encoding": "utf-8"
        }
        return json.dumps(error_response, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    # stdioで通信
    mcp.run(transport="stdio")
