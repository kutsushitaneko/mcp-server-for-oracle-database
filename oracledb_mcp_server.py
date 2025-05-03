import oracledb
import os
import re
import sqlparse
from dotenv import load_dotenv, find_dotenv
import time
from mcp.server.fastmcp import FastMCP
import mcp.types as types
import json

# デフォルト設定
DEFAULT_MAX_LENGTH = 10000
DEFAULT_MAX_ROWS = 100

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
    
    # トークンを解析してUNIONとINTOをチェック
    for i, token in enumerate(stmt.tokens):
        token_value = str(token.value).lower()
        
        # INTO句の使用を禁止
        if 'into' in token_value:
            raise ValueError("INTO句の使用は許可されていません")
        
        # UNIONの検出とガイダンス
        if 'union' in token_value:
            # UNION ALLの場合は特別なガイダンスを提供
            if 'union all' in token_value:
                guidance_message = """
UNION ALLの使用は許可されていません。

代替案として以下の方法を検討してください：

1. ROLLUPを使用した集計:
   GROUP BY ROLLUP(列名)
   - 小計や総計を自動的に生成できます
   - パフォーマンスが向上する可能性があります

2. GROUPING関数との組み合わせ:
   NVL2(GROUPING(列名), '総計', 列名) AS 列名
   - 集計レベルを識別できます
   - より柔軟な集計表示が可能です

例：
WITH 基本集計 AS (
    SELECT 
        カテゴリー,
        年度,
        SUM(売上高) AS 売上高
    FROM 
        売上テーブル
    GROUP BY 
        カテゴリー,
        年度
)
SELECT 
    NVL2(GROUPING(カテゴリー), '総計', カテゴリー) AS カテゴリー,
    SUM(CASE WHEN 年度 = '2023' THEN 売上高 ELSE 0 END) AS "2023年",
    SUM(CASE WHEN 年度 = '2024' THEN 売上高 ELSE 0 END) AS "2024年",
    SUM(売上高) AS 合計,
    CASE 
        WHEN GROUPING(カテゴリー) = 1 THEN 2
        ELSE 1
    END AS ソート順
FROM 
    基本集計
GROUP BY ROLLUP(カテゴリー)
ORDER BY 
    ソート順,
    カテゴリー;

なお、ORDER BY句では集計関数（SUM、COUNT、AVG等）を直接使用することはできません。副問合せやCASE式の使用を検討してください。

この方法により：
- UNION ALL による セキュリティ上の脆弱性を回避
- より効率的なクエリ実行
- メンテナンス性の向上
- 標準的なSQL機能の活用
が期待できます。
"""
                raise ValueError(guidance_message)
            
            # UNIONの後のトークンを検索
            select_found = False
            for next_token in stmt.tokens[i+1:]:
                next_value = str(next_token.value).lower().strip()
                if next_value == 'select':
                    select_found = True
                    break
                # 意味のある文字列トークンがSELECT以外で見つかった場合
                elif next_value and not next_value.isspace():
                    raise ValueError("UNIONの後にはSELECT文が必要です")
            
            if not select_found:
                raise ValueError("UNIONの後にはSELECT文が必要です")

def format_results(cursor, results, max_length=DEFAULT_MAX_LENGTH, more_rows_exist=False):
    """
    検索結果を整形してJSON形式で返す関数
    cursor: データベースカーソル
    results: 検索結果
    max_length: 出力テキスト全体の最大文字数（デフォルト: DEFAULT_MAX_LENGTH）
    more_rows_exist: 取得可能な追加行があるかどうか
    """
    if not results:
        return "検索結果はありません"
        
    # ヘッダー行の作成
    headers = [desc[0] for desc in cursor.description]
    
    # JSON形式で結果を構築
    json_results = []
    for row in results:
        record = {}
        for header, value in zip(headers, row):
            try:
                # 値はすでに文字列に変換されているため、そのまま使用
                if isinstance(value, bytes):
                    record[header] = value.decode('utf-8')
                else:
                    record[header] = value
            except Exception as e:
                record[header] = f"<表示エラー: {str(e)}>"
        json_results.append(record)
    
    # 行数制限メッセージを追加
    if more_rows_exist:
        json_results.append({
            "message": "(行数制限により以降は省略。max_rows値を増やして再実行してください。)"
        })
    
    # 結果を文字列に変換
    result_str = json.dumps(json_results, ensure_ascii=False, indent=2)
    
    # 文字数制限をチェック
    if len(result_str) > max_length:
        # 文字列を制限内に切り詰める
        truncated_str = result_str[:max_length]
        # 最後の完全なJSONオブジェクトを探し、それ以降を削除
        last_bracket = truncated_str.rfind('}')
        if last_bracket != -1:
            truncated_str = truncated_str[:last_bracket + 1]
        # 省略メッセージをJSON構造で追加
        truncated_str = truncated_str + ',\n  {\n    "message": "(文字数制限により以降は省略。max_length値を増やして再実行してください。)"\n  }\n]'
        return truncated_str
    
    return result_str

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
            more_rows_exist = False
            
            while len(results) < max_rows:
                batch = cursor.fetchmany()
                if not batch:
                    break
                results.extend(batch)
                if len(results) >= max_rows:
                    # max_rowsに達した場合、追加データがあるかチェック
                    results = results[:max_rows]
                    # 追加データがあるかを確認
                    check_more = cursor.fetchone()
                    more_rows_exist = check_more is not None
                    break
            
            # 追加データがあることをフラグとして返す
            return results, more_rows_exist
        else:
            results = cursor.fetchall()
            return results, False

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

def execute(query, params=None, max_length=DEFAULT_MAX_LENGTH, max_rows=DEFAULT_MAX_ROWS):
    """
    クエリを実行し、結果を整形して表示する関数
    query: 実行するSQLクエリ
    params: バインド変数に使用するパラメータ（辞書型）
    max_length: 応答の最大文字数（デフォルト: DEFAULT_MAX_LENGTH）
    max_rows: 取得する最大行数（デフォルト: DEFAULT_MAX_ROWS）
    """
    try:
        # データベース接続
        db_connection, cursor = get_db_connection()
        
        try:
            # クエリの実行と結果の表示
            results, more_rows_exist = execute_query(cursor, query, params, max_rows)
            
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
            formated_results = format_results(cursor, processed_results, max_length, more_rows_exist)
            return formated_results
            
        finally:
            # リソースの解放
            cursor.close()
            db_connection.close()
            
    except Exception as e:
        error_message = f"エラーが発生しました: {str(e)}"
        raise ValueError(error_message)

mcp = FastMCP("ORACLE")

@mcp.tool(
    name = "execute_oracle",
    description = f"""
    Oracle Databaseに対してSQLクエリを実行し、結果をフォーマットして返す。
        Args:
            query: 実行するSQLクエリ（必須）
            params: バインド変数に使用するパラメータ（辞書型　例：{{"parameter1": 5}}）
            max_length: 応答の最大文字数（integer型、デフォルト: {DEFAULT_MAX_LENGTH}）
            max_rows: 取得する最大行数（integer型、デフォルト: {DEFAULT_MAX_ROWS}）
        ヒント:
            文字数制限にかかったときは、max_lengthを大きくしてください。
            行数制限にかかったときは、max_rowsを大きくしてください。
            結果をマークダウンで表示する場合には、テーブル名に含まれる$記号記号が特殊文字として扱われるため、バックスラッシュでエスケープすることを忘れないでください。
    """)
def execute_oracle(query: str, params: dict = None, max_length: int = DEFAULT_MAX_LENGTH, max_rows: int = DEFAULT_MAX_ROWS) -> str:
    try:
        results = execute(query, params, max_length, max_rows)
        return [types.TextContent(type="text", text=str(results))]
    except Exception as e:
        return [types.TextContent(type="text", text=str(e))]
    
@mcp.tool(
    name = "describe_table",
    description = """
    データベースのテーブルの構造を表示します。
        Args:
            table_name: テーブル名（必須）
            owner: テーブルの所有者（オプション）
        ヒント:
            結果をマークダウンで表示する場合には、テーブル名に含まれる"$"記号などのエスケープを忘れないでください。
    """)
def describe_table(table_name: str, owner: str = None) -> str:
    def sanitize_table_name(table_name: str) -> str:
        # 空文字やNoneのチェック
        if not table_name or not isinstance(table_name, str):
            raise ValueError("テーブル名は必須で、文字列である必要があります")
            
        # 長さチェック（Oracleの制限は30バイト）
        if len(table_name) > 30:
            raise ValueError("テーブル名は30文字以内である必要があります")
            
        # 明らかに危険な文字のチェック
        dangerous_chars = [';', '--', '/*', '*/', "'", '"', '\x00']
        for char in dangerous_chars:
            if char in table_name:
                raise ValueError(f"テーブル名に不正な文字が含まれています: {char}")
                
        return table_name
    try:
        # 基本的なサニタイゼーション
        table_name = sanitize_table_name(table_name)
        
        # ownerのサニタイゼーション（指定された場合）
        if owner:
            owner = sanitize_table_name(owner)
        
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
            FROM all_tab_columns
            WHERE table_name = :1
            """
            if owner:
                query += " AND owner = :2"
                params = [table_name.upper(), owner.upper()]
            else:
                params = [table_name.upper()]
            query += " ORDER BY column_id"
            
            # コメント情報を取得
            comment_query = """
            SELECT column_name, comments
            FROM all_col_comments
            WHERE table_name = :1
            """
            if owner:
                comment_query += " AND owner = :2"
                comment_params = [table_name.upper(), owner.upper()]
            else:
                comment_params = [table_name.upper()]
            
            # カラム情報を取得
            columns, _ = execute_query(cursor, query, params)
            if not columns:
                raise ValueError(f"テーブル '{table_name}' が見つかりません")
            
            # コメント情報を取得
            comments, _ = execute_query(cursor, comment_query, comment_params)
            comments_dict = {row[0]: row[1] for row in comments}
            
            # 結果を整形
            output = []
            output.append(f"\nテーブル: {table_name}")
            output.append("-" * 5)
            output.append("名前\t\t\t\tNULL?\t型\t\t\t長さ\tコメント")
            output.append("-" * 5)
            
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
            
            results = "\n".join(output)
            
            return [types.TextContent(type="text", text=str(results))]
            
        finally:
            # リソースの解放
            cursor.close()
            db_connection.close()
            
    except Exception as e:
        return [types.TextContent(type="text", text=str(e))]

@mcp.tool(
    name = "list_tables",
    description = f"""
    データベース内のテーブル一覧を表示します。
        Args:
            max_rows: 取得する最大テーブル数（integer型、デフォルト: {DEFAULT_MAX_ROWS}）
            name_pattern: テーブル名のパターン（例: '%EMP%'）（オプション）
            order_by: 並び順（'TABLE_NAME'または'CREATED'、デフォルト: 'TABLE_NAME'）
            include_internal_tables: 内部テーブル（名前に$記号が含まれるテーブル）を含めるかどうか（デフォルト: False）
            use_all_tables: ALL_TABLESを参照するかどうか（デフォルト: False）
            owner: テーブルの所有者（use_all_tablesがTrueの場合は必須）
        ヒント:
            所有者を指定する場合は use_all_tables を True にして、owner を指定してください。
            特定のパターンに一致するテーブルのみを表示するには name_pattern を使用してください。
            テーブル名は基本的に大文字で格納されているため、パターンも大文字で指定すると良いでしょう。
    """)
def list_tables(max_rows: int = DEFAULT_MAX_ROWS, name_pattern: str = None, order_by: str = 'TABLE_NAME', include_internal_tables: bool = False, use_all_tables: bool = False, owner: str = None) -> str:
    try:
        # データベース接続
        db_connection, cursor = get_db_connection()
        
        try:
            # 並び順の検証
            if order_by not in ['TABLE_NAME', 'CREATED']:
                order_by = 'TABLE_NAME'  # デフォルトに戻す
                
            # 内部テーブルを除外する条件
            internal_table_condition = "AND t.table_name NOT LIKE '%$%'" if not include_internal_tables else ""
            
            # ALL_TABLESを使用する場合、OWNERの指定を必須にする
            if use_all_tables and not owner:
                raise ValueError("ALL_TABLESを使用する場合、OWNERを指定する必要があります。")
            
            # テーブルソースを選択
            table_source = 'ALL_TABLES' if use_all_tables else 'USER_TABLES'
            
            # テーブル一覧を取得
            if use_all_tables:
                query = f"""
                SELECT 
                    t.table_name,
                    t.tablespace_name,
                    TO_CHAR(t.last_analyzed, 'YYYY-MM-DD HH24:MI:SS') as last_analyzed,
                    TO_CHAR(t.num_rows) as num_rows,
                    TO_CHAR(o.created, 'YYYY-MM-DD HH24:MI:SS') as created_date
                FROM {table_source} t
                JOIN all_objects o ON t.table_name = o.object_name AND o.object_type = 'TABLE'
                WHERE t.owner = :2 {internal_table_condition}
                """
                if name_pattern:
                    query += " AND t.table_name LIKE :1"
                    params = [name_pattern.upper(), owner.upper() if owner else None]
                else:
                    params = [owner.upper() if owner else None]
                query += f" ORDER BY {order_by}"
            else:
                query = f"""
                SELECT 
                    t.table_name,
                    t.tablespace_name,
                    TO_CHAR(t.last_analyzed, 'YYYY-MM-DD HH24:MI:SS') as last_analyzed,
                    TO_CHAR(t.num_rows) as num_rows,
                    TO_CHAR(o.created, 'YYYY-MM-DD HH24:MI:SS') as created_date
                FROM {table_source} t
                JOIN all_objects o ON t.table_name = o.object_name AND o.object_type = 'TABLE'
                WHERE 1=1 {internal_table_condition}
                """
                if name_pattern:
                    query += " AND t.table_name LIKE :1"
                    params = [name_pattern.upper()]
                else:
                    params = None
                query += f" ORDER BY {order_by}"
                
            # テーブル一覧を取得
            results, more_rows_exist = execute_query(cursor, query, params, max_rows)
            
            if not results:
                return [types.TextContent(type="text", text="テーブルが見つかりません")]
            
            # 結果を整形
            output = []
            output.append("\nテーブル一覧:")
            output.append("-" * 100)
            output.append("テーブル名\t\t\t\tテーブルスペース\t\t最終分析日時\t\t\t行数\t\t作成日時")
            output.append("-" * 100)
            
            for row in results:
                table_name, tablespace_name, last_analyzed, num_rows, created_date = row
                output.append(f"{table_name.ljust(30)}\t{(tablespace_name or '').ljust(20)}\t{(last_analyzed or '').ljust(20)}\t{(num_rows or '').ljust(10)}\t{created_date or ''}")
            
            if more_rows_exist:
                output.append("\n(行数制限により以降は省略。max_rows値を増やして再実行してください。)")
                
            results = "\n".join(output)
            
            return [types.TextContent(type="text", text=str(results))]
            
        finally:
            # リソースの解放
            cursor.close()
            db_connection.close()
            
    except Exception as e:
        return [types.TextContent(type="text", text=str(e))]



if __name__ == "__main__":
    # stdioで通信
    mcp.run(transport="stdio")
