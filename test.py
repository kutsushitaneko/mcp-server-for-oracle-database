import json
from oracledb_mcp_server import execute_oracle, describe_table


result = execute_oracle(
    query="SELECT IMAGE_ID, FILE_NAME, CAPTION FROM images WHERE IMAGE_ID < :param1",
    params={"param1": "5"},
    max_length=10000,
    max_rows=200
)

# result = describe_table(
#     table_name="images"
# )

print(result)
