import re, itertools
from utils.requester import *
from threading import Thread, Semaphore
from config import *


tech = "Error Based SQL Injection"
SQL_ERROR_BASED_ERRORS = {
    "Other":                (r"Internal Server Error",),
    "MySQL":                (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL":           (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access":     (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle":               (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2":              (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite":               (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase":               (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*")
}
ERROR_BASED_SQL = ('\'', '"', '(', ')')

def exec(data):
    for pos, payload in itertools.product(POSITIONS, ERROR_BASED_SQL):
        for parameter in data[pos].keys():
            r = single_request(data, pos, parameter, payload)
            for backend, vs in SQL_ERROR_BASED_ERRORS.items():
                for v in vs:
                    if re.search(v, r.text):
                        print(f"■■■{tech}■■■{backend}■■■{pos}■■■{parameter}■■■{payload}■■■")
                        return True