#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET

# Список критических идентификаторов и CWE для C-кода в РБПО
CRITICAL_SECURITY_IDS = [
    "bufferaccessoutofbounds", 
    "nullpointer", 
    "nullpointerarithmetic",
    "nullpointerredundantcheck",
    "possiblebufferaccessoutofbounds"
]
# 120 / 788 / 119 - Переполнения буфера
# 476 - Разыменование NULL
CRITICAL_CWES = ["120", "476", "401", "119", "788"]

def main():
    if len(sys.argv) < 2:
        print("Использование: python3 security_gate.py <sast-report.xml>")
        sys.exit(1)

    report_path = sys.argv[1]
    try:
        tree = ET.parse(report_path)
        root = tree.getroot()
    except Exception as e:
        print(f"[SECURITY GATE ERROR] Не удалось прочитать XML-отчёт: {e}")
        sys.exit(1)

    errors = root.findall(".//error")
    critical_defects = []
    warnings_list = []
    seen_issues = set()  # Для исключения дубликатов на соседних строках

    for err in errors:
        sev = err.get("severity", "unknown").lower()
        err_id = err.get("id", "generic").lower()
        msg = err.get("msg", "")
        cwe = err.get("cwe", "N/A")

        loc = err.find("location")
        file_path = loc.get("file", "unknown") if loc is not None else "unknown"
        line = loc.get("line", "0") if loc is not None else "0"

        # Уникальный ключ дефекта
        issue_key = (file_path, line, err_id)
        if issue_key in seen_issues:
            continue
        seen_issues.add(issue_key)

        defect = {
            "cwe": cwe,
            "id": err_id,
            "file": file_path,
            "line": line,
            "msg": msg,
            "severity": sev
        }

        # Блокируем при наличии Severity Error или известных критических CWE/ID
        is_security_violation = (
            sev in ["error", "critical"] or
            cwe in CRITICAL_CWES or
            any(crit_id in err_id for crit_id in CRITICAL_SECURITY_IDS)
        )

        if is_security_violation:
            critical_defects.append(defect)
        else:
            warnings_list.append(defect)

    print("\n" + "=" * 70)
    print("      SECURITY GATE: АНАЛИЗ БЕЗОПАСНОСТИ СЕРВЕРА НКУ")
    print("=" * 70)
    print(f"Критические уязвимости памяти (BLOCKER) : {len(critical_defects)} (Лимит: 0)")
    print(f"Остальные замечания           (WARNING) : {len(warnings_list)}")
    print("=" * 70)

    if critical_defects:
        print("\n[!] ОБНАРУЖЕНЫ УЯЗВИМОСТИ:")
        for idx, item in enumerate(critical_defects, 1):
            print(f"  {idx}. [CWE-{item['cwe']}] {item['id'].upper()}")
            print(f"     Файл: {item['file']}:{item['line']}")
            print(f"     Инфо: {item['msg']}\n")

        print("=" * 70)
        print("[FAIL] РЕЗУЛЬТАТ: ПО содержит критические уязвимости!")
        print("=" * 70 + "\n")
        sys.exit(1)
    else:
        print("\n" + "=" * 70)
        print("[PASS] РЕЗУЛЬТАТ: Security Gate пройден успешно. Уязвимостей нет.")
        print("=" * 70 + "\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
