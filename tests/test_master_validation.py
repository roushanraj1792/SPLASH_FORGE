import subprocess
import sys
import py_compile
from pathlib import Path


# ============================================================
# SENTINELX MASTER VALIDATION SUITE
# ============================================================

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"


results = []


def record(name, passed, detail=""):
    results.append(
        {
            "name": name,
            "passed": passed,
            "detail": detail,
        }
    )


def run_test(name, test_file):

    print()
    print("=" * 60)
    print(f"RUNNING: {name}")
    print("=" * 60)

    try:

        result = subprocess.run(
            [
                sys.executable,
                str(test_file)
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=120
        )

        output = result.stdout.strip()
        error = result.stderr.strip()

        if output:
            print(output)

        if error:
            print()
            print("STDERR:")
            print(error)

        passed = result.returncode == 0

        record(
            name,
            passed,
            f"Exit Code: {result.returncode}"
        )

        return passed

    except subprocess.TimeoutExpired:

        print("TEST TIMEOUT")

        record(
            name,
            False,
            "Timeout after 120 seconds"
        )

        return False

    except Exception as error:

        print("TEST ERROR:", error)

        record(
            name,
            False,
            str(error)
        )

        return False


print()
print("=" * 60)
print("        SENTINELX MASTER VALIDATION SUITE")
print("=" * 60)


# ============================================================
# STEP 1 — PYTHON SYNTAX CHECK
# ============================================================

print()
print("=" * 60)
print("RUNNING: Python Syntax Validation")
print("=" * 60)

python_files = []

for folder in [
    ROOT / "database",
    ROOT / "detection",
    ROOT / "services",
    ROOT / "simulator",
    ROOT / "tests",
]:
    if folder.exists():

        for file in folder.rglob("*.py"):

            if (
                "__pycache__" not in file.parts
                and "venv" not in file.parts
                and "backup" not in file.name.lower()
                and file.name != "test_master_validation.py"
            ):
                python_files.append(file)


python_files.append(ROOT / "app.py")


syntax_failed = []

for file in python_files:

    try:
        py_compile.compile(
            str(file),
            doraise=True
        )

    except Exception as error:

        syntax_failed.append(
            f"{file}: {error}"
        )


if syntax_failed:

    print("Syntax errors found:")

    for error in syntax_failed:
        print(error)

    record(
        "Python Syntax",
        False,
        f"{len(syntax_failed)} syntax error(s)"
    )

else:

    print(
        f"Compiled {len(python_files)} Python files successfully."
    )

    record(
        "Python Syntax",
        True,
        f"{len(python_files)} files compiled"
    )


# ============================================================
# STEP 2 — DISCOVER ALL EXISTING TESTS
# ============================================================

test_files = []

for file in TESTS_DIR.rglob("test_*.py"):

    if file.name == "test_master_validation.py":
        continue

    if "__pycache__" in file.parts:
        continue

    test_files.append(file)


test_files.sort()


print()
print("=" * 60)
print("DISCOVERED TESTS")
print("=" * 60)

for file in test_files:
    print(
        " -",
        file.relative_to(ROOT)
    )


# ============================================================
# STEP 3 — RUN EVERY TEST
# ============================================================

for test_file in test_files:

    relative_name = str(
        test_file.relative_to(ROOT)
    )

    run_test(
        relative_name,
        test_file
    )


# ============================================================
# STEP 4 — FINAL REPORT
# ============================================================

print()
print()
print("=" * 60)
print("        SENTINELX MASTER VALIDATION REPORT")
print("=" * 60)

passed_count = 0
failed_count = 0


for result in results:

    if result["passed"]:

        print(
            f"[PASS] {result['name']}"
        )

        passed_count += 1

    else:

        print(
            f"[FAIL] {result['name']}"
        )

        if result["detail"]:
            print(
                f"       {result['detail']}"
            )

        failed_count += 1


total_count = len(results)


print()
print("=" * 60)
print(f"TOTAL TESTS : {total_count}")
print(f"PASSED      : {passed_count}")
print(f"FAILED      : {failed_count}")
print("=" * 60)


if failed_count == 0:

    print()
    print(
        "RESULT: SENTINELX MASTER VALIDATION PASS"
    )
    print()


else:

    print()
    print(
        "RESULT: SENTINELX MASTER VALIDATION FAIL"
    )
    print()
