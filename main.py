import json

from app.firewall import run_firewall
from app.memory_gate import propose_memory, write_memory_if_allowed
from app.report_generator import generate_report


def menu():
    print("\nFAMILY OS - CONTEXT FIREWALL")
    print("1. Test prompt injection firewall")
    print("2. Propose memory")
    print("3. Exit")


def firewall_demo():
    print("\nTrusted user instruction:")
    user_instruction = input("> ")

    print("\nPaste untrusted content. End with a blank line:")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)

    untrusted_content = "\n".join(lines)

    result = run_firewall(
        user_instruction=user_instruction,
        untrusted_content=untrusted_content,
        untrusted_source_type="web_content",
    )

    print("\n=== SAFE OUTPUT ===")
    print(result["safe_output"])

    print("\n=== SECURITY ANALYSIS ===")
    print(json.dumps(result["security_analysis"], indent=2))

    print("\nGenerate report? yes/no:")
    make_report = input("> ").strip().lower() == "yes"
    if make_report:
        print("\nClient/demo name:")
        client_name = input("> ").strip() or "Demo Client"
        report_path = generate_report(result, client_name)
        print(f"\nReport created: {report_path}")

    print("\n=== LABELED CONTEXT ===")
    print(result["labeled_context"])


def memory_demo():
    print("\nMemory content:")
    content = input("> ")

    print("\nSource type direct_user/web_content/email_content/local_file:")
    source_type = input("> ").strip()

    print("\nHuman approved? yes/no:")
    approved = input("> ").strip().lower() == "yes"

    record = propose_memory(content, source_type, approved)
    written = write_memory_if_allowed(record)

    print("\n=== MEMORY RECORD ===")
    print(json.dumps(record, indent=2))
    print(f"\nWritten to ledger: {written}")


if __name__ == "__main__":
    while True:
        menu()
        choice = input("\nChoose: ").strip()

        if choice == "1":
            firewall_demo()
        elif choice == "2":
            memory_demo()
        elif choice == "3":
            break
        else:
            print("Invalid choice.")
