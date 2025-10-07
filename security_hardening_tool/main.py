
import argparse
from modules.os_detector import detect_os
from modules.hardening_engine import apply_hardening
from modules.reporting import generate_pdf_report
from modules.rollback import rollback_changes

def main():
    parser = argparse.ArgumentParser(description="Automated Security Hardening Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Apply command
    apply_parser = subparsers.add_parser("apply", help="Apply hardening policies")
    apply_parser.add_argument("--level", required=True, choices=["basic", "moderate", "strict"], help="Hardening level")

    # Rollback command
    rollback_parser = subparsers.add_parser("rollback", help="Rollback changes")
    rollback_parser.add_argument("--timestamp", required=True, help="Timestamp of the rollback file (e.g., 20231027_103000)")

    args = parser.parse_args()

    os_name = detect_os()
    if os_name == "unsupported":
        print("Unsupported operating system.")
        return

    if args.command == "apply":
        print(f"Applying {args.level} hardening for {os_name}...")
        report_data = apply_hardening(os_name, args.level)
        report_path = generate_pdf_report(report_data)
        print(f"Hardening complete. Report generated at: {report_path}")

    elif args.command == "rollback":
        print(f"Rolling back changes from timestamp: {args.timestamp}...")
        rollback_changes(args.timestamp)
        print("Rollback complete.")

if __name__ == "__main__":
    main()
