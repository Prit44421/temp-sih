
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from .os_detector import detect_os
from .hardening_engine import apply_hardening
from .reporting import generate_pdf_report
from .rollback import rollback_changes, ROLLBACK_DIR
import os

console = Console()

def display_main_menu():
    """Displays the main menu."""
    console.print(Panel.fit(
        "[bold cyan]Automated Security Hardening Tool[/bold cyan]\n\n"
        "1. Apply Hardening\n"
        "2. Rollback Changes\n"
        "3. Exit",
        title="Main Menu"
    ))

def apply_hardening_ui():
    """UI for applying hardening policies."""
    os_name = detect_os()
    if os_name == "unsupported":
        console.print("[bold red]Unsupported operating system.[/bold red]")
        return

    console.print(f"Detected OS: [bold green]{os_name}[/bold green]")
    level = Prompt.ask("Choose hardening level", choices=["basic", "moderate", "strict"])

    with console.status("[bold green]Applying hardening rules...[/bold green]"):
        report_data = apply_hardening(os_name, level)
        report_path = generate_pdf_report(report_data)

    console.print("\n[bold green]Hardening Complete![/bold green]")
    console.print(f"Report generated at: [cyan]{report_path}[/cyan]\n")
    
    console.print(Panel.fit(
        "Parameter | Previous Value | Current Value | Status\n" +
        "---|---|---|---\n" +
        "\n".join([f"{item['parameter']} | {item['previous_value']} | {item['current_value']} | {item['status']}" for item in report_data]),
        title="Hardening Report"
    ))


def rollback_ui():
    """UI for rolling back changes."""
    console.print("\n[bold cyan]Available Rollback Points:[/bold cyan]")
    
    rollback_files = [f for f in os.listdir(ROLLBACK_DIR) if f.endswith('.json')]
    if not rollback_files:
        console.print("[yellow]No rollback points found.[/yellow]")
        return

    for i, filename in enumerate(rollback_files):
        console.print(f"{i + 1}. {filename}")

    choice = Prompt.ask("Choose a rollback point (number)", choices=[str(i+1) for i in range(len(rollback_files))])
    selected_file = rollback_files[int(choice) - 1]
    timestamp = selected_file.replace("rollback_", "").replace(".json", "")


    with console.status(f"[bold yellow]Rolling back changes from {timestamp}...[/bold yellow]"):
        rollback_changes(timestamp)
    
    console.print("\n[bold green]Rollback Complete![/bold green]\n")


def run():
    """Main function to run the TUI."""
    while True:
        display_main_menu()
        choice = Prompt.ask("Enter your choice", choices=["1", "2", "3"])

        if choice == "1":
            apply_hardening_ui()
        elif choice == "2":
            rollback_ui()
        elif choice == "3":
        
            break
