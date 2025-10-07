
from fpdf import FPDF
from datetime import datetime

def generate_pdf_report(report_data):
    """
    Generates a PDF report of the hardening results.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Security Hardening Report", ln=True, align="C")
    pdf.cell(200, 10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(10)

    # Table Header
    pdf.cell(60, 10, "Parameter", 1)
    pdf.cell(50, 10, "Previous Value", 1)
    pdf.cell(50, 10, "Current Value", 1)
    pdf.cell(30, 10, "Status", 1)
    pdf.ln()

    for item in report_data:
        pdf.cell(60, 10, item['parameter'], 1)
        pdf.cell(50, 10, str(item['previous_value']), 1)
        pdf.cell(50, 10, str(item['current_value']), 1)
        pdf.cell(30, 10, item['status'], 1)
        pdf.ln()

    report_path = f"reports/hardening_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_path)
    return report_path
