"""
Convert Agent Analysis Report to PDF
"""
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas
import re
from datetime import datetime

def parse_markdown_to_pdf(md_file, pdf_file):
    """Convert markdown report to PDF with professional formatting"""
    
    # Read markdown content
    with open(md_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create PDF
    doc = SimpleDocTemplate(
        pdf_file,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    # Define styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    h1_style = ParagraphStyle(
        'CustomH1',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=20,
        fontName='Helvetica-Bold',
        borderWidth=0,
        borderColor=colors.HexColor('#3498db'),
        borderPadding=5
    )
    
    h2_style = ParagraphStyle(
        'CustomH2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=10,
        spaceBefore=15,
        fontName='Helvetica-Bold'
    )
    
    h3_style = ParagraphStyle(
        'CustomH3',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#7f8c8d'),
        spaceAfter=8,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=10,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=6,
        alignment=TA_JUSTIFY,
        fontName='Helvetica'
    )
    
    code_style = ParagraphStyle(
        'CustomCode',
        parent=styles['Code'],
        fontSize=9,
        textColor=colors.HexColor('#c0392b'),
        fontName='Courier',
        backColor=colors.HexColor('#f8f9fa'),
        borderWidth=1,
        borderColor=colors.HexColor('#dee2e6'),
        borderPadding=5
    )
    
    # Story (content container)
    story = []
    
    # Parse markdown
    lines = content.split('\n')
    i = 0
    in_code_block = False
    code_buffer = []
    in_table = False
    table_buffer = []
    
    while i < len(lines):
        line = lines[i].rstrip()
        
        # Skip mermaid diagrams
        if '```mermaid' in line:
            while i < len(lines) and '```' not in lines[i+1]:
                i += 1
            i += 2
            continue
        
        # Code blocks
        if line.startswith('```'):
            if in_code_block:
                # End code block
                code_text = '\n'.join(code_buffer)
                story.append(Paragraph(f'<font name="Courier" size="8">{code_text}</font>', code_style))
                story.append(Spacer(1, 0.2*inch))
                code_buffer = []
                in_code_block = False
            else:
                # Start code block
                in_code_block = True
            i += 1
            continue
        
        if in_code_block:
            code_buffer.append(line.replace('<', '&lt;').replace('>', '&gt;'))
            i += 1
            continue
        
        # Tables
        if '|' in line and line.strip().startswith('|'):
            if not in_table:
                in_table = True
                table_buffer = []
            table_buffer.append(line)
            i += 1
            continue
        elif in_table:
            # End of table
            if table_buffer:
                table_data = parse_table(table_buffer)
                if table_data:
                    t = Table(table_data, hAlign='LEFT')
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 0.2*inch))
            in_table = False
            table_buffer = []
        
        # Headers
        if line.startswith('# ') and not line.startswith('## '):
            text = line[2:].strip()
            if i == 0:  # Title
                story.append(Paragraph(text, title_style))
            else:
                story.append(PageBreak())
                story.append(Paragraph(text, h1_style))
            story.append(Spacer(1, 0.1*inch))
        elif line.startswith('## '):
            text = line[3:].strip()
            story.append(Paragraph(text, h2_style))
        elif line.startswith('### '):
            text = line[4:].strip()
            story.append(Paragraph(text, h3_style))
        elif line.startswith('#### '):
            text = line[5:].strip()
            story.append(Paragraph(f'<b>{text}</b>', body_style))
        
        # Horizontal rules
        elif line.strip() == '---':
            story.append(Spacer(1, 0.1*inch))
            story.append(Table([['']], colWidths=[7*inch], style=[
                ('LINEABOVE', (0, 0), (-1, 0), 2, colors.HexColor('#3498db'))
            ]))
            story.append(Spacer(1, 0.1*inch))
        
        # Lists
        elif line.strip().startswith('- ') or line.strip().startswith('* '):
            text = line.strip()[2:]
            text = format_inline_markdown(text)
            story.append(Paragraph(f'• {text}', body_style))
        elif re.match(r'^\d+\.\s', line.strip()):
            text = re.sub(r'^\d+\.\s', '', line.strip())
            text = format_inline_markdown(text)
            story.append(Paragraph(f'{text}', body_style))
        
        # Regular paragraphs
        elif line.strip():
            text = format_inline_markdown(line)
            story.append(Paragraph(text, body_style))
            story.append(Spacer(1, 0.05*inch))
        
        # Empty lines
        else:
            story.append(Spacer(1, 0.1*inch))
        
        i += 1
    
    # Build PDF
    doc.build(story)
    print(f"✅ PDF generated successfully: {pdf_file}")

def parse_table(table_lines):
    """Parse markdown table into data structure"""
    if len(table_lines) < 2:
        return None
    
    data = []
    for line in table_lines:
        if '---' in line:  # Skip separator line
            continue
        cells = [cell.strip() for cell in line.split('|')[1:-1]]
        if cells:
            data.append(cells)
    
    return data if data else None

def format_inline_markdown(text):
    """Format inline markdown (bold, italic, code, links)"""
    # Bold
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    # Italic
    text = re.sub(r'\*(.+?)\*', r'<i>\1</i>', text)
    # Code
    text = re.sub(r'`(.+?)`', r'<font name="Courier" color="#c0392b">\1</font>', text)
    # Links (remove markdown syntax, keep text)
    text = re.sub(r'\[(.+?)\]\(.+?\)', r'\1', text)
    # Checkmarks
    text = text.replace('✅', '✓').replace('⚠️', '⚠').replace('❌', '✗')
    text = text.replace('⭐', '*')
    
    return text

if __name__ == '__main__':
    md_file = r'C:\Users\khanj\.gemini\antigravity\brain\9da4ec4c-bfd7-4904-9aa1-234dc877248e\agent_analysis_report.md'
    pdf_file = r'C:\Users\khanj\.gemini\antigravity\brain\9da4ec4c-bfd7-4904-9aa1-234dc877248e\agent_analysis_report.pdf'
    
    print("🔄 Converting markdown to PDF...")
    parse_markdown_to_pdf(md_file, pdf_file)
    print(f"📄 PDF saved to: {pdf_file}")
