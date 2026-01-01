from convert_to_pdf import parse_markdown_to_pdf
import os

md_file = r'C:\Users\khanj\.gemini\antigravity\brain\3afa3eb2-a1d9-43e5-a017-7847f94ec9af\walkthrough.md'
pdf_file = r'C:\Users\khanj\.gemini\antigravity\brain\3afa3eb2-a1d9-43e5-a017-7847f94ec9af\walkthrough.pdf'

if __name__ == '__main__':
    print(f"🔄 Converting {md_file} to PDF...")
    if os.path.exists(md_file):
        parse_markdown_to_pdf(md_file, pdf_file)
        print(f"📄 PDF saved to: {pdf_file}")
    else:
        print(f"❌ Markdown file not found: {md_file}")
