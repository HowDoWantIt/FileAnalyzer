import os
import mimetypes
import magic
import chardet
from pdfminer.high_level import extract_text as extract_pdf_text
from docx import Document
from .heuristics import heuristic_flags
from .pe_analysis import analyze_pe

def detect_file_type(filepath):
    mime_type, _ = mimetypes.guess_type(filepath)
    if not mime_type:
        mime_type = magic.from_file(filepath, mime=True)
    return mime_type

def read_text_file(filepath):
    with open(filepath, 'rb') as f:
        raw = f.read()
        encoding = chardet.detect(raw)['encoding']
        return raw.decode(encoding or 'utf-8', errors='ignore')

def extract_docx(filepath):
    doc = Document(filepath)
    return '\n'.join(p.text for p in doc.paragraphs)

def analyze_content(content):
    lines = content.lower().splitlines()
    summary = {
        'imports': [],
        'keywords': [],
        'uses_internet': False,
        'file_operations': False,
        'heuristic_flags': []
    }

    for line in lines:
        if 'import ' in line:
            summary['imports'].append(line.strip())
        if 'open(' in line or 'read(' in line or 'write(' in line:
            summary['file_operations'] = True
        if 'requests' in line or 'socket' in line or 'http' in line:
            summary['uses_internet'] = True
        if 'password' in line or 'token' in line:
            summary['keywords'].append('password or token usage')

    summary['heuristic_flags'] = heuristic_flags(content)

    return summary

def create_reports(filepath):
    mime_type = detect_file_type(filepath)
    filename = os.path.basename(filepath)
    full_report = {
        'filename': filename,
        'mime_type': mime_type,
        'analysis': {}
    }

    try:
        if mime_type and mime_type.startswith('text'):
            content = read_text_file(filepath)
        elif filename.lower().endswith('.py'):
            content = read_text_file(filepath)
        elif mime_type == 'application/pdf':
            content = extract_pdf_text(filepath)
        elif filename.lower().endswith('.docx'):
            content = extract_docx(filepath)
        elif filename.lower().endswith('.exe'):
            # تحلیل فایل اجرایی
            pe_info = analyze_pe(filepath)
            full_report['analysis']['pe_info'] = pe_info
            content = ""
        else:
            return {
                'summary': f'⚠️ فرمت فایل {mime_type} پشتیبانی نمی‌شود.',
                'full': full_report
            }

        if content:
            summary = analyze_content(content)
            full_report['analysis'].update(summary)

        # ساخت متن گزارش خلاصه
        summary_text = f"📄 فایل: {filename}\n"
        summary_text += f"🧾 نوع: {mime_type}\n"
        imports = full_report['analysis'].get('imports', [])
        summary_text += f"📥 ایمپورت‌ها: {', '.join(imports) if imports else 'ندارد'}\n"
        summary_text += f"🌐 استفاده از اینترنت: {full_report['analysis'].get('uses_internet', False)}\n"
        summary_text += f"🗂 عملیات فایل: {full_report['analysis'].get('file_operations', False)}\n"
        keywords = full_report['analysis'].get('keywords', [])
        summary_text += f"⚠️ کلمات کلیدی: {', '.join(keywords) if keywords else 'ندارد'}\n"
        heuristics = full_report['analysis'].get('heuristic_flags', [])
        summary_text += f"⚠️ پرچم‌های Heuristic: {', '.join(heuristics) if heuristics else 'ندارد'}\n"

        if 'pe_info' in full_report['analysis']:
            pe = full_report['analysis']['pe_info']
            if 'error' in pe:
                summary_text += f"❌ خطا در تحلیل PE: {pe['error']}\n"
            else:
                summary_text += f"🔍 PE Entry Point: {pe.get('entry_point', 'N/A')}\n"
                summary_text += f"🔍 PE Image Base: {pe.get('image_base', 'N/A')}\n"
                summary_text += f"🔍 PE Sections: {', '.join(pe.get('sections', []))}\n"

        return {
            'summary': summary_text,
            'full': full_report
        }

    except Exception as e:
        return {
            'summary': f"خطا در خواندن فایل: {str(e)}",
            'full': full_report
        }
