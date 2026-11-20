import os, csv, io
from flask import (Blueprint, render_template, jsonify,
                   send_file, make_response, current_app, request)
from flask_login import login_required, current_user

from app.extensions import db
from app.models.detection import DetectionHistory

reports_bp = Blueprint('reports_bp', __name__)


@reports_bp.route('/')
@login_required
def index():
    detections = DetectionHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(DetectionHistory.created_at.desc()).limit(50).all()
    return render_template('reports/index.html',
                           title='Reports', detections=detections)


@reports_bp.route('/<int:detection_id>/pdf')
@login_required
def generate_pdf(detection_id):
    d = DetectionHistory.query.filter_by(
        id=detection_id, user_id=current_user.id
    ).first_or_404()
    try:
        pdf_bytes = _build_pdf(d)
        buf = io.BytesIO(pdf_bytes)
        buf.seek(0)
        return send_file(buf,
                         mimetype='application/pdf',
                         as_attachment=True,
                         download_name=f'cybershield_report_{detection_id}.pdf')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/<int:detection_id>/csv')
@login_required
def generate_csv(detection_id):
    d = DetectionHistory.query.filter_by(
        id=detection_id, user_id=current_user.id
    ).first_or_404()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Field', 'Value'])
    writer.writerow(['Report ID',      detection_id])
    writer.writerow(['Module',         d.module])
    writer.writerow(['Input',          d.input_summary])
    writer.writerow(['Result',         d.result])
    writer.writerow(['Risk Score',     d.risk_score])
    writer.writerow(['Risk Level',     d.risk_level])
    writer.writerow(['Model Used',     d.model_used or 'N/A'])
    writer.writerow(['Timestamp',      d.created_at.isoformat()])
    writer.writerow([])
    writer.writerow(['Indicators'])
    for ind in d.indicators:
        writer.writerow(['', ind])
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = \
        f'attachment; filename=cybershield_report_{detection_id}.csv'
    return resp


from datetime import datetime
from app.services.excel_export import generate_enterprise_detection_excel

@reports_bp.route('/export/excel')
@login_required
def export_excel():
    """Download enterprise-grade formatted .xlsx detection report."""
    buf = generate_enterprise_detection_excel(request.args, current_user)
    timestamp_str = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"cybershield_detection_report_{timestamp_str}.xlsx"
    return send_file(
        buf,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )


@reports_bp.route('/export/all')
@login_required
def export_all():
    detections = DetectionHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(DetectionHistory.created_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Module', 'Input', 'Result',
                     'Risk Score', 'Risk Level', 'Model', 'Timestamp'])
    for d in detections:
        writer.writerow([d.id, d.module, d.input_summary, d.result,
                         d.risk_score, d.risk_level,
                         d.model_used or 'N/A',
                         d.created_at.isoformat()])
    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename=cybershield_all_detections.csv'
    return resp


def _build_pdf(d: DetectionHistory) -> bytes:
    """Generate a PDF report using ReportLab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, HRFlowable)
    from reportlab.lib.units import cm

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    title_style  = ParagraphStyle('Title',  parent=styles['Title'],
                                   textColor=colors.HexColor('#003366'),
                                   fontSize=20)
    head_style   = ParagraphStyle('Heading', parent=styles['Heading2'],
                                   textColor=colors.HexColor('#003366'))
    normal_style = styles['Normal']

    RISK_COLORS_PDF = {
        'Very Low': colors.green,
        'Low':      colors.lightgreen,
        'Medium':   colors.orange,
        'High':     colors.orangered,
        'Critical': colors.red,
    }

    story = []
    story.append(Paragraph('🛡 CyberShield AI — Security Report', title_style))
    story.append(HRFlowable(width='100%', thickness=2,
                             color=colors.HexColor('#003366')))
    story.append(Spacer(1, 0.4*cm))

    # Summary table
    risk_color = RISK_COLORS_PDF.get(d.risk_level, colors.grey)
    data = [
        ['Field',        'Value'],
        ['Module',       d.module.replace('_', ' ').title()],
        ['Input',        d.input_summary],
        ['Result',       d.result],
        ['Risk Score',   f'{d.risk_score}/100'],
        ['Risk Level',   d.risk_level],
        ['Model Used',   d.model_used or 'N/A'],
        ['Analysis Time', d.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
    ]
    tbl = Table(data, colWidths=[5*cm, 12*cm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#003366')),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 4), (1, 4), risk_color),
        ('TEXTCOLOR',  (0, 4), (1, 4), colors.white),
        ('GRID',       (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f4f8')]),
        ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING',    (0, 0), (-1, -1), 6),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.6*cm))

    # Indicators
    story.append(Paragraph('Detection Indicators', head_style))
    story.append(HRFlowable(width='100%', thickness=1, color=colors.grey))
    for ind in d.indicators:
        story.append(Paragraph(f'• {ind}', normal_style))
    story.append(Spacer(1, 0.4*cm))

    # Disclaimer
    story.append(Paragraph(
        '<i>This report is generated by CyberShield AI for educational and '
        'security research purposes. Results should be verified by a '
        'qualified security professional before taking action.</i>',
        ParagraphStyle('Disc', parent=normal_style,
                       textColor=colors.grey, fontSize=8)
    ))

    doc.build(story)
    return buf.getvalue()
