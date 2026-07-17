"""
DefendX — Report Generator
Generates PDF threat assessment reports with charts and user profiles.
"""

import os
from datetime import datetime

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                     TableStyle, Image, PageBreak, HRFlowable)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class ReportGenerator:
    """Generates PDF threat assessment reports."""
    
    def __init__(self, threat_analyzer, alert_manager):
        self.analyzer = threat_analyzer
        self.alerts = alert_manager
    
    def generate_pdf(self, output_path: str, title: str = None) -> str:
        """Generate a comprehensive PDF threat report."""
        if not HAS_REPORTLAB:
            return 'Error: reportlab not installed'
        
        if title is None:
            title = f'DefendX Threat Assessment Report — {datetime.now().strftime("%Y-%m-%d")}'
        
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        
        doc = SimpleDocTemplate(output_path, pagesize=A4,
                               topMargin=20*mm, bottomMargin=20*mm,
                               leftMargin=15*mm, rightMargin=15*mm)
        
        styles = getSampleStyleSheet()
        
        # Custom styles
        styles.add(ParagraphStyle(
            'ReportTitle', parent=styles['Title'],
            fontSize=22, textColor=colors.HexColor('#00d4ff'),
            spaceAfter=10,
        ))
        styles.add(ParagraphStyle(
            'SectionHeader', parent=styles['Heading1'],
            fontSize=16, textColor=colors.HexColor('#00d4ff'),
            spaceBefore=15, spaceAfter=8,
        ))
        styles.add(ParagraphStyle(
            'SubHeader', parent=styles['Heading2'],
            fontSize=13, textColor=colors.HexColor('#a855f7'),
            spaceBefore=10, spaceAfter=5,
        ))
        styles.add(ParagraphStyle(
            'DefendXBodyText', parent=styles['Normal'],
            fontSize=10, textColor=colors.HexColor('#333333'),
            spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            'CriticalText', parent=styles['Normal'],
            fontSize=10, textColor=colors.HexColor('#ff0000'),
            fontName='Helvetica-Bold',
        ))
        
        story = []
        
        # ── Title Page ──
        story.append(Spacer(1, 40))
        story.append(Paragraph('DefendX', styles['ReportTitle']))
        story.append(Paragraph('AI-Based Insider Threat Detection System',
                              styles['SubHeader']))
        story.append(Spacer(1, 15))
        story.append(HRFlowable(width='100%', thickness=2,
                               color=colors.HexColor('#00d4ff')))
        story.append(Spacer(1, 15))
        story.append(Paragraph(
            f'<b>Report Generated:</b> {datetime.now().strftime("%B %d, %Y at %H:%M")}',
            styles['DefendXBodyText']
        ))
        story.append(Paragraph(
            '<b>Classification:</b> CONFIDENTIAL — Internal Use Only',
            styles['CriticalText']
        ))
        story.append(Spacer(1, 25))
        
        # ── Executive Summary ──
        story.append(Paragraph('Executive Summary', styles['SectionHeader']))
        story.append(HRFlowable(width='100%', thickness=1,
                               color=colors.HexColor('#30363d')))
        
        stats = self.analyzer.get_anomaly_stats()
        dist = self.analyzer.get_threat_distribution()
        
        summary_text = (
            f'This report provides an automated threat assessment based on AI analysis '
            f'of {stats.get("total_users", 0)} monitored employees. '
            f'The Isolation Forest anomaly detection model identified '
            f'{stats.get("anomalies", 0)} behavioral anomalies. '
            f'The mean threat score across the organization is '
            f'{stats.get("mean_threat_score", 0):.1f}/100.'
        )
        story.append(Paragraph(summary_text, styles['DefendXBodyText']))
        
        # Threat distribution table
        story.append(Spacer(1, 10))
        story.append(Paragraph('Threat Distribution', styles['SubHeader']))
        
        dist_data = [['Threat Level', 'Users', 'Percentage']]
        total = stats.get('total_users', 1) or 1
        for level in ['Critical', 'High', 'Medium', 'Low']:
            count = dist.get(level, 0)
            pct = f'{count/total*100:.1f}%'
            dist_data.append([level, str(count), pct])
        
        dist_table = Table(dist_data, colWidths=[120, 80, 80])
        dist_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161b22')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#30363d')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.HexColor('#f8f9fa'), colors.white]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(dist_table)
        
        # ── Top Threats ──
        story.append(Spacer(1, 20))
        story.append(Paragraph('Top 10 Highest-Risk Users', styles['SectionHeader']))
        story.append(HRFlowable(width='100%', thickness=1,
                               color=colors.HexColor('#30363d')))
        
        top = self.analyzer.get_top_threats(10)
        if len(top) > 0:
            threat_data = [['Rank', 'User ID', 'Threat Score', 'Level', 'Anomaly']]
            for i, (_, row) in enumerate(top.iterrows(), 1):
                threat_data.append([
                    str(i),
                    str(row['user']),
                    f'{row.get("threat_score", 0):.1f}',
                    str(row.get('threat_level', 'N/A')),
                    'YES' if row.get('is_anomaly', False) else 'No',
                ])
            
            threat_table = Table(threat_data, colWidths=[40, 100, 90, 80, 80])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#161b22')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00d4ff')),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#30363d')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [colors.HexColor('#f8f9fa'), colors.white]),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(threat_table)
        
        # ── Alert Summary ──
        story.append(Spacer(1, 20))
        story.append(Paragraph('Alert Summary', styles['SectionHeader']))
        story.append(HRFlowable(width='100%', thickness=1,
                               color=colors.HexColor('#30363d')))
        
        alert_counts = self.alerts.get_unresolved_count()
        alert_text = (
            f'Active alerts: {self.alerts.get_total_unresolved()} unresolved. '
            f'Critical: {alert_counts.get("CRITICAL", 0)}, '
            f'High: {alert_counts.get("HIGH", 0)}, '
            f'Medium: {alert_counts.get("MEDIUM", 0)}, '
            f'Low: {alert_counts.get("LOW", 0)}.'
        )
        story.append(Paragraph(alert_text, styles['DefendXBodyText']))
        
        # ── Footer ──
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width='100%', thickness=1,
                               color=colors.HexColor('#00d4ff')))
        story.append(Spacer(1, 5))
        story.append(Paragraph(
            '<i>Generated by DefendX AI Insider Threat Detection System. '
            'This report is confidential and intended for authorized security personnel only.</i>',
            ParagraphStyle('Footer', parent=styles['Normal'],
                          fontSize=8, textColor=colors.HexColor('#8b949e'),
                          alignment=TA_CENTER)
        ))
        
        # Build PDF
        doc.build(story)
        return output_path
    
    def generate_csv_report(self, output_path: str) -> str:
        """Export threat scores as CSV."""
        scores = self.analyzer.get_all_threat_scores()
        if len(scores) > 0:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            scores.to_csv(output_path, index=False)
            return output_path
        return 'Error: No data to export'
