package reporter

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"
	"go-ad-audit/internal/audit"
)

type ReportData struct {
	GeneratedAt string
	HighCount   int
	MediumCount int
	LowCount    int
	Issues      []audit.AuditFinding
}

func GenerateHTMLReport(findings []audit.AuditFinding, outputPath string) error {

	reportData := buildReportData(findings)

	templatePath := "../internal/reporter/template.html"
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(outputPath), 0755)
	if err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, reportData)
	if err != nil {
		return fmt.Errorf("failed to render HTML report: %w", err)
	}

	return nil
}

func buildReportData(findings []audit.AuditFinding) ReportData {

	report := ReportData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Issues:      findings,
	}

	for _, f := range findings {
		switch f.Severity {
		case "High":
			report.HighCount++
		case "Medium":
			report.MediumCount++
		default:
			report.LowCount++
		}
	}

	return report
}
