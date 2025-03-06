package component

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

var TemplateDir = "component/"

func TransferredMeaning(data any, fileDetailPath string) error {
	if fileDetailPath == "" {
		return fmt.Errorf("fileDetailPath cannot be empty")
	}
	// get dir by filepath
	dir := filepath.Dir(fileDetailPath)
	// check dir exist if not exist, create it
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}
	// getfileName
	fileName := filepath.Base(fileDetailPath)
	templatePath := filepath.Join(TemplateDir, fileName)
	templateByte, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to read template file: %w", err)
	}
	tmpl, err := template.New(fileName).Parse(string(templateByte))
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	// create file
	file, err := os.Create(fileDetailPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	if _, err = file.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}
