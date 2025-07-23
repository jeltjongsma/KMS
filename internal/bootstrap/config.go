package bootstrap

import (
	"os"
	"bufio"
	"strings"
	"fmt"
	c "kms/internal/bootstrap/context"
)


func LoadConfig(path string) (c.KmsConfig, error) {
	cfg := make(map[string]string)
	file, err := os.Open(path)
	if err != nil {return cfg, err}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {continue}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return cfg, fmt.Errorf("Invalid format: %v", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if key == "" || value == "" {
			return cfg, fmt.Errorf("Invalid key or value: %v", line)
		}

		if err := scanner.Err(); err != nil {
			return cfg, err
		}

		cfg[key] = value
	}
	return c.KmsConfig(cfg), nil
}