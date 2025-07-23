package bootstrap

import (
	"log"
)

type ConsoleLogger struct {
	LogLevel 	int
}

func InitConsoleLogger(logLevel string) (*ConsoleLogger, error) {
	lvl, err := mapLogLevel(logLevel)
	if err != nil {
		return nil, err
	}
	return &ConsoleLogger{
		LogLevel: lvl,
	}, nil
}

func mapLogLevel(logLevel string) (int, error) {
	switch logLevel {
	case "debug":
		return 0, nil
	case "info":
		return 1, nil
	case "notice":
		return 2, nil
	case "warn":
		return 3, nil
	case "error":
		return 4, nil
	case "critical":
		return 5, nil
	case "alert":
		return 6, nil
	case "emergency":
		return 7, nil
	default:
		return 0, fmt.Errorf("Unknown log level: %v", logLevel)
	}
}

func (l *ConsoleLogger) Debug(msg string, args ...any) {
	if l.LogLevel >= 0 {
		log.Printf("[DEBUG] %s:\n\t%v", msg, args)
	}
}

func (l *ConsoleLogger) Info(msg string, args ...any) {
	if l.LogLevel >= 1 {
		log.Printf("[INFO] %s:\n\t%v", msg, args)
	}
}

func (l *ConsoleLogger) Notice(msg string, args ...any) {
	if l.LogLevel >= 2 {
		log.Printf("[NOTICE] %s:\n\t%v", msg, args)
	}
}

func (l *ConsoleLogger) Warn(msg string, args ...any) {
	if l.LogLevel >= 3 {
		log.Printf("[WARN] %s:\n\t%v", msg, args)
	}
}

func (l *ConsoleLogger) Error(msg string, args ...any) {
	if l.LogLevel >= 4 {
		log.Printf("[ERROR] %s:\n\t%v", msg, args)
	}
}

func (l *ConsoleLogger) Critical(msg string, args ...any) {
	if l.LogLevel >= 5 {
		log.Printf("[CRITICAL] %s:\n\t%v", msg, args)
	}
}

func (l *ConsoleLogger) Alert(msg string, args ...any) {
	if l.LogLevel >= 6 {
		log.Printf("[ALERT] %s:\n\t%v", msg, args)
	}
}

func (l *ConsoleLogger) Emergency(msg string, args ...any) {
	if l.LogLevel >= 7 {
		log.Fatalf("[EMERGENCY] %s:\n\t%v", msg, args)
	}
}
