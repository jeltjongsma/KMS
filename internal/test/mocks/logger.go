package mocks

type LoggerMock struct {
	DebugFunc     func(string, ...any)
	InfoFunc      func(string, ...any)
	NoticeFunc    func(string, ...any)
	WarnFunc      func(string, ...any)
	ErrorFunc     func(string, ...any)
	CriticalFunc  func(string, ...any)
	AlertFunc     func(string, ...any)
	EmergencyFunc func(string, ...any)
}

func NewLoggerMock() *LoggerMock {
	return &LoggerMock{}
}

func (m *LoggerMock) Debug(msg string, args ...any) {
	if m.DebugFunc != nil {
		m.DebugFunc(msg, args...)
	}
}

func (m *LoggerMock) Info(msg string, args ...any) {
	if m.InfoFunc != nil {
		m.InfoFunc(msg, args...)
	}
}

func (m *LoggerMock) Notice(msg string, args ...any) {
	if m.NoticeFunc != nil {
		m.NoticeFunc(msg, args...)
	}
}

func (m *LoggerMock) Warn(msg string, args ...any) {
	if m.WarnFunc != nil {
		m.WarnFunc(msg, args...)
	}
}

func (m *LoggerMock) Error(msg string, args ...any) {
	if m.ErrorFunc != nil {
		m.ErrorFunc(msg, args...)
	}
}

func (m *LoggerMock) Critical(msg string, args ...any) {
	if m.CriticalFunc != nil {
		m.CriticalFunc(msg, args...)
	}
}

func (m *LoggerMock) Alert(msg string, args ...any) {
	if m.AlertFunc != nil {
		m.AlertFunc(msg, args...)
	}
}

func (m *LoggerMock) Emergency(msg string, args ...any) {
	if m.EmergencyFunc != nil {
		m.EmergencyFunc(msg, args...)
	}
}
