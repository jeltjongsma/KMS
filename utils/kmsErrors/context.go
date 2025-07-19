package kmsErrors

type AppError struct {
	Err 		error
	Message 	string
	Code 		int
}

func NewAppError(err error, msg string, code int) *AppError {
	return &AppError{
		Err: err,
		Message: msg,
		Code: code,
	}
}
