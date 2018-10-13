package main

import "strings"

type Errors []error

func (errs Errors) Error() string {
	strs := []string{}
	for _, err := range errs {
		strs = append(strs, err.Error())
	}
	return strings.Join(strs, "\n")
}

func CombineErrors(errs ...error) error {
	var combinedError Errors
	for _, err := range errs {
		if err != nil {
			combinedError = append(combinedError, err)
		}
	}
	if len(combinedError) == 0 {
		return nil
	}
	return combinedError
}
