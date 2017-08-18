package tls

// #include "shim.h"
import "C"

import (
	"errors"
	"fmt"
	"strings"
)

func init() {
	if rc := C.X_shim_init(); rc != 0 {
		panic(fmt.Errorf("X_shim_init failed with %d", rc))
	}
}

// errorFromErrorQueue needs to run in the same OS thread as the operation
// that caused the possible error
func errorFromErrorQueue() error {
	var errs []string
	for {
		err := C.ERR_get_error()
		if err == 0 {
			break
		}
		errs = append(errs, fmt.Sprintf("%s:%s:%s",
			C.GoString(C.ERR_lib_error_string(err)),
			C.GoString(C.ERR_func_error_string(err)),
			C.GoString(C.ERR_reason_error_string(err))))
	}
	return errors.New(fmt.Sprintf("SSL errors: %s", strings.Join(errs, "\n")))
}
