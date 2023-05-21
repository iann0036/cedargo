package cedargo

/*
#cgo LDFLAGS: -L./lib -lcedar_go_bindings
#include <stdlib.h>
#include "./lib/cedar_go_bindings.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func Evaluate(principalID, principalType, actionID, actionType, resourceID, resourceType, policies, ctx, entities string) (bool, error) {
	cPolicies := C.CString(policies)
	defer C.free(unsafe.Pointer(cPolicies))
	cPrincipalID := C.CString(principalID)
	defer C.free(unsafe.Pointer(cPrincipalID))
	cPrincipalType := C.CString(principalType)
	defer C.free(unsafe.Pointer(cPrincipalType))
	cActionID := C.CString(actionID)
	defer C.free(unsafe.Pointer(cActionID))
	cActionType := C.CString(actionType)
	defer C.free(unsafe.Pointer(cActionType))
	cResourceID := C.CString(resourceID)
	defer C.free(unsafe.Pointer(cResourceID))
	cResourceType := C.CString(resourceType)
	defer C.free(unsafe.Pointer(cResourceType))
	cCtx := C.CString(ctx)
	defer C.free(unsafe.Pointer(cCtx))
	cEntities := C.CString(entities)
	defer C.free(unsafe.Pointer(cEntities))

	o := C.CedarEvaluate(cPrincipalID, cPrincipalType, cActionID, cActionType, cResourceID, cResourceType, cPolicies, cCtx, cEntities)
	output := C.GoString(o)

	if output == "ALLOW" {
		return true, nil
	} else if output == "DENY" {
		return false, nil
	}

	return false, fmt.Errorf("unknown evaluation response")
}

func Validate(src, sc string) error {
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))
	cSc := C.CString(sc)
	defer C.free(unsafe.Pointer(cSc))

	o := C.CedarValidate(cSrc, cSc)
	output := C.GoString(o)

	if output == "PASS" {
		return nil
	}

	return fmt.Errorf("failed to validate")
}
