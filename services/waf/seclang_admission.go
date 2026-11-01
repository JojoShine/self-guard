package main

import "sync/atomic"

const secInspectionBodyBudget = 64 << 20

type secInspectionAdmission struct {
	slots chan struct{}
	bytes atomic.Int64
}

func newSecInspectionAdmission() *secInspectionAdmission {
	return &secInspectionAdmission{slots: make(chan struct{}, secInspectionAdmissionLimit)}
}
func (a *secInspectionAdmission) acquire(maxBody int64) bool {
	if a == nil || maxBody < 1 || maxBody > secInspectionBodyBudget {
		return false
	}
	select {
	case a.slots <- struct{}{}:
	default:
		return false
	}
	for {
		used := a.bytes.Load()
		if used > secInspectionBodyBudget-maxBody {
			<-a.slots
			return false
		}
		if a.bytes.CompareAndSwap(used, used+maxBody) {
			return true
		}
	}
}
func (a *secInspectionAdmission) release(maxBody int64) {
	a.bytes.Add(-maxBody)
	<-a.slots
}
