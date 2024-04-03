package balancer

import "sync/atomic"

type RoundRobin struct {
	order int64
	from  int64
	to    int64
}

func (rr *RoundRobin) Start() int64 {
	return rr.from
}

func (rr *RoundRobin) End() int64 {
	return rr.to
}

func NewRoundRobin(from, to int64) *RoundRobin {
	if to < from {
		panic("Round robin tool need to work in increasing order, " +
			"please ensure from and to are aligned in an increasing order")
	}
	return &RoundRobin{
		from: from, to: to, order: to,
	}
}

func (rr *RoundRobin) Next() int64 {
	// Iterate +1
	val := atomic.AddInt64(&rr.order, 1)
	if val > rr.to {
		// Try to reset on overflow
		if atomic.CompareAndSwapInt64(&rr.order, val, rr.from) {
			// If reset happened in this thread return value here
			return rr.from
		}
		// If reset failed and should happen in other thread — then load
		// and safeguard to be within the limits of the range
		return atomic.LoadInt64(&rr.order)%(rr.to-rr.from) + 1
	}
	// Return value if not overflown
	return val
}
