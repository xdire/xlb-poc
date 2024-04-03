package balancer

import (
	"sync"
	"testing"
)

func TestRoundRobin_Next(t *testing.T) {
	type fields struct {
		order int64
		from  int64
		to    int64
	}
	tests := []struct {
		name   string
		fields fields
		want   int64
	}{
		{
			"Concurrency test for Round Robin",
			fields{
				order: 0,
				from:  0,
				to:    5,
			},
			5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := &RoundRobin{
				order: tt.fields.order,
				from:  tt.fields.from,
				to:    tt.fields.to,
			}
			distribution := make([]int64, 1000)
			wg := sync.WaitGroup{}
			for i := 0; i < 1000; i++ {
				go func(ii int) {
					wg.Add(1)
					if got := rr.Next(); got > tt.want {
						t.Errorf("Next() = %v, for iter=%d want %v", got, ii, tt.want)
					} else {
						distribution[ii] = got
					}
					wg.Done()
				}(i)
			}
			wg.Wait()

			// Calculate frequency of each number to popup
			freq := make(map[int64]int64)
			for _, v := range distribution {
				freq[v] += 1
			}

			// Visually read distribution and frequency tables
			// t.Logf("distribution %v", distribution)
			// t.Logf("frequency %v", freq)

			// Calculate deviation if any of the values went off-range
			maxDeviation := int64(0)
			prev := int64(0)
			for _, f := range freq {
				if prev == 0 {
					prev = f
					continue
				}
				maxDeviation = max(f-prev, maxDeviation)
			}
			if maxDeviation > 1 {
				t.Errorf("maximum deviation is greater than 1 for the full circle of round robin")
			}
		})
	}
}

//func max(v1, v2 int64) int64 {
//	if v1 > v2 {
//		return v1
//	}
//	return v2
//}
