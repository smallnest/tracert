package tracert

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type TraceRouteResult struct {
	LastSuccessRouters map[string]int      `json:"last_success_routers,omitempty"` // last success router ip => count of failed ip pairs
	FailedPair         map[string][]string `json:"failed_pair,omitempty"`          // last success router ip => failed ip pairs
	Failed             int                 `json:"failed,omitempty"`
	Success            int                 `json:"success,omitempty"`
}

func MTrace(localIP, remoteIP string, localPorts, remotePorts []int) *TraceRouteResult {
	var wg sync.WaitGroup
	wg.Add(len(localPorts))

	var resultsLock sync.Mutex
	results := make(map[string][]*TracertHop)
	for i, localPort := range localPorts {
		i := i
		localPort := localPort

		go func() {
			defer wg.Done()

			remotePort := remotePorts[i]
			key := fmt.Sprintf("%s:%d->%s:%d", localIP, localPort, remoteIP, remotePort)

			trace := New(localIP, remoteIP, localPort, remotePort, nil, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			hops, err := trace.Trace(ctx)
			if err != nil {
				return
			}

			resultsLock.Lock()
			results[key] = hops
			resultsLock.Unlock()
		}()
	}
	wg.Wait()

	lastSuccess := make(map[string]int)
	failedPair := make(map[string][]string)
	var failed, success int

	for key, hops := range results {
		addr := findLastSuccess(remoteIP, hops)
		if addr != "" {
			if addr != remoteIP {
				lastSuccess[addr]++
				failed++
				failedPair[addr] = append(failedPair[addr], key)
			} else {
				success++
			}
		} else {
			lastSuccess["*"]++
			failed++
			failedPair[addr] = append(failedPair[addr], key)
		}
	}

	return &TraceRouteResult{
		LastSuccessRouters: lastSuccess,
		FailedPair:         failedPair,
		Failed:             failed,
		Success:            success,
	}
}
