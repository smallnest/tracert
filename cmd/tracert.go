package main

import (
	//"bufio"

	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/smallnest/tracert"
)

var (
	srcPorts = flag.String("sports", "60151,60151,60151,60151,60151", "")
	dstPorts = flag.String("dports", "60581,60582,60583,60584,60585", "")
	dstIP    = flag.String("d", "", "")
)

func main() {
	flag.Parse()

	localIP, err := getLocalIPByHostname()
	if err != nil {
		panic(err)
	}

	var srcports []int
	for _, p := range strings.Split(*srcPorts, ",") {
		port, _ := strconv.Atoi(p)
		srcports = append(srcports, port)
	}
	var dstports []int
	for _, p := range strings.Split(*dstPorts, ",") {
		port, _ := strconv.Atoi(p)
		dstports = append(dstports, port)
	}

	var wg sync.WaitGroup
	wg.Add(len(srcports))

	var resultsLock sync.Mutex
	results := make(map[string][]*tracert.TracertHop)
	for i, srcPort := range srcports {
		i := i
		srcPort := srcPort

		go func() {
			defer wg.Done()

			dstPort := dstports[i]
			key := fmt.Sprintf("%s:%d->%s:%d", localIP, srcPort, *dstIP, dstPort)

			trace := tracert.New(localIP, *dstIP, srcPort, dstPort, nil, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			hops, err := trace.Trace(ctx)
			if err != nil {
				fmt.Println(err)
				return
			}

			resultsLock.Lock()
			results[key] = hops
			resultsLock.Unlock()
		}()
	}

	wg.Wait()

	for key, result := range results {
		fmt.Println(key)
		for _, hop := range result {
			fmt.Printf("\t%d %s %v\n", hop.TTL, hop.Address, hop.RTT)
		}

	}
}

func getLocalIPByHostname() (string, error) {
	name, err := os.Hostname()
	if err != nil {
		return "", err
	}

	addrs, err := net.LookupHost(name)
	if err != nil {
		return "", err
	}

	if len(addrs) == 0 {
		return "", errors.New("local address is not configured")
	}

	return addrs[0], nil
}
