package tracer

import (
	"fmt"
	"github.com/iovisor/gobpf/pkg/tracepipe"
	"os"
)

// RunTracepipe reads data produced by bpf_trace_printk() in eBPF program
// and prints this data to stdout
func RunTracepipe() {}

	go func() {
		tp, err := tracepipe.New()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		defer tp.Close()

		channel, errorChannel := tp.Channel()

		for {
			select {
			case event := <-channel:
				fmt.Printf("%+v\n", event)
			case err := <-errorChannel:
				fmt.Printf("%+v\n", err)
			}
		}
	}()

}