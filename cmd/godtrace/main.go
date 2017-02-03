package main

import (
	"log"

	"github.com/stinkyfingers/godtrace"
)

func main() {

	// kick off for loop in goroutine to receive Processes on chan
	out := make(chan godtrace.Process)
	go func() {
		for {
			process := <-out

			// NOTE - just ignoring this program's processes - feels yucky
			if process.Execname == "iTerm2" || process.Execname == "godtrace" {
				continue
			}

			// NOTE - in real life, do something besides log
			log.Print("Process: ", process)
		}
	}()

	// call Stream()
	err := godtrace.Stream(out)
	if err != nil {
		log.Fatal(err)
	}
}
