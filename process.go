package godtrace

import (
	"bufio"
	"encoding/xml"
	"fmt"
)

type Process struct {
	XMLName   xml.Name `xml:"Process"`
	PID       string   `xml:"PID"`
	Execname  string   `xml:"Execname"`
	Probefunc string   `xml:"Probefunc"`
}

// Stream takes a Process channel, runs dtrace, "decodes" the piped output and writes it to the channel
func Stream(out chan Process) error {
	handle, err := Open(0)
	if err != nil {
		return err
	}
	defer handle.Close()

	handle.SetBufSize("4m")

	// prog, err := handle.Compile("syscall:::entry { printf(\"PID: %d  Execname: %s  Probefunc: %s\\n\",  pid, execname, probefunc)}", ProbeSpecName, C_PSPEC, nil)

	// dtrace command prints fake xml
	prog, err := handle.Compile("syscall:::entry { printf(\"<Process><PID>%d</PID><Execname>%s</Execname><Probefunc>%s</Probefunc></Process>\\n\",  pid, execname, probefunc)}", ProbeSpecName, C_PSPEC, nil)
	if err != nil {
		return err
	}

	_, err = handle.Exec(prog)
	if err != nil {
		return err
	}

	pr, err := handle.ConsumePipe()
	if err != nil {
		return err
	}
	defer pr.Close()

	var p Process
	errChan := make(chan error)

	go func() {
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			err := xml.Unmarshal([]byte(scanner.Text()), &p)
			if err != nil {
				errChan <- err
			}
			out <- p
		}
	}()

	if err := handle.Go(); err != nil {
		return err
	}

	for {
		status, err := handle.Run()
		if err != nil {
			// return fmt.Errorf("run error: %v", err) // TODO - occassional errors - should we send on errchan?
			fmt.Errorf("run error: %v", err)
			continue
		}
		if !status.IsOK() {
			break
		}

		// Errors from scan/marshalling
		// TODO - Not return on error?
		err = <-errChan
		if err != nil {
			return err
		}
	}
	return nil
}
