package platform

import (
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// The pipe the service serves, without the service around it: what a client
// may open, and a request answered.
func TestHelperPipe(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	h := &helperSvc{sid: sid}
	p, err := h.newPipe(true)
	if err != nil {
		t.Skipf("pipe taken (helper installed?): %v", err)
	}
	go h.serve(p)

	name, _ := windows.UTF16PtrFromString(helperPipe)
	// Asking for GENERIC_WRITE includes the right to serve the pipe, which
	// clients don't get.
	if c, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0); err == nil {
		windows.CloseHandle(c)
		t.Fatal("opened with GENERIC_WRITE")
	}
	c, err := windows.CreateFile(name, pipeAccess, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(c), helperPipe)
	defer f.Close()
	json.NewEncoder(f).Encode(helperRequest{Op: "version"})
	var resp helperResponse
	if err := json.NewDecoder(f).Decode(&resp); err != nil || resp.Proto != helperProto {
		t.Fatalf("version: %+v %v", resp, err)
	}
}
