package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/maxmart/hoststray/internal/hosts"
)

const (
	hostsPath = "/etc/hosts"
	maxConns  = 4 // at once; more wait
	maxReq    = 64 << 10
	anchor    = "com.apple/hoststray"
)

// tokenFile keeps the daemon's pf reference across a crash; /var/run is
// emptied at boot, when pf's references are too.
var tokenFile = "/var/run/" + Label + ".pf"

type server struct {
	uid    uint32
	hosts  string
	mu     sync.Mutex // one hosts change at a time
	conns  chan struct{}
	block  func([]netip.Addr)                      // resets stale connections; pf.add unless testing
	lookup func(old, next *hosts.Doc) []netip.Addr // hosts.MovedAway unless testing
}

// Run is the daemon: it serves uid until the app at appExe is gone.
func Run(uid uint32, appExe string) error {
	if os.Geteuid() != 0 {
		return errors.New("the helper must run as root")
	}
	log.SetFlags(log.LstdFlags)
	p := &pf{}
	p.recover()
	l, err := listen(Socket, int(uid))
	if err != nil {
		return err
	}
	go watchApp(appExe, uid)
	s := &server{uid: uid, hosts: hostsPath, conns: make(chan struct{}, maxConns), block: p.add, lookup: hosts.MovedAway}
	log.Printf("helper (proto %d) serving uid %d for %s", Proto, uid, appExe)
	return s.serve(l)
}

// listen creates the socket so that only uid (and root) may connect.
func listen(path string, uid int) (*net.UnixListener, error) {
	os.Remove(path)
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, uid, -1); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (s *server) serve(l *net.UnixListener) error {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.conns <- struct{}{}
		go func() {
			defer func() { <-s.conns }()
			s.handle(c)
		}()
	}
}

func (s *server) handle(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var req Request
	var resp Response
	if uid, err := peerUID(c); err != nil || (uid != s.uid && uid != 0) {
		log.Printf("refused a connection from uid %d (%v)", uid, err)
		resp.Error = "not allowed"
	} else if err := json.NewDecoder(io.LimitReader(c, maxReq)).Decode(&req); err != nil {
		resp.Error = "bad request: " + err.Error()
	} else {
		resp = s.do(req)
	}
	json.NewEncoder(c).Encode(resp)
}

func (s *server) do(req Request) Response {
	switch req.Op {
	case "version":
		return Response{Proto: Proto}
	case "group":
		s.mu.Lock()
		defer s.mu.Unlock()
		changed, err := s.setGroup(req.Group, req.Enable)
		if errors.Is(err, ErrNoGroup) {
			return Response{Proto: Proto, NoGroup: true}
		}
		if err != nil {
			log.Printf("group %q on=%v: %v", req.Group, req.Enable, err)
			return Response{Proto: Proto, Error: err.Error()}
		}
		log.Printf("group %q on=%v; dropping connections to %v", req.Group, req.Enable, changed)
		return Response{Proto: Proto}
	}
	return Response{Error: "unknown request " + req.Op}
}

// setGroup flips a group in the hosts file and returns the addresses whose
// connections it resets.
func (s *server) setGroup(name string, enable bool) ([]netip.Addr, error) {
	b, err := os.ReadFile(s.hosts)
	if err != nil {
		return nil, err
	}
	old, next := hosts.Parse(string(b)), hosts.Parse(string(b))
	if !hosts.SetGroup(next, name, enable) {
		return nil, ErrNoGroup
	}
	drop := Droppable(s.lookup(old, next)) // before the write: where names point now
	if err := writeAtomic(s.hosts, []byte(hosts.Serialize(next))); err != nil {
		return nil, err
	}
	flushDNS()
	if len(drop) > 0 {
		s.block(drop)
	}
	return drop, nil
}

// writeAtomic replaces path through a temp file in the same folder, so the
// hosts file is never seen half written.
func writeAtomic(path string, content []byte) error {
	real, err := filepath.EvalSymlinks(path) // /etc is a link to /private/etc
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(real), ".hosts-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), real)
}

func flushDNS() {
	exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

// watchApp uninstalls the daemon once the app is gone (moved to the Trash).
// An update swaps the app bundle with two renames, so only a miss that lasts
// a minute counts.
func watchApp(appExe string, uid uint32) {
	missing := false
	for {
		_, err := os.Stat(appExe)
		gone := errors.Is(err, os.ErrNotExist)
		if gone && missing {
			log.Printf("%s is gone; uninstalling", appExe)
			if err := Uninstall(uid); err != nil {
				log.Printf("uninstall: %v", err)
			}
			return
		}
		missing = gone
		if gone {
			time.Sleep(time.Minute)
		} else {
			time.Sleep(10 * time.Minute)
		}
	}
}

// --- pf ---------------------------------------------------------------------------

// pf keeps one anchor whose rules cover every address blocked in the last
// BlockFor, and one reference on pf being enabled while there are any.
type pf struct {
	mu    sync.Mutex
	until map[netip.Addr]time.Time
	token string
	timer *time.Timer
}

var pfTokenRE = regexp.MustCompile(`Token : (\d+)`)

func pfctl(args ...string) error {
	out, err := exec.Command(Pfctl, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// recover undoes what a previous run left behind.
func (p *pf) recover() {
	pfctl("-a", anchor, "-F", "rules")
	if b, err := os.ReadFile(tokenFile); err == nil {
		pfctl("-X", strings.TrimSpace(string(b)))
		os.Remove(tokenFile)
	}
}

func (p *pf) add(addrs []netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.until == nil {
		p.until = map[netip.Addr]time.Time{}
	}
	end := time.Now().Add(BlockFor)
	for _, a := range addrs {
		p.until[a] = end
	}
	if err := p.load(); err != nil {
		log.Print(err)
		return
	}
	// Connections pf already tracks would skip the rules; forget them.
	for _, a := range addrs {
		pfctl("-k", anyFor(a), "-k", a.String())
	}
	if p.timer == nil {
		p.timer = time.AfterFunc(BlockFor, p.expire)
	}
}

// load replaces the anchor's rules with ones for the current addresses, and
// enables pf (or lets go of it) to match.
func (p *pf) load() error {
	if len(p.until) == 0 {
		err := pfctl("-a", anchor, "-F", "rules")
		if p.token != "" {
			pfctl("-X", p.token)
			p.token = ""
			os.Remove(tokenFile)
		}
		return err
	}
	var addrs []netip.Addr
	for a := range p.until {
		addrs = append(addrs, a)
	}
	cmd := exec.Command(Pfctl, "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(StaleRules(addrs))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if p.token == "" {
		out, _ := exec.Command(Pfctl, "-E").CombinedOutput()
		m := pfTokenRE.FindSubmatch(out)
		if m == nil {
			return fmt.Errorf("enabling pf: %s", strings.TrimSpace(string(out)))
		}
		p.token = string(m[1])
		os.WriteFile(tokenFile, m[1], 0o600)
	}
	return nil
}

func (p *pf) expire() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	next := time.Time{}
	for a, t := range p.until {
		if !t.After(now) {
			delete(p.until, a)
		} else if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	if err := p.load(); err != nil {
		log.Print(err)
	}
	p.timer = nil
	if !next.IsZero() {
		p.timer = time.AfterFunc(next.Sub(now), p.expire)
	}
}
