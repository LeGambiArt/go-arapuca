package arapuca

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()
}

func TestCloseIdempotent(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sb.Close()
	sb.Close() // second close is safe
}

func TestCgroupsAvailable(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()
	available := sb.CgroupsAvailable()
	t.Logf("cgroups available: %v", available)
}

func TestLandlockABIVersion(t *testing.T) {
	v := LandlockABIVersion()
	t.Logf("landlock ABI version: %d", v)
}

func TestNetNSAvailable(t *testing.T) {
	available := NetNSAvailable()
	t.Logf("netns available: %v", available)
}

func TestWrapperPath(t *testing.T) {
	path := WrapperPath()
	t.Logf("wrapper path: %q", path)
}

func TestMakeSocketDir(t *testing.T) {
	dir, err := MakeSocketDir()
	if err != nil {
		t.Fatalf("MakeSocketDir: %v", err)
	}
	t.Logf("socket dir: %s", dir)
	_ = os.RemoveAll(dir)
}

func TestMakeTmpDir(t *testing.T) {
	dir, err := MakeTmpDir("test-task")
	if err != nil {
		t.Fatalf("MakeTmpDir: %v", err)
	}
	t.Logf("tmp dir: %s", dir)
	_ = os.RemoveAll(dir)
}

func TestDiskUsageMB(t *testing.T) {
	mb := DiskUsageMB("/tmp")
	t.Logf("disk usage /tmp: %d MB", mb)
}

func TestDiskUsageMBNonexistent(t *testing.T) {
	mb := DiskUsageMB("/nonexistent-xyz-123")
	if mb != 0 {
		t.Errorf("expected 0 for nonexistent path, got %d", mb)
	}
}

func TestProfileValidation_DnsCaptureRequiresNetNS(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx := context.Background()
	_, err = sb.Launch(ctx, Config{
		Profile: Profile{DnsCapture: true, UseNetNS: false},
	}, "/bin/true", nil, nil)
	if err == nil {
		t.Fatal("expected error for DnsCapture without UseNetNS, got nil")
	}
}

// TestAllowedHosts_InvalidPort verifies that port 0 is rejected by
// the FFI layer.
func TestAllowedHosts_InvalidPort(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("AllowedHosts FFI is Linux-only")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	_, err = sb.Launch(context.Background(), Config{
		AllowedHosts: []AllowedHost{{Host: "127.0.0.1", Port: 0}},
	}, "/bin/true", nil, nil)
	if err == nil {
		t.Fatal("expected error for AllowedHost with port 0")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "allowed host") {
		t.Errorf("expected error to mention allowed host, got: %v", err)
	}
}

func TestProfileValidation_InvalidSeccompProfile(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx := context.Background()
	_, err = sb.Launch(ctx, Config{
		Profile: Profile{SeccompProfile: "invalid-profile-xyz"},
	}, "/bin/true", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid seccomp profile, got nil")
	}
}

func TestSeccompProfileConstants(t *testing.T) {
	if SeccompProfileDefault != "" {
		t.Errorf("SeccompProfileDefault = %q, want %q", SeccompProfileDefault, "")
	}
	if SeccompProfileStrict != "strict" {
		t.Errorf("SeccompProfileStrict = %q, want %q", SeccompProfileStrict, "strict")
	}
	if SeccompProfileBaseline != "baseline" {
		t.Errorf("SeccompProfileBaseline = %q, want %q", SeccompProfileBaseline, "baseline")
	}
}

// TestProfileValidation_SeccompProfileStrict verifies the C library accepts "strict".
func TestProfileValidation_SeccompProfileStrict(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx := context.Background()
	_, err = sb.Launch(ctx, Config{
		Profile: Profile{
			SeccompProfile: SeccompProfileStrict,
			ReadPaths:      []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, "/bin/true", nil, nil)
	// err may be non-nil for other reasons (binary not found, no wrapper, etc.)
	// but must NOT be a seccomp profile error.
	if err != nil && containsSeccompError(err) {
		t.Errorf("SeccompProfileStrict rejected by C library: %v", err)
	}
}

// TestProfileValidation_SeccompProfileBaseline verifies the C library accepts "baseline".
func TestProfileValidation_SeccompProfileBaseline(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx := context.Background()
	_, err = sb.Launch(ctx, Config{
		Profile: Profile{
			SeccompProfile: SeccompProfileBaseline,
			ReadPaths:      []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, "/bin/true", nil, nil)
	if err != nil && containsSeccompError(err) {
		t.Errorf("SeccompProfileBaseline rejected by C library: %v", err)
	}
}

// TestProfileValidation_UsePidNS_Happy verifies UsePidNS is accepted when the
// kernel supports PID namespaces.
func TestProfileValidation_UsePidNS_Happy(t *testing.T) {
	if !NetNSAvailable() {
		t.Skip("namespace isolation not available on this system")
	}
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx := context.Background()
	_, err = sb.Launch(ctx, Config{
		Profile: Profile{
			UsePidNS:  true,
			ReadPaths: []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, "/bin/true", nil, nil)
	if err != nil {
		t.Logf("UsePidNS launch result (may fail for non-sandbox reasons): %v", err)
	}
}

// TestProfileValidation_DnsCapture_Happy verifies DnsCapture+UseNetNS is accepted.
func TestProfileValidation_DnsCapture_Happy(t *testing.T) {
	if !NetNSAvailable() {
		t.Skip("network namespace isolation not available on this system")
	}
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx := context.Background()
	_, err = sb.Launch(ctx, Config{
		Profile: Profile{
			UseNetNS:   true,
			DnsCapture: true,
			ReadPaths:  []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, "/bin/true", nil, nil)
	// Should not error with "DnsCapture requires UseNetNS" since UseNetNS is set.
	if err != nil && err.Error() == "arapuca: DnsCapture requires UseNetNS" {
		t.Errorf("DnsCapture with UseNetNS should not error: %v", err)
	}
}

// TestAllowExec_ShebangScript verifies that a shebang script runs
// successfully when AllowExec is true and the interpreter is in a
// read path.
func TestAllowExec_ShebangScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("AllowExec/Landlock is Linux-only")
	}
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}
	if LandlockABIVersion() == 0 {
		t.Skip("Landlock not available")
	}

	// Create a shebang script in a temp dir that will be a write path.
	dir := t.TempDir()
	script := dir + "/hello.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hello-from-shebang\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID: "shebang-allow-exec",
		Stdout: stdoutW,
		Stderr: stderrW,
		Profile: Profile{
			AllowExec:  true,
			ReadPaths:  []string{"/usr", "/lib", "/lib64", "/bin"},
			WritePaths: []string{dir},
		},
	}, script, nil, nil)
	if err != nil {
		stdoutW.Close()
		stderrW.Close()
		t.Fatalf("Launch: %v", err)
	}

	stdoutW.Close()
	stderrW.Close()

	stdout, _ := io.ReadAll(stdoutR)
	stderr, _ := io.ReadAll(stderrR)

	exitCode, err := proc.Wait()
	proc.Cleanup()

	t.Logf("exit=%d err=%v stdout=%q stderr=%q", exitCode, err, stdout, stderr)

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d (err: %v, stderr: %q)", exitCode, err, stderr)
	}
	if got := strings.TrimSpace(string(stdout)); got != "hello-from-shebang" {
		t.Errorf("expected stdout 'hello-from-shebang', got %q", got)
	}
}

// TestAllowExec_DefaultBlocksShebang verifies that a shebang script
// is blocked when AllowExec is false (the default), because Landlock
// denies Execute on the interpreter.
func TestAllowExec_DefaultBlocksShebang(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("AllowExec/Landlock is Linux-only")
	}
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}
	if LandlockABIVersion() == 0 {
		t.Skip("Landlock not available")
	}

	dir := t.TempDir()
	script := dir + "/hello.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hello-from-shebang\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID: "shebang-deny-exec",
		Stdout: stdoutW,
		Stderr: stderrW,
		Profile: Profile{
			AllowExec:  false,
			ReadPaths:  []string{"/usr", "/lib", "/lib64", "/bin"},
			WritePaths: []string{dir},
		},
	}, script, nil, nil)
	if err != nil {
		stdoutW.Close()
		stderrW.Close()
		// Launch itself failing is acceptable -- Landlock may block
		// even the initial exec of the script.
		t.Logf("Launch blocked (expected): %v", err)
		return
	}

	stdoutW.Close()
	stderrW.Close()

	_, _ = io.ReadAll(stdoutR)
	_, _ = io.ReadAll(stderrR)

	exitCode, err := proc.Wait()
	proc.Cleanup()

	t.Logf("exit=%d err=%v", exitCode, err)

	if exitCode == 0 && err == nil {
		t.Error("expected shebang script to fail with AllowExec=false, but it succeeded")
	}
}

// TestDenyUnixSockets_UnsupportedPlatform verifies that DenyUnixSockets
// fails on platforms without seccomp (macOS, non-x86_64/aarch64 Linux).
func TestDenyUnixSockets_UnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		t.Skip("DenyUnixSockets is supported on this platform")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	_, err = sb.Launch(context.Background(), Config{
		Profile: Profile{
			DenyUnixSockets: true,
			ReadPaths:       []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, trueBin(), nil, nil)
	if err == nil {
		t.Fatal("expected error for DenyUnixSockets on unsupported platform")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unix socket") {
		t.Errorf("expected error to mention unix socket, got: %v", err)
	}
}

// TestDenyUnixSockets_Happy verifies that DenyUnixSockets is accepted
// on supported Linux platforms with the wrapper binary available.
func TestDenyUnixSockets_Happy(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("DenyUnixSockets requires Linux x86_64/aarch64")
	}
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID: "deny-unix-sockets",
		Profile: Profile{
			DenyUnixSockets: true,
			ReadPaths:       []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, trueBin(), nil, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	exitCode, err := proc.Wait()
	proc.Cleanup()
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d (err: %v)", exitCode, err)
	}
}

// TestAllowNetworkListeners_Happy verifies that AllowNetworkListeners
// is accepted on supported platforms.
func TestAllowNetworkListeners_Happy(t *testing.T) {
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID: "allow-listeners",
		Profile: Profile{
			AllowNetworkListeners: true,
			ReadPaths:             []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, trueBin(), nil, nil)
	if err != nil {
		t.Logf("Launch result (may fail for non-listener reasons): %v", err)
		return
	}
	exitCode, err := proc.Wait()
	proc.Cleanup()
	if exitCode != 0 {
		t.Logf("exit %d (may fail for non-listener reasons): %v", exitCode, err)
	}
}

func trueBin() string {
	if _, err := os.Stat("/usr/bin/true"); err == nil {
		return "/usr/bin/true"
	}
	return "/bin/true"
}

// containsSeccompError checks whether err is a seccomp profile rejection.
func containsSeccompError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return len(s) > 0 && (contains(s, "seccomp profile") || contains(s, "unknown seccomp"))
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// udsPolicyEnvSupported reports whether the connect-policy tests can
// run here: they need the wrapper binary, python3 as an in-sandbox
// client, an unprivileged user+network namespace (the supervisor
// inspects the target, which on Yama ptrace_scope=1 hosts requires
// the capabilities a user namespace provides), and a Yama scope
// below 3 (which denies all ptrace outright).
func udsPolicyEnvSupported() bool {
	if WrapperPath() == "" {
		return false
	}
	for _, probe := range []struct {
		cmd  string
		args []string
	}{
		{"python3", []string{"-c", "pass"}},
		{"unshare", []string{"--user", "--net", "--map-root-user", "--", "/bin/true"}},
	} {
		if err := exec.Command(probe.cmd, probe.args...).Run(); err != nil {
			return false
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		if scope, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && scope >= 3 {
			return false
		}
	}
	return true
}

// udsEchoListener is a Unix socket listener in the test process that
// accepts a single connection, echoes an ack, and reports what it
// received. Denied-connect tests must not hang on Accept, so the
// listener is closed by Cleanup.
type udsEchoListener struct {
	path     string
	received chan []byte
}

func startUDSEchoListener(t *testing.T, dir, name string) *udsEchoListener {
	t.Helper()
	path := filepath.Join(dir, name)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	l := &udsEchoListener{path: path, received: make(chan []byte, 1)}
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		_, _ = conn.Write([]byte("ack"))
		l.received <- buf[:n]
	}()
	t.Cleanup(func() { ln.Close() })
	return l
}

// launchUDSClient runs a python3 snippet in the sandbox with the
// connect policy active and returns its combined stdout.
func launchUDSClient(t *testing.T, cfg Config, script string) (string, string, int) {
	t.Helper()
	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg.Stdout = stdoutW
	cfg.Stderr = stderrW
	cfg.Profile.UseNetNS = true
	cfg.Profile.SeccompProfile = SeccompProfileBaseline
	cfg.Profile.DenyPrivilegedUnixSockets = true
	cfg.Profile.ReadPaths = []string{"/usr", "/lib", "/lib64", "/bin"}

	proc, err := sb.Launch(ctx, cfg, "/usr/bin/python3", []string{"-c", script}, nil)
	stdoutW.Close()
	stderrW.Close()
	if err != nil {
		stdoutR.Close()
		stderrR.Close()
		t.Fatalf("Launch: %v", err)
	}
	exitCode, err := proc.Wait()
	proc.Cleanup()
	stdout, _ := io.ReadAll(stdoutR)
	stderr, _ := io.ReadAll(stderrR)
	stdoutR.Close()
	stderrR.Close()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	return string(stdout), string(stderr), exitCode
}

// TestDenyPrivilegedUnixSockets_AllowsOrdinarySocket verifies that
// with the connect policy active, connect() to a socket outside any
// deny root is brokered through and data flows end to end.
func TestDenyPrivilegedUnixSockets_AllowsOrdinarySocket(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("connect policy requires Linux x86_64/aarch64")
	}
	if !udsPolicyEnvSupported() {
		t.Skip("requires wrapper, python3, and an unprivileged user namespace")
	}

	dir := t.TempDir()
	listener := startUDSEchoListener(t, dir, "allowed.sock")
	script := fmt.Sprintf(`
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(%q)
s.sendall(b"hello-broker")
assert s.recv(64) == b"ack"
print("ALLOW_OK")
`, listener.path)

	stdout, stderr, exitCode := launchUDSClient(t, Config{TaskID: "uds-policy-allow"}, script)
	if exitCode != 0 || !strings.Contains(stdout, "ALLOW_OK") {
		t.Errorf("allowed connect should work end to end: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	select {
	case data := <-listener.received:
		if string(data) != "hello-broker" {
			t.Errorf("listener received %q, want %q", data, "hello-broker")
		}
	case <-time.After(5 * time.Second):
		t.Error("listener never received the payload")
	}
}

// TestDenyPrivilegedUnixSockets_DeniesDenyRoot verifies that connect()
// to a socket under a configured deny root fails with EACCES and the
// listener never sees a connection.
func TestDenyPrivilegedUnixSockets_DeniesDenyRoot(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("connect policy requires Linux x86_64/aarch64")
	}
	if !udsPolicyEnvSupported() {
		t.Skip("requires wrapper, python3, and an unprivileged user namespace")
	}

	dir := t.TempDir()
	listener := startUDSEchoListener(t, dir, "privileged.sock")
	script := fmt.Sprintf(`
import socket, errno
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
rc = s.connect_ex(%q)
print("RC", rc)
assert rc == errno.EACCES, rc
print("DENY_OK")
`, listener.path)

	stdout, stderr, exitCode := launchUDSClient(t, Config{
		TaskID: "uds-policy-deny",
		Profile: Profile{
			UnixSocketDenyRoots: []string{dir},
		},
	}, script)
	if exitCode != 0 || !strings.Contains(stdout, "DENY_OK") {
		t.Errorf("denied connect should report EACCES: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	// The broker dials the peer with its own private socket to check
	// it, so the listener may accept a connection that sends no data;
	// the oracle is that no payload ever flows (the target's socket is
	// never connected on the deny path).
	select {
	case data := <-listener.received:
		if len(data) != 0 {
			t.Errorf("listener must not receive data on a denied connect, got %q", data)
		}
	case <-time.After(500 * time.Millisecond):
	}
}

// TestDenyPrivilegedUnixSockets_CombinedWithDenyUnixSockets verifies
// that both Unix socket policies can be active at once. The
// combination used to fail every launch before arapuca's supervisor
// branch fixed it.
func TestDenyPrivilegedUnixSockets_CombinedWithDenyUnixSockets(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Unix socket policies require Linux x86_64/aarch64")
	}
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID: "uds-policies-combined",
		Profile: Profile{
			DenyUnixSockets:           true,
			DenyPrivilegedUnixSockets: true,
			ReadPaths:                 []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, trueBin(), nil, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	exitCode, err := proc.Wait()
	proc.Cleanup()
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d (err: %v)", exitCode, err)
	}
}

// TestUnixSocketDenyRoots_Validation verifies that invalid deny-root
// configurations fail fast at Launch with a Go error instead of
// being recorded and failing later inside the C library.
func TestUnixSocketDenyRoots_Validation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("connect policy is Linux-only")
	}

	cases := []struct {
		name      string
		policy    bool
		roots     []string
		wantError string
	}{
		{"relative path", true, []string{"relative/sock"}, "absolute"},
		{"colon separator", true, []string{"/tmp/a:b"}, "must not contain"},
		{"comma separator", true, []string{"/tmp/a,b"}, "must not contain"},
		{"roots without policy", false, []string{"/tmp/sock"}, "requires DenyPrivilegedUnixSockets"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb, err := New()
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer sb.Close()

			_, err = sb.Launch(context.Background(), Config{
				Profile: Profile{
					DenyPrivilegedUnixSockets: tc.policy,
					UnixSocketDenyRoots:       tc.roots,
					ReadPaths:                 []string{"/usr", "/lib", "/lib64", "/bin"},
				},
			}, trueBin(), nil, nil)
			if err == nil {
				t.Fatal("expected Launch to reject the deny roots")
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Errorf("error %q does not mention %q", err, tc.wantError)
			}
		})
	}
}

func sleepBin() string {
	if _, err := os.Stat("/usr/bin/sleep"); err == nil {
		return "/usr/bin/sleep"
	}
	return "/bin/sleep"
}

// TestProcessSignal verifies that a sandboxed process can be signaled
// before Wait, and that the signal — not the context's SIGKILL — is
// what killed it.
func TestProcessSignal(t *testing.T) {
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	// The context timeout is the backstop: if the signal is lost, the
	// cancellation goroutine kills the process group with SIGKILL (9)
	// after 30s and the signal-number assertion below fails.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID:  "signal-term",
		Profile: Profile{ReadPaths: []string{"/usr", "/lib", "/lib64", "/bin"}},
	}, sleepBin(), []string{"30"}, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	exitCode, waitErr := proc.Wait()
	proc.Cleanup()
	if exitCode != 0 || waitErr == nil {
		t.Errorf("expected death by signal, got exit=%d err=%v", exitCode, waitErr)
	}
	if !strings.Contains(waitErr.Error(), strconv.Itoa(int(syscall.SIGTERM))) {
		t.Errorf("expected death by SIGTERM (%d), got: %v", syscall.SIGTERM, waitErr)
	}
}

// TestProcessSignal_AfterWait verifies signaling a reaped process
// fails instead of silently doing nothing.
func TestProcessSignal_AfterWait(t *testing.T) {
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID:  "signal-after-wait",
		Profile: Profile{ReadPaths: []string{"/usr", "/lib", "/lib64", "/bin"}},
	}, trueBin(), nil, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if _, err := proc.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	defer proc.Cleanup()

	if err := proc.Signal(syscall.SIGTERM); err == nil {
		t.Error("expected an error signaling a reaped process")
	}
}

// TestProcessSignal_AfterCleanup verifies signaling a cleaned-up
// process fails.
func TestProcessSignal_AfterCleanup(t *testing.T) {
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID:  "signal-after-cleanup",
		Profile: Profile{ReadPaths: []string{"/usr", "/lib", "/lib64", "/bin"}},
	}, trueBin(), nil, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if _, err := proc.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	proc.Cleanup()

	if err := proc.Signal(syscall.SIGTERM); err == nil {
		t.Error("expected an error signaling a cleaned-up process")
	}
}

// TestCpuTimeout verifies that CpuTimeoutSecs kills a CPU-spinning
// process with SIGXCPU at the limit. The rlimit is applied by the
// wrapper, so the test needs the arapuca binary and read paths that
// force the wrapper launch.
func TestCpuTimeout(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("CpuTimeoutSecs rlimit enforcement is exercised on Linux")
	}
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	// One second of CPU time; the backstop is generous so a healthy
	// run never depends on machine speed.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	start := time.Now()
	proc, err := sb.Launch(ctx, Config{
		TaskID: "cpu-timeout",
		Profile: Profile{
			CpuTimeoutSecs: 1,
			ReadPaths:      []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, "/bin/sh", []string{"-c", "while :; do :; done"}, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}

	exitCode, waitErr := proc.Wait()
	proc.Cleanup()

	elapsed := time.Since(start)
	if exitCode != 0 || waitErr == nil {
		t.Errorf("expected death by signal, got exit=%d err=%v", exitCode, waitErr)
	}
	// The kill signal itself is SIGKILL (the rlimit sets soft = hard, so
	// the kernel skips the SIGXCPU grace window), which is indistinguishable
	// from the context backstop by signal number alone. The elapsed time is
	// the oracle: the limit fires at ~1s of CPU time, the backstop at 60s.
	if elapsed > 10*time.Second {
		t.Errorf("process took %v to die; CPU timeout did not fire promptly", elapsed)
	}
}

// usernsAvailable probes unprivileged user namespace support, which
// UseUserNS launches require.
func usernsAvailable() bool {
	return exec.Command("unshare", "--user", "--map-root-user", "--", "/bin/true").Run() == nil
}

// TestUseUserNS_Happy verifies a launch with an empty user namespace
// runs on supported Linux hosts.
func TestUseUserNS_Happy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("UseUserNS is Linux-only")
	}
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}
	if !usernsAvailable() {
		t.Skip("unprivileged user namespaces unavailable")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID: "userns-happy",
		Profile: Profile{
			UseUserNS: true,
			ReadPaths: []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, trueBin(), nil, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	exitCode, err := proc.Wait()
	proc.Cleanup()
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d (err: %v)", exitCode, err)
	}
}

// TestUseUserNS_ExclusiveWithNetNS verifies the combination fails
// validation instead of one flag silently winning. The library
// validates before the wrapper check, so no wrapper is needed.
func TestUseUserNS_ExclusiveWithNetNS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("UseUserNS is Linux-only")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	_, err = sb.Launch(context.Background(), Config{
		Profile: Profile{
			UseUserNS: true,
			UseNetNS:  true,
		},
	}, trueBin(), nil, nil)
	if err == nil {
		t.Fatal("expected error for UseUserNS combined with UseNetNS")
	}
	if !strings.Contains(err.Error(), "exclusive") {
		t.Errorf("expected an exclusivity error, got: %v", err)
	}
}

// TestDenyUserSessionSockets_RequiresPolicy verifies the session
// socket denial fails validation without the connect policy rather
// than being silently skipped.
func TestDenyUserSessionSockets_RequiresPolicy(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("session socket denial is Linux-only")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	_, err = sb.Launch(context.Background(), Config{
		Profile: Profile{
			DenyUserSessionSockets: true,
		},
	}, trueBin(), nil, nil)
	if err == nil {
		t.Fatal("expected error for session socket denial without the connect policy")
	}
	if !strings.Contains(err.Error(), "requires") {
		t.Errorf("expected a requires-policy error, got: %v", err)
	}
}

// TestDenyUserSessionSockets_Happy verifies the session socket denial
// is accepted with the connect policy active.
func TestDenyUserSessionSockets_Happy(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("session socket denial requires Linux x86_64/aarch64")
	}
	if !udsPolicyEnvSupported() {
		t.Skip("requires wrapper, python3, and an unprivileged user namespace")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID: "deny-session-sockets",
		Profile: Profile{
			DenyUserSessionSockets:    true,
			DenyPrivilegedUnixSockets: true,
			UseNetNS:                  true,
			SeccompProfile:            SeccompProfileBaseline,
			ReadPaths:                 []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, trueBin(), nil, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	exitCode, err := proc.Wait()
	proc.Cleanup()
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d (err: %v)", exitCode, err)
	}
}

// TestMachLookupServices_Validation verifies malformed service names
// fail fast at Launch with a Go error. The rules mirror the library's
// macOS validation so a broken grant list is caught on every platform,
// not only where it would be enforced.
func TestMachLookupServices_Validation(t *testing.T) {
	cases := []struct {
		name    string
		service string
	}{
		{"empty", ""},
		{"leading hyphen", "-com.apple.securityd"},
		{"invalid character", "com.apple.securityd;rm -rf"},
		{"oversized", strings.Repeat("a", 256)},
		{"leading whitespace", " com.apple.securityd"},
		{"trailing whitespace", "com.apple.securityd "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb, err := New()
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer sb.Close()

			_, err = sb.Launch(context.Background(), Config{
				Profile: Profile{
					MachLookupServices: []string{tc.service},
					ReadPaths:          []string{"/usr", "/lib", "/lib64", "/bin"},
				},
			}, trueBin(), nil, nil)
			if err == nil {
				t.Fatal("expected Launch to reject the mach service name")
			}
		})
	}
}

// TestTTY verifies a PTY-backed launch wires the slave as the
// child's stdio. The oracle is the child's own view: [ -t 0 ] and
// [ -t 1 ] only succeed on a terminal, so a dropped TTY binding
// (child inheriting the test binary's stdio — a pipe or /dev/null
// under `go test`) fails the test instead of silently passing.
func TestTTY(t *testing.T) {
	if WrapperPath() == "" {
		t.Skip("arapuca wrapper binary not found")
	}

	sb, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	proc, err := sb.Launch(ctx, Config{
		TaskID: "tty-pty-stdio",
		TTY:    true,
		Profile: Profile{
			ReadPaths: []string{"/usr", "/lib", "/lib64", "/bin"},
		},
	}, "/bin/sh", []string{"-c", "[ -t 0 ] && [ -t 1 ]"}, nil)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	exitCode, err := proc.Wait()
	proc.Cleanup()
	if exitCode != 0 {
		t.Errorf("expected the child to see a terminal on stdin and stdout, got exit %d (err: %v)", exitCode, err)
	}
}
