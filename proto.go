// The twin Credential Tester by @mekalabs.
// This tool was created to solve specific problems.
// about fundamental things that are often overlooked in credential testing problems.
// The principle of this tool is no one credentials left behind.
// Authorized only, great power come great responsibility.
// Tools testing has been carried out with maximum capability.
// using rockyou.txt with 30 million tasks with a maximum RAM usage of 8GB.
// Use the RAM limit function to avoid chaos in the martial arts world.

// {{{ IMPORT

package main

import (
	"fmt"
	"net"
	"strings"
	"time"
	"bufio"
	"strconv"
	"github.com/jlaffaye/ftp"
	"golang.org/x/crypto/ssh"
)

// }}}
// {{{ SECTION 1: SSH TESTER
type SSHTester struct {
	timeout float64
}

func (s *SSHTester) Test(target string, port int, username, password string) (string, float64, string) {
	start := time.Now()

	// Build address
	addr := fmt.Sprintf("%s:%d", target, port)
	if target == "localhost" {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}

	// STEP 1: TCP Connection dengan timeout ketat
	tcpTimeout := time.Duration(s.timeout * 0.4) * time.Second // 40% untuk TCP
	conn, err := net.DialTimeout("tcp", addr, tcpTimeout)
	if err != nil {
		elapsed := time.Since(start).Seconds()
		return s.handleNetError(err, elapsed)
	}
	defer conn.Close()

	// STEP 2: Set deadline untuk SEMUA SSH operations
	sshDeadline := time.Now().Add(time.Duration(s.timeout * 0.6) * time.Second)
	conn.SetDeadline(sshDeadline)

	// STEP 3: SSH Handshake dengan connection yang sudah ada deadline
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// NO Timeout field here - using conn deadline instead
	})

	if err != nil {
		elapsed := time.Since(start).Seconds()

		// Check for deadline exceeded
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "banner-timeout", elapsed, "SSH handshake timeout"
		}

		return s.handleSSHError(err, elapsed)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	elapsed := time.Since(start).Seconds()

	// STEP 4: Test session (dengan deadline yang masih berlaku)
	session, err := client.NewSession()
	if err == nil {
		session.Close()
		return "shell-access", elapsed, ""
	}

	return "success", elapsed, ""
}

func (s *SSHTester) handleNetError(err error, elapsed float64) (string, float64, string) {
	errorStr := err.Error()
	errorLower := strings.ToLower(errorStr)

	switch {
	case strings.Contains(errorLower, "timeout"):
		return "connection-timeout", elapsed, errorStr
	case strings.Contains(errorLower, "connection refused"):
		return "connection-refused", elapsed, errorStr
	case strings.Contains(errorLower, "connection reset"):
		return "connection-reset", elapsed, errorStr
	case strings.Contains(errorLower, "no route"):
		return "no-route", elapsed, errorStr
	case strings.Contains(errorLower, "network unreachable"):
		return "network-unreachable", elapsed, errorStr
	default:
		return "connection-error", elapsed, errorStr
	}
}

func (s *SSHTester) handleSSHError(err error, elapsed float64) (string, float64, string) {
	errorStr := err.Error()
	errorLower := strings.ToLower(errorStr)

	switch {
	case strings.Contains(errorLower, "unable to authenticate"),
		 strings.Contains(errorLower, "authentication failed"):
		return "auth-failed", elapsed, errorStr
	case strings.Contains(errorLower, "handshake failed"):
		if strings.Contains(errorLower, "protocol") {
			return "protocol-mismatch", elapsed, errorStr
		}
		return "handshake-error", elapsed, errorStr
	case strings.Contains(errorLower, "account locked"):
		return "account-locked", elapsed, errorStr
	case strings.Contains(errorLower, "password expired"):
		return "password-expired", elapsed, errorStr
	case strings.Contains(errorLower, "user disabled"):
		return "user-disabled", elapsed, errorStr
	default:
		// Generic SSH error
		if strings.Contains(errorLower, "i/o timeout") ||
		   strings.Contains(errorLower, "timeout") {
			return "ssh-timeout", elapsed, errorStr
		}
		return "ssh-error", elapsed, errorStr
	}
}
// }}}
// {{{ SECTION 3: FTP TESTER
type FTPTester struct {
	timeout float64
	debug   bool
}

func (f *FTPTester) Test(target string, port int, username, password string) (string, float64, string) {
	start := time.Now()

	conn, err := ftp.Dial(fmt.Sprintf("%s:%d", target, port),
		ftp.DialWithTimeout(time.Duration(f.timeout*float64(time.Second))))

	if err != nil {
		elapsed := time.Since(start).Seconds()
		errorStr := err.Error()
		errorLower := strings.ToLower(errorStr)

		if f.debug {
			fmt.Printf("[FTP-DEBUG] Dial error for %s:%d - %s\n", target, port, errorStr)
		}

		if strings.Contains(errorLower, "dial tcp") {
			if strings.Contains(errorLower, "i/o timeout") {
				return "timeout", elapsed, errorStr
			}
			if strings.Contains(errorLower, "connection refused") {
				return "connection-refused", elapsed, errorStr
			}
			if strings.Contains(errorLower, "invalid port") {
				return "connection-refused", elapsed, errorStr
			}
			if strings.Contains(errorLower, "no such host") {
				return "no-route", elapsed, errorStr
			}
			return "connection-error", elapsed, errorStr
		}

		if strings.Contains(errorLower, "timeout") {
			return "timeout", elapsed, errorStr
		}

		if strings.Contains(errorLower, "eof") {
			return "connection-reset", elapsed, errorStr
		}
		return "protocol-error", elapsed, errorStr
	}
	defer conn.Quit()

	err = conn.Login(username, password)
	elapsed := time.Since(start).Seconds()

	if err != nil {
		errorStr := err.Error()
		errorLower := strings.ToLower(errorStr)

		if f.debug {
			fmt.Printf("[FTP-DEBUG] Login error for %s@%s:%d - %s\n",
				username, target, port, errorStr)
		}

		if strings.Contains(errorLower, "permission denied") ||
			strings.Contains(errorLower, "login incorrect") ||
			strings.Contains(errorLower, "530") ||
			strings.Contains(errorLower, "not logged in") ||
			strings.Contains(errorLower, "authentication failed") ||
			strings.Contains(errorLower, "auth failed") ||
			strings.Contains(errorLower, "invalid login") {
			return "auth-failed", elapsed, errorStr
		}

		if strings.Contains(errorLower, "account locked") ||
			strings.Contains(errorLower, "locked out") {
			return "account-locked", elapsed, errorStr
		}

		if strings.Contains(errorLower, "eof") {
			return "auth-failed", elapsed, errorStr
		}

		if strings.Contains(errorLower, "broken pipe") ||
			strings.Contains(errorLower, "write: connection reset") {
			return "connection-reset", elapsed, errorStr
		}

		if strings.Contains(errorLower, "i/o timeout") ||
			strings.Contains(errorLower, "read: timeout") {
			return "timeout", elapsed, errorStr
		}

		if strings.Contains(errorLower, "connection reset") ||
			strings.Contains(errorLower, "conn reset") {
			return "connection-reset", elapsed, errorStr
		}

		return "ftp-error", elapsed, errorStr
	}

	return "success", elapsed, ""
}
// }}}
// {{{ SECTION 3: TELNET TESTER

type TelnetTester struct {
	timeout float64
	debug   bool
}

func (t *TelnetTester) Test(target string, port int, username, password string) (string, float64, string) {
	start := time.Now()

	address := target
	if target == "localhost" {
		address = "127.0.0.1"
	}

	fullAddress := fmt.Sprintf("%s:%d", address, port)

	if t.debug {
		fmt.Printf("[TELNET-DEBUG] Connecting to %s\n", fullAddress)
	}
	conn, err := net.DialTimeout("tcp", fullAddress, time.Duration(t.timeout*float64(time.Second)))
	if err != nil {
		elapsed := time.Since(start).Seconds()
		return t.mapError(err, elapsed)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(t.timeout * float64(time.Second))))

	if t.debug {
		fmt.Println("[TELNET-DEBUG] Handling telnet negotiation...")
	}
	t.handleAllNegotiation(conn)
	conn.SetDeadline(time.Now().Add(time.Duration(t.timeout * float64(time.Second))))

	if t.debug {
		fmt.Printf("[TELNET-DEBUG] Sending username: %s\n", username)
	}
	conn.Write([]byte(username + "\r\n"))

	time.Sleep(10 * time.Millisecond)
	response1 := t.readAvailable(conn, 2*time.Second)

	if t.debug && len(response1) > 0 {
		filtered := t.filterTelnetControls(response1)
		if len(filtered) > 0 {
			fmt.Printf("[TELNET-DEBUG] After username: %q\n", string(filtered))
		}
	}

	if t.debug {
		fmt.Printf("[TELNET-DEBUG] Sending password: %s\n", password)
	}
	conn.Write([]byte(password + "\r\n"))

	time.Sleep(10 * time.Millisecond)
	response2 := t.readAvailable(conn, 3*time.Second)
	elapsed := time.Since(start).Seconds()
	filtered := t.filterTelnetControls(response2)

	if t.debug && len(filtered) > 0 {
		fmt.Printf("[TELNET-DEBUG] Final response: %q\n", string(filtered))
	}
	return t.analyzeResponse(filtered, username, elapsed)
}

func (t *TelnetTester) handleAllNegotiation(conn net.Conn) {
	for i := 0; i < 5; i++ {
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)

		if err != nil || n == 0 {
			break
		}

		var response []byte
		for j := 0; j < n; j++ {
			if buf[j] == 0xFF && j+2 < n {
				cmd := buf[j+1]
				opt := buf[j+2]

				switch cmd {
				case 0xFB: // WILL → DONT
					response = append(response, 0xFF, 0xFE, opt)
				case 0xFD: // DO → WONT
					response = append(response, 0xFF, 0xFC, opt)
				}

				j += 2
			}
		}

		if len(response) > 0 {
			conn.Write(response)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func (t *TelnetTester) readAvailable(conn net.Conn, timeout time.Duration) []byte {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var result []byte
	buf := make([]byte, 4096)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			break
		}
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	}

	return result
}

func (t *TelnetTester) filterTelnetControls(data []byte) []byte {
	var result []byte
	i := 0

	for i < len(data) {
		if data[i] == 0xFF && i+2 < len(data) {
			i += 3 // Skip IAC sequence
		} else {
			result = append(result, data[i])
			i++
		}
	}

	return result
}

func (t *TelnetTester) analyzeResponse(response []byte, username string, elapsed float64) (string, float64, string) {
	responseStr := string(response)

	if len(response) == 0 || strings.TrimSpace(responseStr) == "" {
		return "auth-failed", elapsed, "empty-response"
	}
	responseLower := strings.ToLower(responseStr)

	if strings.Contains(responseLower, "welcome") ||
		strings.Contains(responseLower, "last login") {
		return "success", elapsed, "welcome-message-found"
	}

	shellPrompts := []string{"# ", "$ ", "> ", "% ", "~#", "~$"}
	for _, prompt := range shellPrompts {
		if strings.Contains(responseStr, prompt) {
			return "shell-access", elapsed, fmt.Sprintf("shell-prompt:%s", prompt)
		}
	}

	if strings.Contains(responseStr, username+"@") {
		return "success", elapsed, fmt.Sprintf("username-prompt:%s", username)
	}

	failureIndicators := []string{
		"login incorrect",
		"invalid",
		"denied",
		"fail",
		"error",
		"wrong",
		"bad",
		"incorrect",
		"access denied",
		"permission denied",
		"authentication failed",
		"login failed",
	}

	for _, indicator := range failureIndicators {
		if strings.Contains(responseLower, indicator) {
			return "auth-failed", elapsed, fmt.Sprintf("failure:%s", indicator)
		}
	}
	if strings.Contains(responseLower, "password:") {
		return "auth-failed", elapsed, "password-prompt-again"
	}
	if len(response) > 100 {
		return "success", elapsed, "long-response"
	}
	return "auth-failed", elapsed, "no-clear-indicators"
}

func (t *TelnetTester) mapError(err error, elapsed float64) (string, float64, string) {
	errStr := err.Error()
	errLower := strings.ToLower(errStr)

	if strings.Contains(errLower, "timeout") {
		return "timeout", elapsed, errStr
	}
	if strings.Contains(errLower, "connection refused") {
		return "connection-refused", elapsed, errStr
	}
	if strings.Contains(errLower, "connection reset") {
		return "connection-reset", elapsed, errStr
	}
	if strings.Contains(errLower, "eof") {
		return "auth-failed", elapsed, "connection-closed"
	}
	return "connection-error", elapsed, errStr
}
// }}}
// {{{ SECTION 4: COMMAND EXECUTION

func ExecuteCommandForTask(task Task, command string, timeout float64, debug bool) string {
    if command == "" {
        return ""
    }

    switch task.Protocol {
    case "ssh":
        return executeSSHCommand(task, command, timeout, debug)
    case "telnet":
        return executeTelnetCommand(task, command, timeout, debug)
    default:
        return ""
    }
}

func executeSSHCommand(task Task, command string, timeout float64, debug bool) string {
    if debug {
        fmt.Printf("[SSH-CMD] Executing command on %s:%d - %s\n",
            task.Target, task.Port, command)
    }

    config := &ssh.ClientConfig{
        User: task.Username,
        Auth: []ssh.AuthMethod{
            ssh.Password(task.Password),
        },
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout:         time.Duration(timeout * float64(time.Second)),
    }

    addr := fmt.Sprintf("%s:%d", task.Target, task.Port)

    client, err := ssh.Dial("tcp", addr, config)
    if err != nil {
        if debug {
            fmt.Printf("[SSH-CMD] Connection failed: %v\n", err)
        }
        return fmt.Sprintf("CONNECT-ERROR: %v", err)
    }
    defer client.Close()

    if needsShellExecution(command) {
        return executeWithShell(client, command, debug)
    } else {
        return executeSimple(client, command, debug)
    }
}

func needsShellExecution(cmd string) bool {
    operators := []string{"&&", "||", ";", "|", ">", "<", ">>", "<<"}

    for _, op := range operators {
        if strings.Contains(cmd, op) {
            return true
        }
    }

    return false
}

func executeSimple(client *ssh.Client, cmd string, debug bool) string {
    session, err := client.NewSession()
    if err != nil {
        if debug {
            fmt.Printf("[SSH-CMD] Session failed: %v\n", err)
        }
        return fmt.Sprintf("SESSION-ERROR: %v", err)
    }
    defer session.Close()

    output, err := session.CombinedOutput(cmd)
    if err != nil {
        if debug {
            fmt.Printf("[SSH-CMD] Command failed: %v\n", err)
        }
        outputStr := strings.TrimSpace(string(output))
        if outputStr == "" {
            return fmt.Sprintf("EXEC-ERROR: %v", err)
        }
        return fmt.Sprintf("EXEC-ERROR: %v | Output: %s", err, outputStr)
    }

    result := strings.TrimSpace(string(output))
    if debug {
        printDebugOutput("[SSH-CMD] Output:", result)
    }

    return result
}

func executeWithShell(client *ssh.Client, cmd string, debug bool) string {
    session, err := client.NewSession()
    if err != nil {
        if debug {
            fmt.Printf("[SSH-CMD] Session failed: %v\n", err)
        }
        return fmt.Sprintf("SESSION-ERROR: %v", err)
    }
    defer session.Close()

    escapedCmd := strings.ReplaceAll(cmd, "'", "'\"'\"'")
    shellCmd := fmt.Sprintf("sh -c '%s'", escapedCmd)

    if debug {
        fmt.Printf("[SSH-CMD] Shell command: %s\n", shellCmd)
    }

    output, err := session.CombinedOutput(shellCmd)
    if err != nil {
        if debug {
            fmt.Printf("[SSH-CMD] Shell command failed: %v\n", err)
        }
        outputStr := strings.TrimSpace(string(output))
        if outputStr == "" {
            return fmt.Sprintf("SHELL-ERROR: %v", err)
        }
        return fmt.Sprintf("SHELL-ERROR: %v | Output: %s", err, outputStr)
    }

    result := strings.TrimSpace(string(output))
    if debug {
        printDebugOutput("[SSH-CMD] Shell output:", result)
    }

    return result
}

func executeTelnetCommand(task Task, command string, timeout float64, debug bool) string {
    if debug {
        fmt.Printf("[TELNET-CMD] Executing command on %s:%d - %s\n",
            task.Target, task.Port, command)
    }

    address := task.Target
    if task.Target == "localhost" {
        address = "127.0.0.1"
    }

    fullAddress := fmt.Sprintf("%s:%d", address, task.Port)

    conn, err := net.DialTimeout("tcp", fullAddress,
        time.Duration(timeout * float64(time.Second)))
    if err != nil {
        if debug {
            fmt.Printf("[TELNET-CMD] Connection failed: %v\n", err)
        }
        return fmt.Sprintf("CONNECT-ERROR: %v", err)
    }
    defer conn.Close()

    deadline := time.Now().Add(time.Duration(timeout * float64(time.Second)))
    conn.SetDeadline(deadline)

    handleTelnetNegotiation(conn)
    conn.Write([]byte(task.Username + "\r\n"))
    time.Sleep(100 * time.Millisecond)
    conn.Write([]byte(task.Password + "\r\n"))
    time.Sleep(300 * time.Millisecond)

    clearTelnetBuffer(conn)
    time.Sleep(500 * time.Millisecond)

    cmdWithNewline := command + "\r\n"
    if debug {
        fmt.Printf("[TELNET-CMD] Sending command: %q\n", strings.TrimSpace(cmdWithNewline))
    }

    conn.Write([]byte(cmdWithNewline))
    time.Sleep(500 * time.Millisecond)
    output := readTelnetOutput(conn, command, debug)

    if debug {
        printDebugOutput("[TELNET-CMD] Output:", output)
    }

    return output
}

func handleTelnetNegotiation(conn net.Conn) {
    for i := 0; i < 3; i++ {
        buf := make([]byte, 1024)
        conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
        n, err := conn.Read(buf)

        if err != nil || n == 0 {
            break
        }

        var response []byte
        for j := 0; j < n; j++ {
            if buf[j] == 0xFF && j+2 < n {
                cmd := buf[j+1]
                opt := buf[j+2]

                switch cmd {
                case 0xFB: // WILL → DONT
                    response = append(response, 0xFF, 0xFE, opt)
                case 0xFD: // DO → WONT
                    response = append(response, 0xFF, 0xFC, opt)
                }
                j += 2
            }
        }

        if len(response) > 0 {
            conn.Write(response)
        }

        time.Sleep(50 * time.Millisecond)
    }
}

func clearTelnetBuffer(conn net.Conn) {
    conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
    buf := make([]byte, 4096)
    for {
        _, err := conn.Read(buf)
        if err != nil {
            break
        }
    }
    conn.SetReadDeadline(time.Time{}) // Reset deadline
}

func readTelnetOutput(conn net.Conn, command string, debug bool) string {
    conn.SetDeadline(time.Now().Add(3 * time.Second))

    var output strings.Builder
    reader := bufio.NewReader(conn)

    timeout := time.After(2 * time.Second)
    maxBytes := 8192 // 8KB max
    bytesRead := 0

readLoop:
    for bytesRead < maxBytes {
        select {
        case <-timeout:
            if debug {
                fmt.Printf("[TELNET-CMD] Read timeout after 2s\n")
            }
            break readLoop

        default:
            conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
            buf := make([]byte, 1024)
            n, err := reader.Read(buf)

            if err != nil || n == 0 {
                time.Sleep(100 * time.Millisecond)
                continue
            }

            cleanData := filterTelnetControls(buf[:n])
            if len(cleanData) > 0 {
                output.Write(cleanData)
                bytesRead += len(cleanData)

                currentOutput := output.String()
                if hasShellPrompt(currentOutput) {
                    if debug {
                        fmt.Printf("[TELNET-CMD] Detected shell prompt, stopping read\n")
                    }
                    break readLoop
                }
            }
        }
    }

    return cleanTelnetOutput(output.String(), command)
}

func filterTelnetControls(data []byte) []byte {
    var result []byte
    i := 0

    for i < len(data) {
        if data[i] == 0xFF && i+2 < len(data) {
            i += 3 // Skip IAC sequence
        } else {
            result = append(result, data[i])
            i++
        }
    }

    return result
}

func hasShellPrompt(output string) bool {
    prompts := []string{
        "# ", "$ ", "> ", "% ", // Unix prompts
        ":~#", ":~$",            // Home directory prompts
        "\\$ ", "\\# ",          // Escaped prompts
        "login:", "Password:",   // Login prompts
        "Username:", "user:",    // More login prompts
    }

    for _, prompt := range prompts {
        if strings.Contains(output, prompt) {
            return true
        }
    }

    if strings.Contains(output, ">") && len(output) > 50 {
        return true
    }

    return false
}

func cleanTelnetOutput(output, command string) string {
    if output == "" {
        return "NO-OUTPUT"
    }

    output = strings.Replace(output, command+"\r\n", "", 1)
    output = strings.Replace(output, command+"\n", "", 1)

    output = strings.ReplaceAll(output, "\r", "")

    lines := strings.Split(output, "\n")
    var cleanLines []string

    for _, line := range lines {
        trimmed := strings.TrimSpace(line)

        if trimmed == "" || strings.Contains(trimmed, command) {
            continue
        }

        if strings.HasPrefix(trimmed, "\xff") ||
           strings.HasPrefix(trimmed, "\x1b[") || // ANSI escape codes
           trimmed == "Password:" ||
           trimmed == "login:" {
            continue
        }

        cleanLines = append(cleanLines, trimmed)
    }

    result := strings.Join(cleanLines, "\n")

    if len(result) > 4096 {
        result = result[:4096] + "\n...[truncated]"
    }

    return result
}

func printDebugOutput(prefix, output string) {
    if output == "" {
        fmt.Printf("%s <empty>\n", prefix)
        return
    }

    if len(output) > 200 {
        fmt.Printf("%s %s... [len=%d]\n", prefix, output[:200], len(output))
    } else {
        fmt.Printf("%s %s\n", prefix, output)
    }
}

// }}}
// {{{ SECTION 5: PROTOCOL FACTORY
func createProtocolTester(protocol string, timeout float64, debug bool) ProtocolTester {
	switch protocol {
	case "ssh":
		return &SSHTester{timeout: timeout}
	case "ftp":
		return &FTPTester{timeout: timeout, debug: debug}
	case "telnet":
		return &TelnetTester{timeout: timeout, debug: debug}
	default:
		return nil
	}
}
// }}}
// {{{ SECTION 6: IP UTILITIES

// ParseTargetRange - Parse berbagai format target
func ParseTargetRange(targetSpec string) ([]string, error) {
	targetSpec = strings.TrimSpace(targetSpec)

	// Case 1: CIDR notation (192.168.1.0/24)
	if strings.Contains(targetSpec, "/") {
		return ExpandCIDR(targetSpec)
	}

	// Case 2: IP range (192.168.1.1-100)
	if strings.Contains(targetSpec, "-") && !strings.Contains(targetSpec, ",") {
		return ExpandIPRange(targetSpec)
	}

	// Case 3: Comma-separated list
	if strings.Contains(targetSpec, ",") {
		ips := strings.Split(targetSpec, ",")
		var cleanIPs []string
		for _, ip := range ips {
			cleanIPs = append(cleanIPs, strings.TrimSpace(ip))
		}
		return cleanIPs, nil
	}

	// Case 4: Single IP/hostname
	return []string{targetSpec}, nil
}

// ExpandCIDR - Expand CIDR ke list IP
func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}

// ExpandIPRange - Expand IP range
func ExpandIPRange(rangeSpec string) ([]string, error) {
	parts := strings.Split(rangeSpec, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", rangeSpec)
	}

	startIP := strings.TrimSpace(parts[0])
	endPart := strings.TrimSpace(parts[1])

	// Parse start IP
	start := net.ParseIP(startIP)
	if start == nil {
		return nil, fmt.Errorf("invalid start IP: %s", startIP)
	}

	// Check if endPart is just the last octet
	if !strings.Contains(endPart, ".") {
		// Format: 192.168.1.1-100
		ipParts := strings.Split(startIP, ".")
		if len(ipParts) != 4 {
			return nil, fmt.Errorf("invalid IP format: %s", startIP)
		}

		startOctet, err := strconv.Atoi(ipParts[3])
		if err != nil {
			return nil, fmt.Errorf("invalid octet: %s", ipParts[3])
		}

		endOctet, err := strconv.Atoi(endPart)
		if err != nil {
			return nil, fmt.Errorf("invalid end octet: %s", endPart)
		}

		if endOctet < startOctet || endOctet > 255 {
			return nil, fmt.Errorf("invalid octet range: %d-%d", startOctet, endOctet)
		}

		var ips []string
		for i := startOctet; i <= endOctet; i++ {
			ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", ipParts[0], ipParts[1], ipParts[2], i))
		}
		return ips, nil
	}

	// Full IP range: 192.168.1.1-192.168.1.100
	end := net.ParseIP(endPart)
	if end == nil {
		return nil, fmt.Errorf("invalid end IP: %s", endPart)
	}

	// Simple expansion
	startInt := ipToInt(start.To4())
	endInt := ipToInt(end.To4())

	if startInt > endInt {
		return nil, fmt.Errorf("start IP must be less than end IP")
	}

	if (endInt - startInt) > 65536 { // Limit to 65K IPs
		return nil, fmt.Errorf("range too large (> 65536 IPs). Use CIDR notation")
	}

	var ips []string
	for i := startInt; i <= endInt; i++ {
		ips = append(ips, intToIP(i).String())
	}

	return ips, nil
}

// Helper functions
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipToInt(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func intToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// }}}
