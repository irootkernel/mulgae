//go:build darwin && arm64

// Package gittarget provides Darwin Git target capture adapters for ports.
package gittarget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	gitExecutable          = "/usr/bin/git"
	defaultMaxCommandBytes = 64 << 10
	defaultMaxStdoutBytes  = 16 << 20
	defaultMaxStderrBytes  = 1 << 20
)

var errStreamLimit = errors.New("Git command stream exceeds configured limit")

// Command is one direct Git invocation. Args excludes the git executable and
// is passed verbatim to exec.CommandContext; it is never interpreted by a shell.
type Command struct {
	Dir  string
	Args []string
}

// Clone returns a caller-owned command copy suitable for transcripts.
func (command Command) Clone() Command {
	return Command{
		Dir:  command.Dir,
		Args: cloneStrings(command.Args),
	}
}

// Argv returns the exact process argv, including the pinned Git executable.
func (command Command) Argv() []string {
	argv := make([]string, 1, len(command.Args)+1)
	argv[0] = gitExecutable
	argv = append(argv, command.Args...)
	return argv
}

// Result contains the bounded stdout and stderr bytes from one Git command.
type Result struct {
	Stdout []byte
	Stderr []byte
}

// Clone returns a caller-owned result copy.
func (result Result) Clone() Result {
	return Result{
		Stdout: cloneBytes(result.Stdout),
		Stderr: cloneBytes(result.Stderr),
	}
}

// Runner executes a direct Git command. Implementations must not invoke a
// shell or reinterpret Command.Args.
type Runner interface {
	Run(context.Context, Command) (Result, error)
}

// ExecRunner executes direct Git argv with fixed environment and memory caps.
// A zero cap selects the fixed default; negative caps are rejected.
type ExecRunner struct {
	MaxCommandBytes int
	MaxStdoutBytes  int
	MaxStderrBytes  int
}

// NewExecRunner returns an ExecRunner with the fixed default caps.
func NewExecRunner() ExecRunner {
	return ExecRunner{
		MaxCommandBytes: defaultMaxCommandBytes,
		MaxStdoutBytes:  defaultMaxStdoutBytes,
		MaxStderrBytes:  defaultMaxStderrBytes,
	}
}

// DeterministicEnvironment returns the complete environment given to every
// Git child process. Canonical reads use an isolated Git admin directory.
func DeterministicEnvironment() []string {
	return []string{
		"HOME=/var/empty",
		"LANG=C",
		"LC_ALL=C",
		"PAGER=cat",
		"PATH=/usr/bin:/bin",
		"TZ=UTC",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_PAGER=cat",
		"GIT_TERMINAL_PROMPT=0",
	}
}

// CommandInputError reports an invalid direct Git invocation before execution.
type CommandInputError struct {
	Reason string
}

func (err *CommandInputError) Error() string {
	return "Git command input: " + err.Reason
}

// CommandLimitError reports an argv that exceeds the configured command cap.
type CommandLimitError struct {
	Limit   int
	Actual  int
	command Command
}

func (err *CommandLimitError) Error() string {
	return fmt.Sprintf("Git command exceeds %d-byte argv limit", err.Limit)
}

// Command returns a caller-owned exact invocation transcript.
func (err *CommandLimitError) Command() Command {
	return err.command.Clone()
}

// OutputLimitError reports a stdout or stderr stream that exceeded its cap.
type OutputLimitError struct {
	Stream  string
	Limit   int
	command Command
}

func (err *OutputLimitError) Error() string {
	return fmt.Sprintf("Git command %s exceeds %d-byte limit", err.Stream, err.Limit)
}

// Command returns a caller-owned exact invocation transcript.
func (err *OutputLimitError) Command() Command {
	return err.command.Clone()
}

// CommandError reports an attempted Git command that did not exit successfully.
type CommandError struct {
	command Command
	stderr  []byte
	cause   error
}

func (err *CommandError) Error() string {
	return "Git command failed"
}

// Unwrap returns the underlying process or context error.
func (err *CommandError) Unwrap() error {
	return err.cause
}

// Command returns a caller-owned exact invocation transcript.
func (err *CommandError) Command() Command {
	return err.command.Clone()
}

// Stderr returns a caller-owned bounded stderr copy.
func (err *CommandError) Stderr() []byte {
	return cloneBytes(err.stderr)
}

// Run executes git with Command.Args as direct argv and no shell. It fails
// closed on a command, stdout, or stderr cap violation.
func (runner ExecRunner) Run(ctx context.Context, command Command) (Result, error) {
	if ctx == nil {
		return Result{}, &CommandInputError{Reason: "nil context"}
	}
	if err := validateCommand(command); err != nil {
		return Result{}, err
	}

	maxCommand, maxStdout, maxStderr, err := runner.limits()
	if err != nil {
		return Result{}, err
	}
	actualCommandBytes := commandBytes(command)
	if actualCommandBytes > maxCommand {
		return Result{}, &CommandLimitError{
			Limit:   maxCommand,
			Actual:  actualCommandBytes,
			command: command.Clone(),
		}
	}
	if err := verifyGitExecutable(); err != nil {
		return Result{}, err
	}

	stdout := cappedBuffer{limit: maxStdout}
	stderr := cappedBuffer{limit: maxStderr}
	child := exec.CommandContext(ctx, gitExecutable, command.Args...)
	child.Dir = command.Dir
	child.Env = DeterministicEnvironment()
	child.Stdout = &stdout
	child.Stderr = &stderr
	commandErr := child.Run()

	if stdout.exceeded {
		return Result{}, &OutputLimitError{Stream: "stdout", Limit: maxStdout, command: command.Clone()}
	}
	if stderr.exceeded {
		return Result{}, &OutputLimitError{Stream: "stderr", Limit: maxStderr, command: command.Clone()}
	}
	if commandErr != nil {
		return Result{}, &CommandError{
			command: command.Clone(),
			stderr:  cloneBytes(stderr.Bytes()),
			cause:   commandErr,
		}
	}
	return Result{
		Stdout: cloneBytes(stdout.Bytes()),
		Stderr: cloneBytes(stderr.Bytes()),
	}, nil
}

func (runner ExecRunner) limits() (int, int, int, error) {
	maxCommand := runner.MaxCommandBytes
	maxStdout := runner.MaxStdoutBytes
	maxStderr := runner.MaxStderrBytes
	if maxCommand == 0 {
		maxCommand = defaultMaxCommandBytes
	}
	if maxStdout == 0 {
		maxStdout = defaultMaxStdoutBytes
	}
	if maxStderr == 0 {
		maxStderr = defaultMaxStderrBytes
	}
	if maxCommand < 0 || maxStdout < 0 || maxStderr < 0 {
		return 0, 0, 0, &CommandInputError{Reason: "caps must not be negative"}
	}
	return maxCommand, maxStdout, maxStderr, nil
}

func validateCommand(command Command) error {
	if command.Dir == "" || !filepath.IsAbs(command.Dir) || filepath.Clean(command.Dir) != command.Dir {
		return &CommandInputError{Reason: "directory must be an absolute canonical path"}
	}
	if len(command.Args) == 0 {
		return &CommandInputError{Reason: "argv must contain a Git subcommand"}
	}
	for _, arg := range command.Args {
		if strings.ContainsRune(arg, 0) {
			return &CommandInputError{Reason: "argv must not contain NUL"}
		}
	}
	return nil
}

func commandBytes(command Command) int {
	size := len(gitExecutable)
	for _, arg := range command.Args {
		size++
		size += len(arg)
	}
	return size
}

func verifyGitExecutable() error {
	if !filepath.IsAbs(gitExecutable) || filepath.Clean(gitExecutable) != gitExecutable {
		return &CommandInputError{Reason: "pinned Git executable is not absolute"}
	}
	info, err := os.Lstat(gitExecutable)
	if err != nil {
		return &CommandInputError{Reason: "pinned Git executable is unavailable"}
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return &CommandInputError{Reason: "pinned Git executable is not executable"}
	}
	return nil
}

type cappedBuffer struct {
	limit    int
	buffer   bytes.Buffer
	exceeded bool
}

func (buffer *cappedBuffer) Write(value []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		if len(value) > 0 {
			buffer.exceeded = true
			return 0, errStreamLimit
		}
		return 0, nil
	}
	if len(value) > remaining {
		written, _ := buffer.buffer.Write(value[:remaining])
		buffer.exceeded = true
		return written, errStreamLimit
	}
	return buffer.buffer.Write(value)
}

func (buffer *cappedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copyValue := make([]byte, len(value))
	copy(copyValue, value)
	return copyValue
}

func cloneStrings(value []string) []string {
	if value == nil {
		return nil
	}
	copyValue := make([]string, len(value))
	copy(copyValue, value)
	return copyValue
}
