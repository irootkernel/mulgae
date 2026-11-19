package providercli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	zcodeOSCredentialPrefix    = "enc:v2:os:"
	zcodeKeychainAddon         = "Contents/Resources/app.asar.unpacked/node_modules/@napi-rs/keyring-darwin-arm64/keyring.darwin-arm64.node"
	zcodeSigningRequirement    = `anchor apple generic and identifier "dev.zcode.app" and certificate leaf[subject.OU] = "8A5X4JJ39T"`
	zcodeCredentialReadTimeout = 10 * time.Second
	zcodeModuleRequirement     = `anchor apple generic and identifier "keyring.darwin-arm64" and certificate leaf[subject.OU] = "8A5X4JJ39T"`
)

const zcodeCredentialDecryptScript = `
const { createHash, createDecipheriv } = require('node:crypto');
const { readFileSync } = require('node:fs');

async function readCredential(readKey) {
  const value = readFileSync(0, 'utf8');
  const match = /^enc:v2:os:([a-f0-9]{24}):([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(value);
  if (!match || match[0] !== value) throw new Error();
  const [iv, tag, ciphertext] = match.slice(2).map(part => Buffer.from(part, 'base64url'));
  if (iv.length !== 12 || tag.length !== 16) throw new Error();

  const encoded = await readKey();
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw new Error();
  const key = Buffer.from(encoded, 'base64url');
  try {
    const fingerprint = createHash('sha256').update(key).digest('hex').slice(0, 24);
    if (key.length !== 32 || fingerprint !== match[1]) throw new Error();
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    process.stdout.write(plaintext, () => plaintext.fill(0));
  } finally {
    key.fill(0);
  }
}`

// Run with the installed ZCode identity so Keychain applies the app's existing
// authorization. Only the selected decrypted value crosses the private pipe.
const zcodeKeychainReadScript = zcodeCredentialDecryptScript + `
readCredential(() => {
  const native = { exports: {} };
  process.dlopen(native, '/dev/fd/3');
  return new native.exports.AsyncEntry('ZCode Credential Encryption', process.argv[1]).getPassword();
}).catch(() => { process.exitCode = 1; });
`

func (d RuntimeDefinition) prepareZCodeOSCredential(ctx context.Context, credentialPath string) (zcodeOSCredentialReader, func(), error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" ||
		!validCanonicalAbsolute(credentialPath) {
		return nil, nil, errors.New("unsupported ZCode Keychain credential source")
	}
	bundle, addon, err := d.zcodeKeychainBundle()
	if err != nil {
		return nil, nil, err
	}
	readCtx, cancel := context.WithTimeout(ctx, zcodeCredentialReadTimeout)
	prepared := false
	defer func() {
		if !prepared {
			cancel()
		}
	}()
	if err := verifyZCodeSignature(readCtx, "--verify", "--deep", "--strict", "-R="+zcodeSigningRequirement, bundle); err != nil {
		return nil, nil, zcodeKeychainCommandError(ctx, readCtx, "ZCode Keychain app signature verification failed")
	}
	module, closeModule, err := prepareZCodeKeychainModule(addon)
	if err != nil {
		return nil, nil, err
	}
	info, err := module.Stat()
	if err != nil {
		closeModule()
		return nil, nil, errors.New("ZCode Keychain module identity is unavailable")
	}
	if err := verifyZCodeSignature(readCtx, "--verify", "--strict", "-R="+zcodeModuleRequirement, module.Name()); err != nil {
		closeModule()
		return nil, nil, zcodeKeychainCommandError(ctx, readCtx, "ZCode Keychain module signature verification failed")
	}
	if err := verifyZCodeKeychainModuleIdentity(module, info); err != nil {
		closeModule()
		return nil, nil, err
	}
	account := fmt.Sprintf("%x", sha256.Sum256([]byte(credentialPath)))
	read := func(ciphertext string) (string, error) {
		return d.readZCodeOSCredential(ctx, readCtx, module, info, account, ciphertext)
	}
	prepared = true
	return read, func() {
		cancel()
		closeModule()
	}, nil
}

func (d RuntimeDefinition) zcodeKeychainBundle() (string, string, error) {
	bundle := filepath.Dir(filepath.Dir(d.applicationMetadata))
	if !validCanonicalAbsolute(bundle) || d.applicationMetadata != filepath.Join(bundle, "Contents/Info.plist") ||
		d.executable != filepath.Join(bundle, "Contents/MacOS/ZCode") {
		return "", "", errors.New("invalid ZCode Keychain app bundle binding")
	}
	addon := filepath.Join(bundle, zcodeKeychainAddon)
	canonicalAddon, err := filepath.EvalSymlinks(addon)
	if err != nil || canonicalAddon != addon {
		return "", "", errors.New("ZCode Keychain module is unavailable")
	}
	return bundle, addon, nil
}

func prepareZCodeKeychainModule(addon string) (*os.File, func(), error) {
	moduleBytes, err := readZCodeAccountFile(addon, false, true)
	if err != nil {
		return nil, nil, errors.New("ZCode Keychain module is unavailable")
	}
	scratch, err := os.MkdirTemp("/private/tmp", "mulgae-zcode-keychain-")
	if err != nil {
		return nil, nil, errors.New("ZCode Keychain module scratch directory is unavailable")
	}
	modulePath := filepath.Join(scratch, "keyring.node")
	fd, err := unix.Open(modulePath, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		_ = os.Remove(scratch)
		return nil, nil, errors.New("ZCode Keychain module copy failed")
	}
	module := os.NewFile(uintptr(fd), modulePath)
	closeModule := func() {
		_ = module.Close()
		_ = os.Remove(modulePath)
		_ = os.Remove(scratch)
	}
	if _, err := module.Write(moduleBytes); err != nil {
		closeModule()
		return nil, nil, errors.New("ZCode Keychain module copy failed")
	}
	if _, err := module.Seek(0, io.SeekStart); err != nil {
		closeModule()
		return nil, nil, errors.New("ZCode Keychain module descriptor is unavailable")
	}
	if err := module.Chmod(0400); err != nil {
		closeModule()
		return nil, nil, errors.New("ZCode Keychain module permissions are unavailable")
	}
	return module, closeModule, nil
}

func verifyZCodeKeychainModuleIdentity(module *os.File, expected os.FileInfo) error {
	var stat unix.Stat_t
	current, err := os.Lstat(module.Name())
	if err != nil || !os.SameFile(expected, current) || current.Mode() != 0400 ||
		current.Size() != expected.Size() || !current.ModTime().Equal(expected.ModTime()) ||
		unix.Fstat(int(module.Fd()), &stat) != nil || stat.Nlink != 1 {
		return errors.New("ZCode Keychain module identity changed")
	}
	return nil
}

func (d RuntimeDefinition) readZCodeOSCredential(ctx, readCtx context.Context, module *os.File, info os.FileInfo, account, ciphertext string) (string, error) {
	if len(ciphertext) > zcodeAccountFileLimit {
		return "", errors.New("ZCode Keychain ciphertext exceeds credential limit")
	}
	command := exec.CommandContext(readCtx, d.executable, "-e", zcodeKeychainReadScript, account)
	command.Dir = "/private/var/empty"
	command.Env = []string{"ELECTRON_RUN_AS_NODE=1"}
	command.ExtraFiles = []*os.File{module}
	command.Stdin = strings.NewReader(ciphertext)
	command.WaitDelay = time.Second
	var output zcodeCredentialOutput
	command.Stdout = &output
	defer func() { clear(output.buffer.Bytes()) }()

	if err := verifyZCodeKeychainModuleIdentity(module, info); err != nil {
		return "", err
	}
	if !matchesZCodeKeychainFile(d.applicationMetadata, d.applicationMetadataSHA256) {
		return "", errors.New("ZCode Keychain app metadata identity changed")
	}
	if !matchesZCodeKeychainFile(d.executable, d.executableSHA256) {
		return "", errors.New("ZCode Keychain app executable identity changed")
	}
	if err := command.Run(); err != nil {
		return "", zcodeKeychainCommandError(ctx, readCtx, "ZCode Keychain credential could not be read or authenticated")
	}
	return output.buffer.String(), nil
}

func matchesZCodeKeychainFile(path, digest string) bool {
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return false
	}
	file, err := readZCodeAccountFile(path, false, true)
	return err == nil && fmt.Sprintf("sha256:%x", sha256.Sum256(file)) == digest
}

func zcodeKeychainCommandError(ctx, commandCtx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if commandCtx.Err() != nil {
		return errors.New("ZCode Keychain operation timed out")
	}
	return errors.New(message)
}

func verifyZCodeSignature(ctx context.Context, arguments ...string) error {
	command := exec.CommandContext(ctx, "/usr/bin/codesign", arguments...)
	command.Env = []string{}
	command.Dir = "/private/var/empty"
	return command.Run()
}

type zcodeCredentialOutput struct{ buffer bytes.Buffer }

func (output *zcodeCredentialOutput) Write(data []byte) (int, error) {
	if len(data) > zcodeAccountFileLimit-output.buffer.Len() {
		return 0, errors.New("ZCode Keychain reply exceeds credential limit")
	}
	return output.buffer.Write(data)
}
