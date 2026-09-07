package ports

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestProtocolProviderPacketBindingKeepsPacketOutOfArgvAndStdin(t *testing.T) {
	packet := schedulingTestPacket(t, []byte("protocol packet"))
	binding, err := NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Channel() != ProviderPacketChannelProtocol {
		t.Fatalf("Channel() = %q", binding.Channel())
	}
	if !binding.Valid() {
		t.Fatal("protocol binding is invalid")
	}
	if _, err := NewProtocolProviderPacketBinding(ProviderPacket{}); err == nil {
		t.Fatal("NewProtocolProviderPacketBinding() accepted invalid packet")
	}
	if !ProviderPacketChannelProtocol.Valid() {
		t.Fatal("protocol channel is invalid")
	}
}

func TestNewProviderProtocolProcessRequestStartsWithEmptyStdin(t *testing.T) {
	packet := schedulingTestPacket(t, []byte("protocol packet"))
	binding, err := NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}

	request, err := NewProviderProtocolProcessRequest(
		"/usr/bin/provider", []string{"/usr/bin/provider", "app-server"}, nil, "/work",
		binding, 5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := request.Stdin(); len(got) != 0 {
		t.Fatalf("Stdin() = %q, want empty", got)
	}
	if got := request.Timeout(); got != 5*time.Second {
		t.Fatalf("Timeout() = %s", got)
	}
	attached, ok := request.ProviderPacketBinding()
	if !ok || attached.Channel() != ProviderPacketChannelProtocol || attached.PacketIdentity() != packet.Identity() {
		t.Fatalf("ProviderPacketBinding() = %#v, %t", attached, ok)
	}
	if !request.Valid() {
		t.Fatal("request is invalid")
	}

	if _, err := NewProviderProtocolProcessRequest(
		"/usr/bin/provider", []string{"/usr/bin/provider", "protocol packet"}, nil, "/work",
		binding, 5*time.Second,
	); err == nil {
		t.Fatal("NewProviderProtocolProcessRequest() accepted packet in argv")
	}
	stdinBinding, err := NewStdinProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProviderProtocolProcessRequest(
		"/usr/bin/provider", []string{"/usr/bin/provider"}, nil, "/work",
		stdinBinding, 5*time.Second,
	); err == nil {
		t.Fatal("NewProviderProtocolProcessRequest() accepted a non-protocol binding")
	}
}

func TestProtocolProviderPacketTransportReceiptAdmitsIncrementalStdin(t *testing.T) {
	packet := schedulingTestPacket(t, []byte("protocol packet"))
	binding, err := NewProtocolProviderPacketBinding(packet)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewProviderPacketTransportReceipt(
		binding.Channel(), binding.PacketIdentity(), "", "", ProviderPacketIdentity{}, ProviderPacketIdentity{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Valid() {
		t.Fatal("protocol transport receipt is invalid")
	}
	if receipt.PromptFileReference() != "" || receipt.SnapshotCWD() != "" {
		t.Fatal("protocol transport receipt carries prompt-file evidence")
	}
	if receipt.PreStartIdentity().Valid() || receipt.PostTerminationIdentity().Valid() {
		t.Fatal("protocol transport receipt carries file identities")
	}

	frameReceipt, err := NewStdinWriteReceipt(48, 48, schedulingStdinWriteSHA256([]byte("frame-bytes-accepted-by-the-child-pipe!!")), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateProviderPacketTransportReceipt(ProcessTerminationExited, frameReceipt, receipt); err != nil {
		t.Fatalf("protocol transport with incremental stdin receipt: %v", err)
	}
	zeroReceipt, err := NewStdinWriteReceipt(0, 0, schedulingStdinWriteSHA256(nil), true)
	if err != nil {
		t.Fatal(err)
	}
	// Protocol transport evidence follows the stdin channel's posture: the
	// incremental stdin write receipt itself is the delivery evidence, so the
	// defensive validation mirrors stdin rather than the argv and prompt-file
	// zero-byte invariant. The conversation runner never attaches a transport
	// receipt to a start failure.
	if err := validateProviderPacketTransportReceipt(ProcessTerminationStartFailed, zeroReceipt, receipt); err != nil {
		t.Fatalf("protocol transport with zero-byte stdin receipt after start failure: %v", err)
	}
}

func TestConversationTeardownSignalRequestReceiptsAreClosedFacts(t *testing.T) {
	for _, reason := range []ProcessGroupSignalRequestReason{
		ProcessGroupSignalRequestConversationTeardown,
		ProcessGroupSignalRequestConversationTeardownEscalation,
	} {
		signal, err := NewProcessSignal(15, "SIGTERM")
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := NewAcceptedProcessGroupSignalRequestReceipt(reason, signal)
		if err != nil {
			t.Fatalf("NewAcceptedProcessGroupSignalRequestReceipt(%q): %v", reason, err)
		}
		if !receipt.Valid() {
			t.Fatalf("receipt for %q is invalid", reason)
		}
		if _, ok := receipt.PacketIdentity(); ok {
			t.Fatalf("receipt for %q carries a packet identity", reason)
		}
		if _, ok := receipt.FrameSHA256(); ok {
			t.Fatalf("receipt for %q carries a frame digest", reason)
		}
	}
}

func TestProviderSessionExchangeAndDriverAreContractInterfaces(t *testing.T) {
	var exchange ProviderSessionExchange = &protocolTestExchange{}
	var driver ProviderSessionDriver = protocolTestDriver{}
	_ = exchange
	_ = driver
	if !errors.Is(ErrProviderSessionExchangeClosed, ErrProviderSessionExchangeClosed) {
		t.Fatal("exchange closure sentinel is not comparable")
	}
}

type protocolTestExchange struct{}

func (exchange *protocolTestExchange) ReceiveLine(ctx context.Context) ([]byte, error) {
	return nil, io.EOF
}

func (exchange *protocolTestExchange) SendLine(ctx context.Context, line []byte) error {
	if len(line) == 0 {
		return errors.New("empty line")
	}
	return nil
}

type protocolTestDriver struct{}

func (driver protocolTestDriver) Drive(ctx context.Context, exchange ProviderSessionExchange) error {
	if _, err := exchange.ReceiveLine(ctx); !errors.Is(err, io.EOF) {
		return errors.New("expected stream end")
	}
	return nil
}
