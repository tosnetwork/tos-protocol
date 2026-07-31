package edge

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestProfileInvocationRegistryUsesExactCanonicalSelector(t *testing.T) {
	var calls atomic.Int32
	mapper := ProfileInvocationMapperFunc(func(
		context.Context,
		ProfileInvocationInput,
	) (ProfileInvocationOutput, error) {
		calls.Add(1)
		return ProfileInvocationOutput{Model: "test-model"}, nil
	})
	extensions := []string{"urn:tos:extension:z", "urn:tos:extension:a"}
	registry, err := NewProfileInvocationRegistry([]ProfileInvocationRegistration{{
		ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
		ProfileExtensions: extensions, Operation: "invoke", Mapper: mapper,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if registry.Len() != 1 {
		t.Fatalf("registry length = %d", registry.Len())
	}
	extensions[0] = "urn:tos:extension:changed"
	material := authorization.ReceiptInvocationMaterial{
		ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
		ProfileExtensions: []string{
			"urn:tos:extension:a", "urn:tos:extension:z",
		},
		Operation: "invoke",
	}
	const readers = 32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, readers)
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			resolved, err := registry.resolve(material)
			if err != nil {
				errorsSeen <- err
				return
			}
			if _, err := resolved.MapInvocation(
				context.Background(), ProfileInvocationInput{},
			); err != nil {
				errorsSeen <- err
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	if calls.Load() != readers || registry.Len() != 1 {
		t.Fatalf("calls = %d, length = %d", calls.Load(), registry.Len())
	}
	material.ProfileExtensions = []string{"urn:tos:extension:a"}
	if _, err := registry.resolve(material); err == nil {
		t.Fatal("partial extension selector used a registered mapper")
	}
	material.ProfileExtensions = []string{
		"urn:tos:extension:a", "urn:tos:extension:z",
	}
	material.ProfileVersion = "0.2.0"
	if _, err := registry.resolve(material); err == nil {
		t.Fatal("different profile version used a registered mapper")
	}
	material.ProfileVersion = "0.1.0"
	material.Operation = "embed"
	if _, err := registry.resolve(material); err == nil {
		t.Fatal("different operation used a registered mapper")
	}
}

func TestProfileInvocationRegistryRejectsInvalidOrAmbiguousEntries(t *testing.T) {
	validMapper := ProfileInvocationMapperFunc(func(
		context.Context,
		ProfileInvocationInput,
	) (ProfileInvocationOutput, error) {
		return ProfileInvocationOutput{}, nil
	})
	valid := ProfileInvocationRegistration{
		ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
		Operation: "invoke", Mapper: validMapper,
	}
	if _, err := NewProfileInvocationRegistry(nil); err == nil {
		t.Fatal("empty profile invocation registry accepted")
	}
	duplicate := valid
	duplicate.ProfileExtensions = []string{
		"urn:tos:extension:z", "urn:tos:extension:a",
	}
	first := valid
	first.ProfileExtensions = []string{
		"urn:tos:extension:a", "urn:tos:extension:z",
	}
	if _, err := NewProfileInvocationRegistry(
		[]ProfileInvocationRegistration{first, duplicate},
	); err == nil {
		t.Fatal("duplicate canonical selector accepted")
	}
	var nilMapper ProfileInvocationMapperFunc
	typedNil := valid
	typedNil.Mapper = nilMapper
	if _, err := NewProfileInvocationRegistry(
		[]ProfileInvocationRegistration{typedNil},
	); err == nil {
		t.Fatal("typed nil mapper accepted")
	}
	invalid := valid
	invalid.ProfileVersion = "01.0.0"
	if _, err := NewProfileInvocationRegistry(
		[]ProfileInvocationRegistration{invalid},
	); err == nil {
		t.Fatal("invalid selector accepted")
	}
	overLimit := make(
		[]ProfileInvocationRegistration,
		MaxProfileInvocationRegistrations+1,
	)
	for index := range overLimit {
		overLimit[index] = valid
		overLimit[index].Operation = fmt.Sprintf("invoke-%03d", index)
	}
	if _, err := NewProfileInvocationRegistry(overLimit); err == nil {
		t.Fatal("oversized profile invocation registry accepted")
	}
}

func TestCoreClaimsOnlyRegisteredPaidProfileInvocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	intent := []byte("registered-intent")
	digest, err := protocol.RequestIntentDigest(
		"tos.ai.inference", "0.1.0", nil, "invoke", intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	scope, authorized := fixture.authorizePaymentWithIntentDigest(
		t, "registered-mapping-0001", digest,
	)
	request := applyAuthorizedPaymentForCompletion(
		t, core, scope, authorized, now,
	)
	worker := mappingWorkerClient(t, now)
	mapperCalls := 0
	mapper := ProfileInvocationMapperFunc(func(
		_ context.Context,
		input ProfileInvocationInput,
	) (ProfileInvocationOutput, error) {
		mapperCalls++
		if input.ProfileVersion != "0.1.0" ||
			input.Operation != "invoke" || string(input.Intent) != string(intent) {
			t.Fatalf("unexpected registered mapper input: %#v", input)
		}
		return ProfileInvocationOutput{
			Model: "registered-model", Payload: []byte("worker-payload"),
		}, nil
	})
	wrongRegistry, err := NewProfileInvocationRegistry(
		[]ProfileInvocationRegistration{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.2.0",
			Operation: "invoke", Mapper: mapper,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.MapAndClaimRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		intent, wrongRegistry, worker,
	); err == nil {
		t.Fatal("unregistered exact selector was claimed")
	}
	if mapperCalls != 0 {
		t.Fatal("nonmatching registered mapper was called")
	}
	if _, err := core.Execution(scope); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("failed registry lookup persisted execution: %v", err)
	}
	registry, err := NewProfileInvocationRegistry(
		[]ProfileInvocationRegistration{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
			Operation: "invoke", Mapper: mapper,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := core.MapAndClaimRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		intent, registry, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	if mapperCalls != 1 || claimed.Disposition != journal.ExecutionClaimed ||
		claimed.Request.Model != "registered-model" ||
		string(claimed.Request.Payload) != "worker-payload" {
		t.Fatalf("unexpected registered claim: %#v", claimed)
	}
}
