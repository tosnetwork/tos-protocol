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
	if !registry.Supports(
		"tos.ai.inference",
		"0.1.0",
		[]string{"urn:tos:extension:a", "urn:tos:extension:z"},
		"invoke",
	) {
		t.Fatal("exact canonical selector was not reported as supported")
	}
	if registry.Supports(
		"tos.ai.inference", "0.1.0",
		[]string{"urn:tos:extension:a"}, "invoke",
	) {
		t.Fatal("partial extension selector was reported as supported")
	}
	if registry.Supports("tos.ai.inference", "01.0.0", nil, "invoke") {
		t.Fatal("invalid selector was reported as supported")
	}
	var nilRegistry *ProfileInvocationRegistry
	if nilRegistry.Supports("tos.ai.inference", "0.1.0", nil, "invoke") {
		t.Fatal("nil registry reported a selector as supported")
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
			if !registry.Supports(
				"tos.ai.inference",
				"0.1.0",
				[]string{"urn:tos:extension:z", "urn:tos:extension:a"},
				"invoke",
			) {
				errorsSeen <- errors.New("concurrent exact selector lookup failed")
				return
			}
			if err := registry.ValidateRequirements(
				[]ProfileInvocationRequirement{{
					ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
					ProfileExtensions: []string{
						"urn:tos:extension:a", "urn:tos:extension:z",
					},
					Operation: "invoke",
				}},
			); err != nil {
				errorsSeen <- err
				return
			}
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

func TestProfileInvocationRegistryValidatesBoundedExactRequirements(t *testing.T) {
	mapper := ProfileInvocationMapperFunc(func(
		context.Context,
		ProfileInvocationInput,
	) (ProfileInvocationOutput, error) {
		return ProfileInvocationOutput{Model: "model"}, nil
	})
	registry, err := NewProfileInvocationRegistry([]ProfileInvocationRegistration{
		{
			ProfileID: "tos.ai.text-generation", ProfileVersion: "0.1.0",
			Operation: "generate", Mapper: mapper,
		},
		{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.2.0",
			ProfileExtensions: []string{"urn:tos:extension:a"},
			Operation:         "embed", Mapper: mapper,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	requirements := []ProfileInvocationRequirement{
		{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.2.0",
			ProfileExtensions: []string{"urn:tos:extension:a"},
			Operation:         "embed",
		},
		{
			ProfileID: "tos.ai.text-generation", ProfileVersion: "0.1.0",
			Operation: "generate",
		},
	}
	if err := registry.ValidateRequirements(requirements); err != nil {
		t.Fatal(err)
	}
	requirements[0].ProfileExtensions[0] = "urn:tos:extension:b"
	if err := registry.ValidateRequirements(requirements); err == nil {
		t.Fatal("missing exact mapper requirement was accepted")
	}
	if err := registry.ValidateRequirements(nil); err == nil {
		t.Fatal("empty requirements were accepted")
	}
	duplicate := []ProfileInvocationRequirement{
		requirements[1], requirements[1],
	}
	if err := registry.ValidateRequirements(duplicate); err == nil {
		t.Fatal("duplicate requirements were accepted")
	}
	overLimit := make(
		[]ProfileInvocationRequirement,
		MaxProfileInvocationRequirements+1,
	)
	if err := registry.ValidateRequirements(overLimit); err == nil {
		t.Fatal("oversized requirements were accepted")
	}
	var nilRegistry *ProfileInvocationRegistry
	if err := nilRegistry.ValidateRequirements(requirements); err == nil {
		t.Fatal("nil registry accepted requirements")
	}
}

func TestProfileInvocationPlanEnablesOnlyDeclaredSelectors(t *testing.T) {
	mapper := ProfileInvocationMapperFunc(func(
		context.Context,
		ProfileInvocationInput,
	) (ProfileInvocationOutput, error) {
		return ProfileInvocationOutput{Model: "model"}, nil
	})
	registrations := []ProfileInvocationRegistration{
		{
			ProfileID: "tos.ai.text-generation", ProfileVersion: "0.1.0",
			Operation: "generate", Mapper: mapper,
		},
		{
			ProfileID: "tos.ai.embedding", ProfileVersion: "0.1.0",
			Operation: "embed", Mapper: mapper,
		},
	}
	plan, err := NewProfileInvocationPlan(
		registrations,
		[]ProfileInvocationRequirement{{
			ProfileID: "tos.ai.text-generation", ProfileVersion: "0.1.0",
			Operation: "generate",
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Len() != 1 || !plan.Supports(
		"tos.ai.text-generation", "0.1.0", nil, "generate",
	) {
		t.Fatalf("required selector not enabled: length = %d", plan.Len())
	}
	if plan.Supports("tos.ai.embedding", "0.1.0", nil, "embed") {
		t.Fatal("installed but undeclared selector was enabled")
	}
	if _, err := plan.resolve(authorization.ReceiptInvocationMaterial{
		ProfileID: "tos.ai.embedding", ProfileVersion: "0.1.0",
		Operation: "embed",
	}); err == nil {
		t.Fatal("installed but undeclared selector resolved through plan")
	}
	if _, err := NewProfileInvocationPlan(
		registrations,
		[]ProfileInvocationRequirement{{
			ProfileID: "tos.ai.unknown", ProfileVersion: "0.1.0",
			Operation: "invoke",
		}},
	); err == nil {
		t.Fatal("plan with missing mapper was accepted")
	}
	var nilPlan *ProfileInvocationPlan
	if nilPlan.Len() != 0 || nilPlan.Supports(
		"tos.ai.text-generation", "0.1.0", nil, "generate",
	) {
		t.Fatal("nil plan reported an enabled selector")
	}

	const readers = 64
	var wait sync.WaitGroup
	failures := make(chan error, readers)
	for range readers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if !plan.Supports(
				"tos.ai.text-generation", "0.1.0", nil, "generate",
			) {
				failures <- errors.New("concurrent plan lookup failed")
				return
			}
			if _, err := plan.resolve(authorization.ReceiptInvocationMaterial{
				ProfileID: "tos.ai.text-generation", ProfileVersion: "0.1.0",
				Operation: "generate",
			}); err != nil {
				failures <- err
			}
		}()
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if plan.Len() != 1 {
		t.Fatalf("concurrent lookups changed plan length: %d", plan.Len())
	}
}

func TestCoreClaimsOnlyPlannedPaidProfileInvocation(t *testing.T) {
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
	registrations := []ProfileInvocationRegistration{
		{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
			Operation: "invoke", Mapper: mapper,
		},
		{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.2.0",
			Operation: "invoke", Mapper: mapper,
		},
	}
	wrongPlan, err := NewProfileInvocationPlan(
		registrations,
		[]ProfileInvocationRequirement{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.2.0",
			Operation: "invoke",
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.MapAndClaimRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		intent, wrongPlan, worker,
	); err == nil {
		t.Fatal("selector outside the deployment plan was claimed")
	}
	if mapperCalls != 0 {
		t.Fatal("mapper outside the deployment plan was called")
	}
	if _, err := core.Execution(scope); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("failed registry lookup persisted execution: %v", err)
	}
	plan, err := NewProfileInvocationPlan(
		registrations,
		[]ProfileInvocationRequirement{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
			Operation: "invoke",
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Supports("tos.ai.inference", "0.2.0", nil, "invoke") {
		t.Fatal("unused installed mapper was enabled")
	}
	claimed, err := core.MapAndClaimRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		intent, plan, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	if mapperCalls != 1 || claimed.Disposition != journal.ExecutionClaimed ||
		claimed.Request.Model != "registered-model" ||
		string(claimed.Request.Payload) != "worker-payload" {
		t.Fatalf("unexpected registered claim: %#v", claimed)
	}
	recovered, err := core.MapAndClaimRecoveredPaidExecution(
		context.Background(), scope, intent, plan, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	if mapperCalls != 2 || recovered.Disposition != journal.ExecutionReplay ||
		recovered.Request.TaskId != claimed.Request.TaskId {
		t.Fatalf("unexpected planned recovery: %#v", recovered)
	}
}
