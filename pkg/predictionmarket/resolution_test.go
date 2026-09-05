package predictionmarket

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func evidenceEntry(index byte) EvidenceEntryV1 {
	digest := testHash(index + 1)
	return EvidenceEntryV1{
		SourceKind: SourceHTTPS, CanonicalSourceID: fmt.Sprintf("https://source-%02d.example/results", index),
		ContentDigest: digest, ArchiveLocator: "tos-cas-sha256:" + hex.EncodeToString(digest[:]),
		PublicationTimeSeconds: 2_000 + uint64(index), EventTimeSeconds: 1_900 + uint64(index),
		ParserProfileVersion: "election-result/v1",
	}
}

func TestEvidenceManifestCanonicalizesOrderAndRoundTripsMaximum(t *testing.T) {
	entries := make([]EvidenceEntryV1, MaxEvidenceEntries)
	for index := range entries {
		entries[index] = evidenceEntry(byte(MaxEvidenceEntries - index - 1))
	}
	manifest := PredictionEvidenceManifestV1{MarketID: testHash(0x11), RulesHash: testHash(0x22),
		RoundContextHash: testHash(0x33), Outcome: OutcomeYes, Entries: entries}
	root, err := BuildPredictionEvidenceManifestCell(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if root.Depth() > MaxCanonicalObjectDepth {
		t.Fatalf("maximum manifest depth %d exceeds cap", root.Depth())
	}
	decoded, err := DecodePredictionEvidenceManifestV1(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Entries) != MaxEvidenceEntries || decoded.Entries[0].CanonicalSourceID != "https://source-00.example/results" {
		t.Fatal("evidence entries were not decoded in canonical order")
	}
	rebuilt, err := BuildPredictionEvidenceManifestCell(*decoded)
	if err != nil || cellHash(rebuilt) != cellHash(root) {
		t.Fatal("evidence manifest did not round trip canonically")
	}
}

func TestEvidenceManifestRejectsAliasesAndDuplicates(t *testing.T) {
	base := evidenceEntry(1)
	tests := []struct {
		name   string
		mutate func(*EvidenceEntryV1)
	}{
		{"http source", func(value *EvidenceEntryV1) { value.CanonicalSourceID = "http://source-01.example/results" }},
		{"uppercase host", func(value *EvidenceEntryV1) { value.CanonicalSourceID = "https://SOURCE-01.example/results" }},
		{"query alias", func(value *EvidenceEntryV1) { value.CanonicalSourceID += "?mirror=1" }},
		{"path alias", func(value *EvidenceEntryV1) { value.CanonicalSourceID = "https://source-01.example/a/../results" }},
		{"mutable locator", func(value *EvidenceEntryV1) { value.ArchiveLocator = "https://archive.example/latest" }},
		{"digest mismatch", func(value *EvidenceEntryV1) { value.ContentDigest = testHash(0xee) }},
		{"fetch time masquerading as event time", func(value *EvidenceEntryV1) { value.EventTimeSeconds = value.PublicationTimeSeconds + 1 }},
		{"unversioned parser", func(value *EvidenceEntryV1) { value.ParserProfileVersion = "election-result" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := base
			test.mutate(&entry)
			_, err := BuildPredictionEvidenceManifestCell(PredictionEvidenceManifestV1{MarketID: testHash(1), RulesHash: testHash(2),
				RoundContextHash: testHash(3), Outcome: OutcomeYes, Entries: []EvidenceEntryV1{entry}})
			if err == nil {
				t.Fatal("non-canonical evidence was accepted")
			}
		})
	}
	if _, err := BuildPredictionEvidenceManifestCell(PredictionEvidenceManifestV1{MarketID: testHash(1), RulesHash: testHash(2),
		RoundContextHash: testHash(3), Outcome: OutcomeYes, Entries: []EvidenceEntryV1{base, base}}); err == nil {
		t.Fatal("duplicate evidence tuple was accepted")
	}
}

func TestEvidenceSourceIdentityProfiles(t *testing.T) {
	key := testPrivateKey().Public().(ed25519.PublicKey)
	digest := testHash(9)
	tosDigest := testHash(10)
	entries := []EvidenceEntryV1{
		{SourceKind: SourceSignedDocument, CanonicalSourceID: "ed25519:" + hex.EncodeToString(key), ContentDigest: digest,
			ArchiveLocator: "tos-cas-sha256:" + hex.EncodeToString(digest[:]), PublicationTimeSeconds: 20, EventTimeSeconds: 10,
			ParserProfileVersion: "signed-result/v2"},
		{SourceKind: SourceTOSFinalized, CanonicalSourceID: "tos-account:" + testAddress(0x66), ContentDigest: tosDigest,
			ArchiveLocator: "tos-cas-sha256:" + hex.EncodeToString(tosDigest[:]), PublicationTimeSeconds: 20, EventTimeSeconds: 10,
			ParserProfileVersion: "tos-event/v1"},
	}
	for _, entry := range entries {
		if err := validateEvidenceEntry(entry); err != nil {
			t.Fatalf("valid source profile rejected: %v", err)
		}
	}
}

func TestChallengeEvidenceUsesIndependentNonRecursiveDomain(t *testing.T) {
	entry := evidenceEntry(1)
	normal, err := BuildPredictionEvidenceManifestCell(PredictionEvidenceManifestV1{MarketID: testHash(1), RulesHash: testHash(2),
		RoundContextHash: testHash(3), Outcome: OutcomeNo, Entries: []EvidenceEntryV1{entry}})
	if err != nil {
		t.Fatal(err)
	}
	challenge := PredictionChallengeEvidenceManifestV1{MarketID: testHash(1), RulesHash: testHash(2),
		ProposedStatementHash: testHash(3), CounterOutcome: OutcomeNo, Entries: []EvidenceEntryV1{entry}}
	challengeCell, err := BuildPredictionChallengeEvidenceManifestCell(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if cellHash(normal) == cellHash(challengeCell) {
		t.Fatal("normal and challenge evidence domains collided")
	}
	decoded, err := DecodePredictionChallengeEvidenceManifestV1(challengeCell)
	if err != nil || decoded.ProposedStatementHash != challenge.ProposedStatementHash {
		t.Fatal("challenge evidence lost proposal binding")
	}
	changed := challenge
	changed.ProposedStatementHash = testHash(4)
	changedCell, err := BuildPredictionChallengeEvidenceManifestCell(changed)
	if err != nil || cellHash(changedCell) == cellHash(challengeCell) {
		t.Fatal("challenge evidence did not bind the proposed statement")
	}
}

func TestResolutionContextsAndStatementRoundTrip(t *testing.T) {
	normal := PredictionNormalContextV1{MarketID: testHash(1), RulesHash: testHash(2), NormalRoundNonce: testHash(3),
		NormalRoundOpenedAt: 100, ResolveNotBefore: 110, OracleVoteDeadline: 200}
	normalCell, err := BuildPredictionNormalContextCell(normal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePredictionNormalContextV1(normalCell); err != nil {
		t.Fatal(err)
	}
	normalHash := cellHash(normalCell)

	review := PredictionReviewBaseContextV1{MarketID: testHash(1), RulesHash: testHash(2), Reason: ReviewChallenge,
		ReviewStartedAt: 210, ReviewVoteNotBefore: 220, AppealDeadline: 300,
		Challenge: &PredictionChallengeReviewV1{ProposedStatementHash: testHash(4), ProposedOutcome: OutcomeYes,
			ProposedEvidenceRoot: testHash(5), ChallengerAddress: testAddress(0x77), CounterOutcome: OutcomeNo,
			CounterEvidenceRoot: testHash(6)}}
	reviewCell, err := BuildPredictionReviewBaseContextCell(review)
	if err != nil {
		t.Fatal(err)
	}
	decodedReview, err := DecodePredictionReviewBaseContextV1(reviewCell)
	if err != nil || decodedReview.Challenge == nil || decodedReview.Challenge.ChallengerAddress != review.Challenge.ChallengerAddress {
		t.Fatal("challenge review context did not round trip")
	}
	vote := PredictionReviewVoteContextV1{ReviewBaseContextHash: cellHash(reviewCell), ReviewRoundNonce: testHash(7), ReviewRoundOpenedAt: 220}
	voteCell, err := BuildPredictionReviewVoteContextCell(vote)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePredictionReviewVoteContextV1(voteCell); err != nil {
		t.Fatal(err)
	}
	if normalHash == cellHash(reviewCell) || normalHash == cellHash(voteCell) || cellHash(reviewCell) == cellHash(voteCell) {
		t.Fatal("round context domains are not separated")
	}

	statement := PredictionResolutionStatementV1{GlobalID: 42, MarketAddress: testAddress(0x11), MarketID: testHash(1),
		RulesHash: testHash(2), RoundPolicyHash: testHash(8), RoundContextHash: cellHash(voteCell), Round: RoundAppeal,
		Outcome: OutcomeInvalid, EvidenceRoot: testHash(9), StatementCreatedAt: 230, StatementExpiry: 290}
	statementCell, err := BuildPredictionResolutionStatementCell(statement)
	if err != nil {
		t.Fatal(err)
	}
	decodedStatement, err := DecodePredictionResolutionStatementV1(statementCell)
	if err != nil || decodedStatement.RoundContextHash != statement.RoundContextHash || decodedStatement.Outcome != OutcomeInvalid {
		t.Fatal("resolution statement did not round trip")
	}
	changed := statement
	changed.Round = RoundNormal
	changedCell, err := BuildPredictionResolutionStatementCell(changed)
	if err != nil || cellHash(changedCell) == cellHash(statementCell) {
		t.Fatal("resolution statement did not bind its round")
	}
}

func TestReviewContextRejectsPartialOrContradictoryProvenance(t *testing.T) {
	normalWithChallenge := PredictionReviewBaseContextV1{MarketID: testHash(1), RulesHash: testHash(2), Reason: ReviewNormalTimeout,
		ReviewStartedAt: 100, ReviewVoteNotBefore: 110, AppealDeadline: 200, Challenge: &PredictionChallengeReviewV1{}}
	if _, err := BuildPredictionReviewBaseContextCell(normalWithChallenge); err == nil {
		t.Fatal("normal timeout accepted challenge provenance")
	}
	challengeWithoutProvenance := normalWithChallenge
	challengeWithoutProvenance.Reason = ReviewChallenge
	challengeWithoutProvenance.Challenge = nil
	if _, err := BuildPredictionReviewBaseContextCell(challengeWithoutProvenance); err == nil {
		t.Fatal("challenge review accepted missing provenance")
	}
	bad := PredictionReviewBaseContextV1{MarketID: testHash(1), RulesHash: testHash(2), Reason: ReviewChallenge,
		ReviewStartedAt: 100, ReviewVoteNotBefore: 110, AppealDeadline: 200,
		Challenge: &PredictionChallengeReviewV1{ProposedStatementHash: testHash(3), ProposedOutcome: OutcomeYes,
			ProposedEvidenceRoot: testHash(4), ChallengerAddress: testAddress(5), CounterOutcome: OutcomeYes,
			CounterEvidenceRoot: testHash(6)}}
	if _, err := BuildPredictionReviewBaseContextCell(bad); err == nil {
		t.Fatal("challenge accepted a counter-outcome equal to the proposal")
	}
}

func TestResolutionRejectsTrailingData(t *testing.T) {
	value := PredictionReviewVoteContextV1{ReviewBaseContextHash: testHash(1), ReviewRoundNonce: testHash(2), ReviewRoundOpenedAt: 3}
	root, err := BuildPredictionReviewVoteContextCell(value)
	if err != nil {
		t.Fatal(err)
	}
	malformed := root.ToBuilder().MustStoreRef(cell.BeginCell().EndCell()).EndCell()
	if _, err := DecodePredictionReviewVoteContextV1(malformed); err == nil {
		t.Fatal("context with trailing reference was accepted")
	}
}
