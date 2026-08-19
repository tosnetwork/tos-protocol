package economic

// stringSet counts distinct identifiers. A unique-participant metric is a set
// size, and keeping the set here means every such metric dedups the same way.
type stringSet struct {
	members map[string]struct{}
}

func newStringSet() *stringSet {
	return &stringSet{members: map[string]struct{}{}}
}

func (s *stringSet) add(value string) {
	s.members[value] = struct{}{}
}

func (s *stringSet) size() uint64 {
	return uint64(len(s.members))
}
