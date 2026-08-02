package nilcheck

import "testing"

type sample struct{}

func TestIsNilRejectsTypedNil(t *testing.T) {
	var pointer *sample
	var function func()
	for name, value := range map[string]any{"nil": nil, "pointer": pointer, "function": function} {
		if !IsNil(value) {
			t.Fatalf("%s typed nil was accepted", name)
		}
	}
	if IsNil(&sample{}) || IsNil(1) {
		t.Fatal("concrete value was rejected")
	}
}
