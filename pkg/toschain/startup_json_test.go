package toschain

import "testing"

func TestDecodeStartupConfigJSONStrict(t *testing.T) {
	document := []byte(`{
        "version":"1",
        "network":"tos-local",
        "endpoints":["http://127.0.0.1:8011/","http://127.0.0.1:8012/","http://127.0.0.1:8013/"],
        "quorum":2,
        "allowedServiceCodeHashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    }`)
	config, err := DecodeStartupConfigJSON(document)
	if err != nil {
		t.Fatal(err)
	}
	if config.Network != "tos-local" || config.Quorum != 2 {
		t.Fatalf("unexpected config: %+v", config)
	}
	for name, malformed := range map[string][]byte{
		"duplicate": []byte(`{"version":"1","version":"1"}`),
		"unknown":   []byte(`{"version":"1","unexpected":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeStartupConfigJSON(malformed); err == nil {
				t.Fatal("expected strict decode failure")
			}
		})
	}
}
