package sops

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func creationFixture(t *testing.T, extension string) (string, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOPS_AGE_KEY", identity.String())
	root := t.TempDir()
	target := filepath.Join(root, "environment", "new.enc."+extension)
	config := filepath.Join(root, ".sops.yml")
	rules := fmt.Sprintf("creation_rules:\n  - path_regex: '^environment/new\\.enc\\.%s$'\n    age: %s\n    encrypted_suffix: _enc\n    mac_only_encrypted: true\n", extension, identity.Recipient())
	if err := os.WriteFile(config, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	return target, config
}

func TestResourceSopsEntry_createFromConfig(t *testing.T) {
	for _, extension := range []string{"yaml", "json"} {
		t.Run(extension, func(t *testing.T) {
			target, config := creationFixture(t, extension)
			initial := fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  config_file = %q
  entries = {
    "database.password_enc" = "initial-secret"
    label = "public"
  }
}`, target, config)
			updated := fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    "database.password_enc" = "updated-secret"
    label = "public"
  }
}`, target)
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				CheckDestroy: func(_ *terraform.State) error {
					tree, _, _, _, err := loadAndDecryptFile(target)
					if err != nil {
						return err
					}
					if len(readAllEntries(tree)) != 0 {
						return fmt.Errorf("managed keys remain after destroy")
					}
					return nil
				},
				Steps: []resource.TestStep{
					{
						Config:             initial,
						PlanOnly:           true,
						ExpectNonEmptyPlan: true,
					},
					{
						Config: initial,
						PreConfig: func() {
							if _, err := os.Stat(target); !os.IsNotExist(err) {
								t.Fatalf("planning created the target file: %v", err)
							}
						},
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("sops_entry.test", "data.database.password_enc", "initial-secret"),
							func(_ *terraform.State) error {
								content, err := os.ReadFile(target)
								if err != nil {
									return err
								}
								if bytes.Contains(content, []byte("initial-secret")) {
									return fmt.Errorf("plaintext secret found in encrypted file")
								}
								info, err := os.Stat(target)
								if err != nil {
									return err
								}
								if info.Mode().Perm() != 0600 {
									return fmt.Errorf("file permissions are %o", info.Mode().Perm())
								}
								tree, _, _, _, err := loadAndDecryptFile(target)
								if err != nil {
									return err
								}
								if tree.Metadata.EncryptedSuffix != "_enc" || !tree.Metadata.MACOnlyEncrypted {
									return fmt.Errorf("creation rule options were not preserved")
								}
								return nil
							},
						),
					},
					{
						Config: updated,
						PreConfig: func() {
							if err := os.Remove(config); err != nil {
								t.Fatal(err)
							}
						},
						Check: resource.TestCheckResourceAttr("sops_entry.test", "data.database.password_enc", "updated-secret"),
					},
				},
			})
		})
	}
}

func TestResourceSopsEntry_recreatesDeletedFile(t *testing.T) {
	target, config := creationFixture(t, "yaml")
	configuration := fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  config_file = %q
  entries = { password_enc = "secret" }
}`, target, config)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: configuration},
			{
				Config: configuration,
				PreConfig: func() {
					if err := os.Remove(target); err != nil {
						t.Fatal(err)
					}
				},
				Check: resource.TestCheckResourceAttr("sops_entry.test", "data.password_enc", "secret"),
			},
		},
	})
}

func TestLoadOrCreateFile_explicitConfigAndFailureHandling(t *testing.T) {
	for _, test := range []struct{ name, contents, configPath, existing, expected string }{
		{name: "no implicit discovery", expected: "set config_file"},
		{name: "missing explicit config", configPath: "missing.yml", expected: "loading creation rules"},
		{name: "unmatched rule", contents: "creation_rules:\n  - path_regex: '^elsewhere/'\n", configPath: ".sops.yml", expected: "no matching creation rules"},
		{name: "empty config", contents: "{}\n", configPath: ".sops.yml", expected: "no encryption recipients"},
		{name: "no recipients", contents: "creation_rules:\n  - path_regex: ''\n", configPath: ".sops.yml", expected: "empty key group"},
		{name: "invalid config", contents: "creation_rules: [\n", configPath: ".sops.yml", expected: "loading creation rules"},
		{name: "invalid existing file", existing: "not a SOPS file\n", configPath: ".sops.yml", expected: "loading encrypted file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, config := creationFixture(t, "yaml")
			if test.configPath == "" {
				config = ""
			} else if test.configPath == "missing.yml" {
				config = filepath.Join(filepath.Dir(config), test.configPath)
			} else if test.contents != "" {
				if err := os.WriteFile(config, []byte(test.contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if test.existing != "" {
				if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, []byte(test.existing), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, _, _, _, err := loadOrCreateFile(target, config)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("error = %v; expected %q", err, test.expected)
			}
			contents, readErr := os.ReadFile(target)
			if test.existing == "" && !os.IsNotExist(readErr) {
				t.Fatalf("failed creation wrote a file: %v", readErr)
			}
			if test.existing != "" && string(contents) != test.existing {
				t.Fatal("invalid existing file was changed")
			}
		})
	}
}

func TestLoadOrCreateFile_firstRuleAndFreshDataKey(t *testing.T) {
	target, config := creationFixture(t, "yaml")
	contents, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	contents = append(contents, []byte(fmt.Sprintf("  - age: %s\n", other.Recipient()))...)
	if err := os.WriteFile(config, contents, 0600); err != nil {
		t.Fatal(err)
	}
	tree, firstKey, cipher, store, err := loadOrCreateFile(target, config)
	if err != nil {
		t.Fatal(err)
	}
	_, secondKey, _, _, err := loadOrCreateFile(target, config)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstKey, secondKey) {
		t.Fatal("new files reused a data key")
	}
	setEntries(tree, map[string]string{"secret_enc": "example"})
	if err := encryptAndWriteFile(tree, firstKey, cipher, store, target); err != nil {
		t.Fatal(err)
	}
	// Only the first rule's identity is available for decryption.
	if _, _, _, _, err := loadAndDecryptFile(target); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := loadOrCreateFile(target, "missing-config.yml"); err != nil {
		t.Fatal("existing files should not load creation rules:", err)
	}
}

func TestLoadOrCreateFile_shamirGroupsAndDefaultSuffix(t *testing.T) {
	target, config := creationFixture(t, "yaml")
	first, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	second, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOPS_AGE_KEY", first.String()+"\n"+second.String())
	rules := fmt.Sprintf("creation_rules:\n  - shamir_threshold: 2\n    key_groups:\n      - age: [%s]\n      - age: [%s]\n", first.Recipient(), second.Recipient())
	if err := os.WriteFile(config, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	tree, key, cipher, store, err := loadOrCreateFile(target, config)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Metadata.ShamirThreshold != 2 || len(tree.Metadata.KeyGroups) != 2 {
		t.Fatal("Shamir configuration was not preserved")
	}
	if tree.Metadata.UnencryptedSuffix != "_unencrypted" {
		t.Fatal("default unencrypted suffix was not set")
	}
	setEntries(tree, map[string]string{"secret": "example", "label_unencrypted": "public"})
	if err := encryptAndWriteFile(tree, key, cipher, store, target); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := loadAndDecryptFile(target); err != nil {
		t.Fatal(err)
	}
}
