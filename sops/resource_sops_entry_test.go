package sops

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func copyFixture(t *testing.T, fixtureName string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(wd, "test-fixtures", fixtureName)
	content, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	ext := filepath.Ext(fixtureName)
	tmp, err := os.CreateTemp(t.TempDir(), "sops-entry-*"+ext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(content); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	return tmp.Name()
}

func TestResourceSopsEntry_basic(t *testing.T) {
	tmpFile := copyFixture(t, "basic.yaml")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    new_key = "new_value"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "id", tmpFile),
					resource.TestCheckResourceAttr("sops_entry.test", "data.new_key", "new_value"),
					resource.TestCheckResourceAttr("sops_entry.test", "data.hello", "world"),
				),
			},
		},
	})
}

func TestResourceSopsEntry_update(t *testing.T) {
	tmpFile := copyFixture(t, "basic.yaml")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    my_key = "initial_value"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.my_key", "initial_value"),
				),
			},
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    my_key = "updated_value"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.my_key", "updated_value"),
					resource.TestCheckResourceAttr("sops_entry.test", "data.hello", "world"),
				),
			},
		},
	})
}

func TestResourceSopsEntry_multipleEntries(t *testing.T) {
	tmpFile := copyFixture(t, "basic.yaml")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    key_one = "value_one"
    key_two = "value_two"
    key_three = "value_three"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.key_one", "value_one"),
					resource.TestCheckResourceAttr("sops_entry.test", "data.key_two", "value_two"),
					resource.TestCheckResourceAttr("sops_entry.test", "data.key_three", "value_three"),
					resource.TestCheckResourceAttr("sops_entry.test", "data.hello", "world"),
				),
			},
		},
	})
}

func TestResourceSopsEntry_overwriteExisting(t *testing.T) {
	tmpFile := copyFixture(t, "basic.yaml")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    hello = "updated_world"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.hello", "updated_world"),
				),
			},
		},
	})
}

func TestResourceSopsEntry_json(t *testing.T) {
	tmpFile := copyFixture(t, "basic.json")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    new_key = "json_value"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.new_key", "json_value"),
					resource.TestCheckResourceAttr("sops_entry.test", "data.hello", "world"),
				),
			},
		},
	})
}

func TestResourceSopsEntry_nestedDotPath(t *testing.T) {
	tmpFile := copyFixture(t, "nested.yaml")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    "db.password" = "new_password"
    "db.port"     = "5432"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.db.password", "new_password"),
					resource.TestCheckResourceAttr("sops_entry.test", "data.db.port", "5432"),
					// Existing nested key preserved
					resource.TestCheckResourceAttr("sops_entry.test", "data.db.user", "foo"),
				),
			},
		},
	})
}

func TestResourceSopsEntry_updateRemovesOldKeys(t *testing.T) {
	tmpFile := copyFixture(t, "basic.yaml")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    key_a = "value_a"
    key_b = "value_b"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.key_a", "value_a"),
					resource.TestCheckResourceAttr("sops_entry.test", "data.key_b", "value_b"),
				),
			},
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    key_a = "value_a"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.key_a", "value_a"),
					resource.TestCheckNoResourceAttr("sops_entry.test", "data.key_b"),
				),
			},
		},
	})
}

func TestResourceSopsEntry_destroyRemovesKeys(t *testing.T) {
	tmpFile := copyFixture(t, "basic.yaml")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			// After destroy, verify the key was removed from the file
			tree, _, _, _, err := loadAndDecryptFile(tmpFile)
			if err != nil {
				return fmt.Errorf("failed to load file after destroy: %w", err)
			}
			entries := readEntries(tree, []string{"destroy_test_key"})
			if _, exists := entries["destroy_test_key"]; exists {
				return fmt.Errorf("key 'destroy_test_key' still exists in file after destroy")
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    destroy_test_key = "should_be_removed"
  }
}
`, tmpFile),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("sops_entry.test", "data.destroy_test_key", "should_be_removed"),
				),
			},
		},
	})
}

func TestResourceSopsEntry_fileNotFound(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "sops_entry" "test" {
  file = "/nonexistent/path/to/file.yaml"
  entries = {
    key = "value"
  }
}
`,
				ExpectError: regexp.MustCompile(`file not found`),
			},
		},
	})
}

func TestResourceSopsEntry_emptyEntries(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "sops_entry" "test" {
  file = "/some/file.yaml"
  entries = {}
}
`,
				ExpectError: regexp.MustCompile(`Empty entries map`),
			},
		},
	})
}

func TestResourceSopsEntry_invalidKeyPath(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "sops_entry" "test" {
  file = "/some/file.yaml"
  entries = {
    "foo..bar" = "value"
  }
}
`,
				ExpectError: regexp.MustCompile(`Invalid entry key`),
			},
		},
	})
}

func TestResourceSopsEntry_preservesFilePermissions(t *testing.T) {
	tmpFile := copyFixture(t, "basic.yaml")

	// Set restrictive permissions before apply
	if err := os.Chmod(tmpFile, 0600); err != nil {
		t.Fatal(err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "sops_entry" "test" {
  file = %q
  entries = {
    perm_test = "value"
  }
}
`, tmpFile),
				Check: func(s *terraform.State) error {
					info, err := os.Stat(tmpFile)
					if err != nil {
						return err
					}
					if info.Mode().Perm() != 0600 {
						return fmt.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
					}
					return nil
				},
			},
		},
	})
}
