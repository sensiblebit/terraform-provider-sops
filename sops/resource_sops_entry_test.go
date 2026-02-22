package sops

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
					// Verify the new entry was set
					resource.TestCheckResourceAttr("sops_entry.test", "data.new_key", "new_value"),
					// Verify existing entries are preserved
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
					// Existing keys still present
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
					// Existing keys preserved
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
