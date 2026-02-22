package sops

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	sopssdk "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
)

// loadAndDecryptFile loads a SOPS-encrypted file and decrypts it.
// Returns the tree, data key, cipher (with populated IV stash), and store.
// The same cipher instance must be used for re-encryption to preserve
// unchanged ciphertext via the IV stash mechanism.
func loadAndDecryptFile(filePath string) (*sopssdk.Tree, []byte, sopssdk.Cipher, common.Store, error) {
	format := formats.FormatForPath(filePath)
	store := common.StoreForFormat(format, config.NewStoresConfig())
	cipher := aes.NewCipher()

	tree, err := common.LoadEncryptedFileWithBugFixes(common.GenericDecryptOpts{
		Cipher:      cipher,
		InputStore:  store,
		InputPath:   filePath,
		IgnoreMAC:   false,
		KeyServices: []keyservice.KeyServiceClient{keyservice.NewLocalClient()},
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("loading encrypted file: %w", err)
	}

	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:      cipher,
		IgnoreMac:   false,
		Tree:        tree,
		KeyServices: []keyservice.KeyServiceClient{keyservice.NewLocalClient()},
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("decrypting file: %w", err)
	}

	return tree, dataKey, cipher, store, nil
}

// parsePath converts a dot-separated key string into a SOPS tree path.
// Integer segments are converted to int for array indexing (e.g., "list.0.name"
// becomes []interface{}{"list", 0, "name"}).
func parsePath(key string) []interface{} {
	parts := strings.Split(key, ".")
	path := make([]interface{}, len(parts))
	for i, part := range parts {
		if idx, err := strconv.Atoi(part); err == nil {
			path[i] = idx
		} else {
			path[i] = part
		}
	}
	return path
}

// setEntries sets each key/value pair in entries on the first branch of the tree.
// Keys use dot-separated paths for nested access (e.g., "db.password").
// Returns true if any value changed.
func setEntries(tree *sopssdk.Tree, entries map[string]string) bool {
	anyChanged := false
	for key, value := range entries {
		var changed bool
		tree.Branches[0], changed = tree.Branches[0].Set(
			parsePath(key),
			value,
		)
		if changed {
			anyChanged = true
		}
	}
	return anyChanged
}

// unsetEntries removes each key from the first branch of the tree.
// Keys use dot-separated paths for nested access. Keys that don't exist are silently skipped.
func unsetEntries(tree *sopssdk.Tree, keys []string) {
	for _, key := range keys {
		branch, err := tree.Branches[0].Unset(parsePath(key))
		if err == nil {
			tree.Branches[0] = branch
		}
	}
}

// encryptAndWriteFile re-encrypts the tree and writes it to disk.
func encryptAndWriteFile(tree *sopssdk.Tree, dataKey []byte, cipher sopssdk.Cipher, store common.Store, filePath string) error {
	err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    tree,
		Cipher:  cipher,
	})
	if err != nil {
		return fmt.Errorf("encrypting tree: %w", err)
	}

	encryptedFile, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return fmt.Errorf("serializing encrypted file: %w", err)
	}

	if err := os.WriteFile(filePath, encryptedFile, 0644); err != nil {
		return fmt.Errorf("writing encrypted file: %w", err)
	}

	return nil
}

// readEntries extracts specific keys from the decrypted tree's first branch.
// Keys use dot-separated paths, matching the flattened output format.
func readEntries(tree *sopssdk.Tree, keys []string) map[string]string {
	allFlat := readAllEntries(tree)
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if val, ok := allFlat[key]; ok {
			result[key] = val
		}
	}
	return result
}

// readAllEntries extracts all key/value pairs from the decrypted tree's first branch,
// flattening nested structures to dot-separated keys.
func readAllEntries(tree *sopssdk.Tree) map[string]string {
	data := make(map[string]interface{})
	for _, item := range tree.Branches[0] {
		if keyStr, ok := item.Key.(string); ok {
			data[keyStr] = item.Value
		}
	}
	return flatten(data)
}
