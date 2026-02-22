package sops

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &entryResource{}

func newEntryResource() resource.Resource {
	return &entryResource{}
}

type entryResource struct{}

type entryResourceModel struct {
	File    types.String `tfsdk:"file"`
	Entries types.Map    `tfsdk:"entries"`
	Data    types.Map    `tfsdk:"data"`
}

func (r *entryResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "sops_entry"
}

func (r *entryResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage specific key/value entries in an existing SOPS-encrypted file. " +
			"Inserts entries if missing, updates if changed. Unchanged values preserve their ciphertext.",
		Attributes: map[string]schema.Attribute{
			"file": schema.StringAttribute{
				Description: "Path to an existing SOPS-encrypted file.",
				Required:    true,
			},
			"entries": schema.MapAttribute{
				Description: "Key/value pairs to set in the encrypted file.",
				Required:    true,
				Sensitive:   true,
				ElementType: types.StringType,
			},
			"data": schema.MapAttribute{
				Description: "All decrypted key/value pairs from the file after update.",
				Computed:    true,
				Sensitive:   true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *entryResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan entryResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	filePath := plan.File.ValueString()

	var entries map[string]string
	diags = plan.Entries.ElementsAs(ctx, &entries, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tree, dataKey, cipher, store, err := loadAndDecryptFile(filePath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to load encrypted file", err.Error())
		return
	}

	setEntries(tree, entries)

	if err := encryptAndWriteFile(tree, dataKey, cipher, store, filePath); err != nil {
		resp.Diagnostics.AddError("Failed to write encrypted file", err.Error())
		return
	}

	// Re-read to populate data attribute
	tree, _, _, _, err = loadAndDecryptFile(filePath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read back encrypted file", err.Error())
		return
	}

	allData := readAllEntries(tree)
	m, mapDiags := types.MapValueFrom(ctx, types.StringType, allData)
	resp.Diagnostics.Append(mapDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.Data = m
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *entryResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state entryResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	filePath := state.File.ValueString()

	var entries map[string]string
	diags = state.Entries.ElementsAs(ctx, &entries, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tree, _, _, _, err := loadAndDecryptFile(filePath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to load encrypted file", err.Error())
		return
	}

	// Check if managed entries still match
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	currentValues := readEntries(tree, keys)

	// Detect drift: update entries in state to reflect current file values
	driftedEntries := make(map[string]string, len(entries))
	for k, v := range entries {
		if currentVal, ok := currentValues[k]; ok {
			driftedEntries[k] = currentVal
		} else {
			// Key was removed from file externally — keep planned value
			// so Terraform will re-create it on next apply
			driftedEntries[k] = v
		}
	}

	driftedMap, mapDiags := types.MapValueFrom(ctx, types.StringType, driftedEntries)
	resp.Diagnostics.Append(mapDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Entries = driftedMap

	allData := readAllEntries(tree)
	m, mapDiags := types.MapValueFrom(ctx, types.StringType, allData)
	resp.Diagnostics.Append(mapDiags...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Data = m

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *entryResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan entryResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get prior state to detect removed keys
	var priorState entryResourceModel
	diags = req.State.Get(ctx, &priorState)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	filePath := plan.File.ValueString()

	var newEntries map[string]string
	diags = plan.Entries.ElementsAs(ctx, &newEntries, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var oldEntries map[string]string
	diags = priorState.Entries.ElementsAs(ctx, &oldEntries, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tree, dataKey, cipher, store, err := loadAndDecryptFile(filePath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to load encrypted file", err.Error())
		return
	}

	// Remove keys that were in old state but not in new plan
	var removedKeys []string
	for k := range oldEntries {
		if _, exists := newEntries[k]; !exists {
			removedKeys = append(removedKeys, k)
		}
	}
	if len(removedKeys) > 0 {
		unsetEntries(tree, removedKeys)
	}

	setEntries(tree, newEntries)

	if err := encryptAndWriteFile(tree, dataKey, cipher, store, filePath); err != nil {
		resp.Diagnostics.AddError("Failed to write encrypted file", err.Error())
		return
	}

	// Re-read to populate data attribute
	tree, _, _, _, err = loadAndDecryptFile(filePath)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read back encrypted file", err.Error())
		return
	}

	allData := readAllEntries(tree)
	m, mapDiags := types.MapValueFrom(ctx, types.StringType, allData)
	resp.Diagnostics.Append(mapDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.Data = m
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *entryResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state entryResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	filePath := state.File.ValueString()

	var entries map[string]string
	diags = state.Entries.ElementsAs(ctx, &entries, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tree, dataKey, cipher, store, err := loadAndDecryptFile(filePath)
	if err != nil {
		// If the file no longer exists, nothing to clean up
		resp.Diagnostics.AddWarning(
			"Failed to load encrypted file during destroy",
			fmt.Sprintf("Could not load %s: %s. Keys may remain in the file.", filePath, err.Error()),
		)
		return
	}

	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	unsetEntries(tree, keys)

	if err := encryptAndWriteFile(tree, dataKey, cipher, store, filePath); err != nil {
		resp.Diagnostics.AddError("Failed to write encrypted file during destroy", err.Error())
		return
	}
}
