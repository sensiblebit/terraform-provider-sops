package sops

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &entryResource{}
	_ resource.ResourceWithImportState    = &entryResource{}
	_ resource.ResourceWithValidateConfig = &entryResource{}
)

func newEntryResource() resource.Resource {
	return &entryResource{}
}

type entryResource struct{}

type entryResourceModel struct {
	Id      types.String `tfsdk:"id"`
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
			"Inserts entries if missing, updates if changed. Unchanged values preserve their ciphertext. " +
			"Only one sops_entry resource should target a given file to avoid concurrent write conflicts. " +
			"Only the first YAML document is supported in multi-document files.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "Resource identifier (set to the file path).",
				Computed:    true,
			},
			"file": schema.StringAttribute{
				Description: "Path to an existing SOPS-encrypted file.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"entries": schema.MapAttribute{
				Description: "Key/value pairs to set in the encrypted file. " +
					"Keys support dot-separated paths for nested access (e.g., \"db.password\"). " +
					"Numeric path segments are treated as array indices. " +
					"Purely numeric YAML string keys cannot be targeted with this syntax.",
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

func (r *entryResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config entryResourceModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Entries.IsNull() || config.Entries.IsUnknown() {
		return
	}

	var entries map[string]string
	diags = config.Entries.ElementsAs(ctx, &entries, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if len(entries) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("entries"),
			"Empty entries map",
			"The entries map must contain at least one key/value pair.",
		)
		return
	}

	for key := range entries {
		if err := validateKeyPath(key); err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("entries"),
				"Invalid entry key",
				fmt.Sprintf("Key %q is invalid: %s", key, err),
			)
		}
	}
}

func (r *entryResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("file"), req, resp)
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

	// Read data from in-memory tree before encryption mutates it
	allData := readAllEntries(tree)

	if err := encryptAndWriteFile(tree, dataKey, cipher, store, filePath); err != nil {
		resp.Diagnostics.AddError("Failed to write encrypted file", err.Error())
		return
	}

	m, mapDiags := types.MapValueFrom(ctx, types.StringType, allData)
	resp.Diagnostics.Append(mapDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.Id = types.StringValue(filePath)
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
		// If the file no longer exists, remove from state so Terraform can recreate
		if isFileNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to load encrypted file", err.Error())
		return
	}

	// Check if managed entries still match
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	currentValues := readEntries(tree, keys)

	// Detect drift: update entries in state to reflect current file values.
	// If a key was externally deleted, set to empty string to force a diff
	// against the planned value on next apply.
	driftedEntries := make(map[string]string, len(entries))
	for k := range entries {
		if currentVal, ok := currentValues[k]; ok {
			driftedEntries[k] = currentVal
		} else {
			// Key was removed from file externally — use empty string to
			// trigger a diff so Terraform will re-create the key on next apply
			driftedEntries[k] = ""
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

	// Read data from in-memory tree before encryption mutates it
	allData := readAllEntries(tree)

	if err := encryptAndWriteFile(tree, dataKey, cipher, store, filePath); err != nil {
		resp.Diagnostics.AddError("Failed to write encrypted file", err.Error())
		return
	}

	m, mapDiags := types.MapValueFrom(ctx, types.StringType, allData)
	resp.Diagnostics.Append(mapDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.Id = types.StringValue(filePath)
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
		// If the file no longer exists, nothing to clean up — that's fine
		if isFileNotFound(err) {
			return
		}
		// For other errors (e.g., decryption failure), report as error
		// so the user can investigate rather than silently losing state
		resp.Diagnostics.AddError(
			"Failed to load encrypted file during destroy",
			fmt.Sprintf("Could not load %s: %s", filePath, err.Error()),
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
