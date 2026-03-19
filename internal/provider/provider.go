// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/darkhonor/terraform-provider-technitium/internal/client"
	"github.com/darkhonor/terraform-provider-technitium/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure TechnitiumProvider satisfies various provider interfaces.
var _ provider.Provider = &TechnitiumProvider{}

// TechnitiumProvider defines the provider implementation.
type TechnitiumProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// TechnitiumProviderModel maps provider schema to Go types.
type TechnitiumProviderModel struct {
	ServerURL      types.String         `tfsdk:"server_url"`
	APIToken       types.String         `tfsdk:"api_token"`
	SkipTLSVerify  types.Bool           `tfsdk:"skip_tls_verify"`
	CACertFile     types.String         `tfsdk:"ca_cert_file"`
	CACertDir      types.String         `tfsdk:"ca_cert_dir"`
	TLSServerName  types.String         `tfsdk:"tls_server_name"`
	TLSMinVersion  types.String         `tfsdk:"tls_min_version"`
	STIGCompliance *STIGComplianceModel `tfsdk:"stig_compliance"`
}

// STIGComplianceModel maps the stig_compliance block.
type STIGComplianceModel struct {
	Enabled        types.Bool           `tfsdk:"enabled"`
	NSS            types.Bool           `tfsdk:"nss"`
	Enforcement    types.String         `tfsdk:"enforcement"`
	Suppress       types.List           `tfsdk:"suppress"`
	Categorization *CategorizationModel `tfsdk:"categorization"`
}

// CategorizationModel maps the categorization block.
type CategorizationModel struct {
	Baseline        types.String `tfsdk:"baseline"`
	Confidentiality types.String `tfsdk:"confidentiality"`
	Integrity       types.String `tfsdk:"integrity"`
	Availability    types.String `tfsdk:"availability"`
}

// TechnitiumProviderData is passed to resources via req.ProviderData.
type TechnitiumProviderData struct {
	Client         *client.Client
	STIGEnabled    bool
	NSS            bool
	Categorization Categorization
	STIGEngine     *validators.Engine // nil when STIG disabled
}

// Categorization holds the resolved C/I/A levels.
type Categorization struct {
	Confidentiality string
	Integrity       string
	Availability    string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &TechnitiumProvider{
			version: version,
		}
	}
}

func (p *TechnitiumProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "technitium"
	resp.Version = p.version
}

func (p *TechnitiumProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for managing Technitium DNS Server. " +
			"Provides STIG-hardened defaults and optional CNSSI 1253 compliance enforcement.",
		Attributes: map[string]schema.Attribute{
			"server_url": schema.StringAttribute{
				Description: "Technitium DNS Server API base URL. Can also be set via TECHNITIUM_SERVER_URL env var.",
				Required:    true,
			},
			"api_token": schema.StringAttribute{
				Description: "Technitium API token. Can also be set via TECHNITIUM_API_TOKEN env var.",
				Required:    true,
				Sensitive:   true,
			},
			"skip_tls_verify": schema.BoolAttribute{
				Description: "Skip TLS certificate verification. Generates STIG warning when stig_compliance is enabled (SC-8).",
				Optional:    true,
			},
			"ca_cert_file": schema.StringAttribute{
				Description: "Path to a PEM-encoded CA certificate file to validate the Technitium server's TLS certificate. " +
					"May be set via the TECHNITIUM_CACERT environment variable.",
				Optional: true,
			},
			"ca_cert_dir": schema.StringAttribute{
				Description: "Path to a directory of PEM-encoded CA certificate files to validate the Technitium server's TLS certificate. " +
					"Files that fail to parse are skipped. May be set via the TECHNITIUM_CAPATH environment variable.",
				Optional: true,
			},
			"tls_server_name": schema.StringAttribute{
				Description: "Name to use as the SNI host when connecting to the Technitium server via TLS. " +
					"May be set via the TECHNITIUM_TLS_SERVER_NAME environment variable.",
				Optional: true,
			},
			"tls_min_version": schema.StringAttribute{
				Description: "Minimum TLS version to accept when connecting to the Technitium server. " +
					"Valid values: \"1.2\", \"1.3\". Defaults to \"1.3\". " +
					"May be set via the TECHNITIUM_TLS_MIN_VERSION environment variable.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf("1.2", "1.3"),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"stig_compliance": schema.SingleNestedBlock{
				Description: "STIG compliance configuration with optional CNSSI 1253 categorization.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Description: "Enable STIG validation on all resources.",
						Optional:    true,
					},
					"nss": schema.BoolAttribute{
						Description: "National Security System mode — requires full CNSSI 1253 categorization.",
						Optional:    true,
					},
					"enforcement": schema.StringAttribute{
						Description: "STIG enforcement policy: strict (errors block apply), warn (warnings only), silent (suppress all). Default: strict.",
						Optional:    true,
					},
					"suppress": schema.ListAttribute{
						Description: "List of DNS-REQ-XXX requirement IDs to suppress. Suppressed findings emit warnings instead of errors.",
						Optional:    true,
						ElementType: types.StringType,
					},
				},
				Blocks: map[string]schema.Block{
					"categorization": schema.SingleNestedBlock{
						Description: "Security categorization for STIG validation.",
						Attributes: map[string]schema.Attribute{
							"baseline": schema.StringAttribute{
								Description: "Shorthand baseline: low, moderate, high. Only when nss = false. Mutually exclusive with individual objectives.",
								Optional:    true,
							},
							"confidentiality": schema.StringAttribute{
								Description: "Confidentiality objective level: low, moderate, high. Required when nss = true.",
								Optional:    true,
							},
							"integrity": schema.StringAttribute{
								Description: "Integrity objective level: low, moderate, high. Required when nss = true.",
								Optional:    true,
							},
							"availability": schema.StringAttribute{
								Description: "Availability objective level: low, moderate, high. Required when nss = true.",
								Optional:    true,
							},
						},
					},
				},
			},
		},
	}
}

func (p *TechnitiumProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config TechnitiumProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Env var fallbacks
	serverURL := config.ServerURL.ValueString()
	if serverURL == "" {
		serverURL = os.Getenv("TECHNITIUM_SERVER_URL")
	}
	if serverURL == "" {
		resp.Diagnostics.AddError("Missing server_url",
			"server_url must be set in the provider configuration or via TECHNITIUM_SERVER_URL environment variable.")
		return
	}

	apiToken := config.APIToken.ValueString()
	if apiToken == "" {
		apiToken = os.Getenv("TECHNITIUM_API_TOKEN")
	}
	if apiToken == "" {
		resp.Diagnostics.AddError("Missing api_token",
			"api_token must be set in the provider configuration or via TECHNITIUM_API_TOKEN environment variable.")
		return
	}

	// Resolve TLS configuration (HCL > env var > default)
	var skipTLSPtr *bool
	if !config.SkipTLSVerify.IsNull() {
		v := config.SkipTLSVerify.ValueBool()
		skipTLSPtr = &v
	}
	skipTLSVerify, err := resolveTLSBool(skipTLSPtr, "TECHNITIUM_SKIP_TLS_VERIFY", false)
	if err != nil {
		resp.Diagnostics.AddError("Invalid TLS configuration", err.Error())
		return
	}

	caCertFile := resolveTLSString(config.CACertFile.ValueString(), "TECHNITIUM_CACERT")
	caCertDir := resolveTLSString(config.CACertDir.ValueString(), "TECHNITIUM_CAPATH")
	tlsServerName := resolveTLSString(config.TLSServerName.ValueString(), "TECHNITIUM_TLS_SERVER_NAME")
	tlsMinVersion, err := resolveTLSMinVersion(config.TLSMinVersion.ValueString(), "TECHNITIUM_TLS_MIN_VERSION", "1.3")
	if err != nil {
		resp.Diagnostics.AddError("Invalid TLS configuration", err.Error())
		return
	}

	// Extract STIG/NSS booleans before Ping for tiered diagnostics
	var stigEnabled, nssEnabled bool
	if config.STIGCompliance != nil {
		stigEnabled = config.STIGCompliance.Enabled.ValueBool()
		nssEnabled = config.STIGCompliance.NSS.ValueBool()
	}

	// Parse STIG compliance (before Ping so ValidateProvider fires first)
	providerData := &TechnitiumProviderData{}

	if config.STIGCompliance != nil {
		providerData.STIGEnabled = stigEnabled
		providerData.NSS = nssEnabled

		if config.STIGCompliance.Categorization != nil {
			cat, diags := validateCategorization(config.STIGCompliance.Categorization, providerData.NSS)
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			providerData.Categorization = cat
		} else if providerData.NSS {
			resp.Diagnostics.AddError("Missing categorization",
				"categorization block is required when nss = true.")
			return
		} else if providerData.STIGEnabled && config.STIGCompliance.Categorization == nil {
			resp.Diagnostics.AddError("Missing categorization",
				"categorization block is required when stig_compliance is enabled.")
			return
		}

		// Parse enforcement (default: strict)
		enforcement := "strict"
		if !config.STIGCompliance.Enforcement.IsNull() && config.STIGCompliance.Enforcement.ValueString() != "" {
			enforcement = config.STIGCompliance.Enforcement.ValueString()
			enfDiags := validateEnforcement(enforcement)
			resp.Diagnostics.Append(enfDiags...)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		// Parse suppress list and validate IDs
		var suppressions []string
		if !config.STIGCompliance.Suppress.IsNull() {
			var rawSuppress []types.String
			resp.Diagnostics.Append(config.STIGCompliance.Suppress.ElementsAs(ctx, &rawSuppress, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
			for _, s := range rawSuppress {
				suppressions = append(suppressions, s.ValueString())
			}
			supDiags := validateSuppressIDs(suppressions)
			resp.Diagnostics.Append(supDiags...)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		// Construct engine when STIG enabled and run ValidateProvider before Ping.
		// STIG validators catch HTTP URLs, skip_tls_verify=true, tls_min_version=1.2
		// before any network call; Ping then fires with tiered TLS diagnostics if
		// provider-level validation passes.
		if providerData.STIGEnabled {
			engine := validators.NewEngine(validators.EngineConfig{
				Enabled:     true,
				Enforcement: enforcement,
				Suppressions: suppressions,
				Categorization: validators.Categorization{
					Confidentiality: providerData.Categorization.Confidentiality,
					Integrity:       providerData.Categorization.Integrity,
					Availability:    providerData.Categorization.Availability,
				},
				NSS: providerData.NSS,
			})
			engine.RegisterBindings(validators.ResourceZone, validators.ZoneBindings)
			engine.RegisterBindings(validators.ResourceServerSettings, validators.ServerSettingsBindings)
			engine.RegisterBindings(validators.ResourceRecord, validators.RecordBindings)
			engine.RegisterBindings(validators.ResourceTSIGKey, validators.TSIGKeyBindings)
			engine.RegisterBindings(validators.TargetProvider, validators.ProviderBindings)
			providerData.STIGEngine = engine

			providerAccessor := &providerConfigAccessor{
				serverURL:     serverURL,
				skipTLSVerify: skipTLSVerify,
				tlsMinVersion: tlsMinVersion,
			}
			engine.ValidateProvider(ctx, providerAccessor, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	// Create API client
	apiClient, err := client.NewClient(client.ClientConfig{
		BaseURL:       serverURL,
		Token:         apiToken,
		SkipTLSVerify: skipTLSVerify,
		CACertFile:    caCertFile,
		CACertDir:     caCertDir,
		TLSServerName: tlsServerName,
		TLSMinVersion: tlsMinVersion,
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to create API client", err.Error())
		return
	}

	// Verify connectivity with tiered TLS error diagnostics
	if err := apiClient.Ping(); err != nil {
		isHTTPS := strings.HasPrefix(serverURL, "https://")
		if isHTTPS {
			tlsErr := client.ClassifyTLSError(err)
			if diagnostic := buildTLSDiagnostic(tlsErr, serverURL, stigEnabled, nssEnabled); diagnostic != "" {
				resp.Diagnostics.AddError("TLS connection failed", diagnostic)
				return
			}
		}
		resp.Diagnostics.AddError("Unable to connect to Technitium server",
			fmt.Sprintf("Ping to %s failed: %s", serverURL, err.Error()))
		return
	}

	providerData.Client = apiClient

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *TechnitiumProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewZoneResource,
		NewRecordResource,
		NewServerSettingsResource,
		NewTSIGKeyResource,
		NewBlockedZoneResource,
		NewBlockedZonesResource,
		NewAllowedZoneResource,
		NewAllowedZonesResource,
	}
}

func (p *TechnitiumProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewZoneDataSource,
		NewRecordDataSource,
		NewServerSettingsDataSource,
		NewTSIGKeyDataSource,
		NewBlockedZoneDataSource,
		NewBlockedZonesDataSource,
		NewAllowedZoneDataSource,
		NewAllowedZonesDataSource,
	}
}

// resolveTLSString resolves a TLS string config value with HCL > env var > empty precedence.
func resolveTLSString(hclValue, envVar string) string {
	if hclValue != "" {
		return hclValue
	}
	return os.Getenv(envVar)
}

// resolveTLSBool resolves a TLS bool config value with HCL > env var > default precedence.
func resolveTLSBool(hclValue *bool, envVar string, defaultVal bool) (bool, error) {
	if hclValue != nil {
		return *hclValue, nil
	}
	envStr := os.Getenv(envVar)
	if envStr != "" {
		val, err := strconv.ParseBool(envStr)
		if err != nil {
			return false, fmt.Errorf("invalid value for %s: %q (expected true/false)", envVar, envStr)
		}
		return val, nil
	}
	return defaultVal, nil
}

// resolveTLSMinVersion resolves the TLS minimum version with HCL > env var > default precedence.
func resolveTLSMinVersion(hclValue, envVar, defaultVal string) (string, error) {
	result := hclValue
	if result == "" {
		result = os.Getenv(envVar)
	}
	if result == "" {
		return defaultVal, nil
	}
	if result != "1.2" && result != "1.3" {
		return "", fmt.Errorf("invalid value for %s: %q (must be \"1.2\" or \"1.3\")", envVar, result)
	}
	return result, nil
}

// validLevels are the allowed CNSSI 1253 / NIST 800-53 categorization levels.
var validLevels = map[string]bool{
	"low":      true,
	"moderate": true,
	"high":     true,
}

// validateCategorization enforces the categorization rules from the design spec Section 3.
func validateCategorization(cat *CategorizationModel, nss bool) (Categorization, diag.Diagnostics) {
	var diags diag.Diagnostics
	result := Categorization{}

	hasBaseline := !cat.Baseline.IsNull() && cat.Baseline.ValueString() != ""
	hasConf := !cat.Confidentiality.IsNull() && cat.Confidentiality.ValueString() != ""
	hasInteg := !cat.Integrity.IsNull() && cat.Integrity.ValueString() != ""
	hasAvail := !cat.Availability.IsNull() && cat.Availability.ValueString() != ""
	hasIndividual := hasConf || hasInteg || hasAvail

	// Rule: baseline and individual objectives are mutually exclusive
	if hasBaseline && hasIndividual {
		diags.AddError("Invalid categorization",
			"baseline and individual objectives (confidentiality, integrity, availability) are mutually exclusive. Use one or the other.")
		return result, diags
	}

	// Rule: NSS requires explicit per-objective categorization, not baseline
	if nss && hasBaseline {
		diags.AddError("Invalid categorization for NSS",
			"National Security Systems require explicit per-objective categorization. "+
				"Set confidentiality, integrity, and availability instead of baseline.")
		return result, diags
	}

	// Rule: NSS requires all three objectives
	if nss && !(hasConf && hasInteg && hasAvail) {
		diags.AddError("Incomplete NSS categorization",
			"National Security Systems require all three objectives: confidentiality, integrity, and availability.")
		return result, diags
	}

	if hasBaseline {
		level := cat.Baseline.ValueString()
		if !validLevels[level] {
			diags.AddError("Invalid baseline level",
				fmt.Sprintf("baseline must be one of: low, moderate, high. Got: %q", level))
			return result, diags
		}
		// Expand baseline to all three objectives
		result.Confidentiality = level
		result.Integrity = level
		result.Availability = level
	} else if hasIndividual {
		// Validate each provided level
		if hasConf {
			if !validLevels[cat.Confidentiality.ValueString()] {
				diags.AddError("Invalid confidentiality level",
					fmt.Sprintf("confidentiality must be one of: low, moderate, high. Got: %q", cat.Confidentiality.ValueString()))
			}
			result.Confidentiality = cat.Confidentiality.ValueString()
		}
		if hasInteg {
			if !validLevels[cat.Integrity.ValueString()] {
				diags.AddError("Invalid integrity level",
					fmt.Sprintf("integrity must be one of: low, moderate, high. Got: %q", cat.Integrity.ValueString()))
			}
			result.Integrity = cat.Integrity.ValueString()
		}
		if hasAvail {
			if !validLevels[cat.Availability.ValueString()] {
				diags.AddError("Invalid availability level",
					fmt.Sprintf("availability must be one of: low, moderate, high. Got: %q", cat.Availability.ValueString()))
			}
			result.Availability = cat.Availability.ValueString()
		}
	}

	return result, diags
}

// validateEnforcement checks the enforcement value is valid.
func validateEnforcement(enforcement string) diag.Diagnostics {
	var diags diag.Diagnostics
	switch enforcement {
	case "strict", "warn", "silent":
		// valid
	default:
		diags.AddError("Invalid enforcement level",
			fmt.Sprintf("enforcement must be one of: strict, warn, silent. Got: %q", enforcement))
	}
	return diags
}

// buildTLSDiagnostic produces a context-aware error message for TLS handshake
// failures. The message is tailored to the user's STIG/NSS context: NSS users
// receive only server-upgrade guidance, STIG users see CA cert options without
// skip_tls_verify, and non-STIG users see all available remediation options.
// Returns an empty string when the error is not TLS-related (caller falls
// through to the generic connectivity error).
func buildTLSDiagnostic(tlsErr client.TLSError, serverURL string, stigEnabled, nss bool) string {
	switch tlsErr.Kind {
	case client.TLSErrVersionMismatch:
		msg := fmt.Sprintf("Connection to %s failed: TLS 1.3 not supported by the server.", serverURL)
		if nss {
			msg += " NSS environments require TLS 1.3 (SC-8). Upgrade the server's TLS configuration to support TLS 1.3."
		} else if stigEnabled {
			msg += " To resolve, either:\n" +
				"  - Upgrade the server's TLS configuration to support TLS 1.3\n" +
				"  - Set tls_min_version = \"1.2\" in the provider configuration (will generate STIG warning)"
		} else {
			msg += " To resolve, either:\n" +
				"  - Upgrade the server's TLS configuration to support TLS 1.3\n" +
				"  - Set tls_min_version = \"1.2\" in the provider configuration\n" +
				"  - Set skip_tls_verify = true to bypass certificate verification entirely"
		}
		return msg
	case client.TLSErrUnknownAuthority:
		msg := fmt.Sprintf("Connection to %s failed: server certificate signed by unknown authority.", serverURL)
		if nss || stigEnabled {
			msg += " To resolve:\n" +
				"  - Configure ca_cert_file or ca_cert_dir with the CA certificate that signed the server's certificate"
		} else {
			msg += " To resolve, either:\n" +
				"  - Configure ca_cert_file or ca_cert_dir with the CA certificate that signed the server's certificate\n" +
				"  - Set skip_tls_verify = true to bypass certificate verification entirely"
		}
		return msg
	case client.TLSErrCertificateInvalid, client.TLSErrHostnameMismatch:
		msg := fmt.Sprintf("Connection to %s failed: server certificate verification failed.", serverURL)
		if nss || stigEnabled {
			msg += " Verify the correct CA chain is configured in ca_cert_file or ca_cert_dir."
		} else {
			msg += " To resolve, either:\n" +
				"  - Verify the correct CA chain is configured in ca_cert_file or ca_cert_dir\n" +
				"  - Set skip_tls_verify = true to bypass certificate verification entirely"
		}
		return msg
	case client.TLSErrNotTLS:
		return ""
	}
	return ""
}

// validateSuppressIDs checks all suppression IDs are valid DNS-REQ-XXX IDs.
func validateSuppressIDs(ids []string) diag.Diagnostics {
	var diags diag.Diagnostics
	validIDs := make(map[string]bool)
	for _, id := range validators.AllRequirementIDs() {
		validIDs[id] = true
	}
	for _, id := range ids {
		if !validIDs[id] {
			diags.AddError("Invalid suppression ID",
				fmt.Sprintf("suppress contains unknown requirement ID: %q. Valid IDs are DNS-REQ-001 through DNS-REQ-%03d.", id, len(validators.DNSSecurityRequirements)))
		}
	}
	return diags
}

// providerConfigAccessor adapts provider configuration for STIG validator access.
type providerConfigAccessor struct {
	serverURL     string
	skipTLSVerify bool
	tlsMinVersion string
}

func (a *providerConfigAccessor) GetString(path string) (string, bool) {
	switch path {
	case "server_url":
		return a.serverURL, true
	case "tls_min_version":
		if a.tlsMinVersion == "" {
			return "", false
		}
		return a.tlsMinVersion, true
	default:
		return "", false
	}
}

func (a *providerConfigAccessor) GetBool(path string) (bool, bool) {
	switch path {
	case "skip_tls_verify":
		// Always returns ok=true because the resolved value always exists
		// after resolveTLSBool (explicit default). Default (false) is compliant.
		return a.skipTLSVerify, true
	default:
		return false, false
	}
}

func (a *providerConfigAccessor) GetStringList(path string) ([]string, bool) {
	return nil, false
}

// Interface compliance assertion.
var _ validators.ConfigAccessor = &providerConfigAccessor{}
