package taintscan

import (
	"sync"
	"sync/atomic"

	"github.com/dimasma0305/php-parser-go/ast"
	"github.com/dimasma0305/php-parser-go/parsetree"
)

type Location struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet,omitempty"`
}

type Trace struct {
	Source   Location `json:"source"`
	Sink     Location `json:"sink"`
	Callable string   `json:"callable,omitempty"`
}

type EntryPoint struct {
	Kind     string   `json:"kind"`
	Name     string   `json:"name,omitempty"`
	Route    string   `json:"route,omitempty"`
	Methods  string   `json:"methods,omitempty"`
	Access   string   `json:"access,omitempty"`
	Location Location `json:"location"`
}

type FlowContext struct {
	Access             string       `json:"access,omitempty"`
	RequiredCapability string       `json:"required_capability,omitempty"`
	MinimumRole        string       `json:"minimum_role,omitempty"`
	EntryPoints        []EntryPoint `json:"entrypoints,omitempty"`
	CapabilityChecks   []Location   `json:"capability_checks,omitempty"`
	NonceChecks        []Location   `json:"nonce_checks,omitempty"`
	ValidationChecks   []Location   `json:"validation_checks,omitempty"`
	AuthChecks         []Location   `json:"auth_checks,omitempty"`
	UnauthChecks       []Location   `json:"unauth_checks,omitempty"`
	AdminChecks        []Location   `json:"admin_checks,omitempty"`
	AjaxChecks         []Location   `json:"ajax_checks,omitempty"`
}

type sourceOriginRef struct {
	Location           Location    `json:"location"`
	PersistentRead     bool        `json:"persistent_read,omitempty"`
	PathSafe           bool        `json:"path_safe,omitempty"`
	OutputSafeHTML     bool        `json:"output_safe_html,omitempty"`
	OutputUnsafeHTML   bool        `json:"output_unsafe_html,omitempty"`
	StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
}

type Finding struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message            string      `json:"message"`
		Trace              Trace       `json:"dataflow_trace"`
		Context            FlowContext `json:"context,omitempty"`
		StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
	} `json:"extra"`
}

type Payload struct {
	Summary *PayloadSummary `json:"summary,omitempty"`
	Results []Finding       `json:"results"`
	Errors  []string        `json:"errors"`
}

type Result struct {
	Target    string
	Manifest  *parsetree.Manifest
	Payload   Payload
	Callables int
}

type Options struct {
	AllowedSinkOps  map[string]struct{}
	MaxPasses       int
	Instrumentation bool
	// MemoryLimitBytes is the soft heap ceiling at which in-flight callable
	// analysis aborts gracefully (partial findings) instead of risking OOM on
	// pathological mega-plugins. 0 keeps the legacy between-callable guard.
	MemoryLimitBytes uint64
}

type sourceFile struct {
	FullPath string
	Relative string
	Source   string
	AST      []ast.Node
	Lines    []string
}

type callable struct {
	Key                          string
	Display                      string
	SourcePath                   string
	StartLine                    int
	Class                        string
	Namespace                    string
	UseAliases                   map[string]string
	Static                       bool
	Params                       []string
	ParamTypes                   map[string]string
	HasDirectReturnHintCandidate bool
	Stmts                        []ast.Node
}

type taintSummary struct {
	Sources       []Location
	SourceOrigins []sourceOriginRef
	ReceiverPaths []receiverPathRef
	Params        []int
	ParamPaths    []paramPathRef
}

type paramPathRef struct {
	Index              int         `json:"index"`
	Path               string      `json:"path"`
	PersistentRead     bool        `json:"persistent_read,omitempty"`
	PathSafe           bool        `json:"path_safe,omitempty"`
	OutputSafeHTML     bool        `json:"output_safe_html,omitempty"`
	OutputUnsafeHTML   bool        `json:"output_unsafe_html,omitempty"`
	StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
}

type receiverPathRef struct {
	Path               string      `json:"path"`
	PersistentRead     bool        `json:"persistent_read,omitempty"`
	PathSafe           bool        `json:"path_safe,omitempty"`
	OutputSafeHTML     bool        `json:"output_safe_html,omitempty"`
	OutputUnsafeHTML   bool        `json:"output_unsafe_html,omitempty"`
	StoredWriteContext FlowContext `json:"stored_write_context,omitempty"`
}

type summary struct {
	ReturnSources        []Location
	ReturnSourceOrigins  []sourceOriginRef
	ReturnReceiverPaths  []receiverPathRef
	ReturnParams         []int
	ReturnParamPaths     []paramPathRef
	ReturnPathWrites     map[string]taintSummary
	ReturnClasses        []string
	SourceFindings       []findingRecord
	ParamFindings        map[int][]sinkTemplate
	ReceiverFindings     []sinkTemplate
	StaticWrites         map[string]taintSummary
	ReceiverWrites       map[string]taintSummary
	ReceiverPathWrites   map[string]taintSummary
	ReceiverStorageLinks map[string]string
	StorageWrites        map[string]taintSummary
	StoragePathWrites    map[string]taintSummary
}

type sinkTemplate struct {
	RuleID             string
	Message            string
	Sink               Location
	Callable           string
	Context            FlowContext
	StoredWriteContext FlowContext
	ParamPath          string
	ReceiverPath       string
}

type findingRecord struct {
	RuleID             string
	Message            string
	Source             Location
	Sink               Location
	Callable           string
	Context            FlowContext
	StoredWriteContext FlowContext
}

type origin struct {
	kind               string
	paramIdx           int
	paramPath          string
	receiverPath       string
	source             Location
	persistentRead     bool
	pathSafe           bool
	outputSafeHTML     bool
	outputUnsafeHTML   bool
	// numericSafe marks a value coerced to a number by intval/absint/floatval
	// (or array_map thereof): it cannot carry HTML/JS metacharacters, so the
	// reflected-XSS path drops it. It is deliberately NOT honored by the
	// stored-XSS path, where container-field collapse can make a numeric helper
	// falsely "cover" a sibling string field that is the real XSS carrier.
	numericSafe        bool
	storedWriteContext FlowContext
}

type originSet map[string]origin

type engine struct {
	target                          string
	files                           []sourceFile
	fileIndex                       map[string]sourceFile
	callables                       map[string]callable
	callOrder                       []string
	functions                       map[string]string
	methods                         map[string]map[string]string
	classParents                    map[string]string
	staticPropOwners                map[string]map[string]string
	literalClassIndex               map[string][]string
	literalClassProperties          map[string]string
	specializedLiteralCallables     map[string]map[string]string
	literalGlobalConsts             map[string]string
	literalClassConsts              map[string]string
	directReturnHints               map[string]string
	directReturnPropertyHints       map[string]string
	literalArgHints                 map[string]map[int]string
	literalArgPathHints             map[string]map[int]map[string]string
	receiverPropertyClassHints      map[string][]string
	receiverPropertyFallbackHints   map[string]classHintCandidatesCacheEntry
	callableReceiverPropertyClasses map[string]map[string][]string
	receiverPropertyEntryClassHints map[string][]string
	callableArrayEntryClassHints    map[string][]string
	receiverMutatingCallables       map[string]struct{}
	summaries                       map[string]summary
	contexts                        map[string]FlowContext
	staticProps                     map[string]originSet
	storage                         map[string]originSet
	storagePaths                    map[string]originSet
	callEdges                       map[string]map[string]struct{}
	dataCallEdges                   map[string]map[string]struct{}
	callSiteEdges                   map[string][]callSiteEdge
	reverseCallEdges                map[string]map[string]struct{}
	storageReadFamiliesByCallable   map[string]map[string]struct{}
	storageReadBucketsByCallable    map[string]map[string]struct{}
	directStorageWriterCallables    map[string]struct{}
	storageBaseReadersByFamily      map[string]map[string]struct{}
	storagePathReadersByExact       map[string]map[string]struct{}
	storagePathReadersByBucket      map[string]map[string]struct{}
	storageBaseWritersByFamily      map[string]map[string]struct{}
	storageBaseWritersByFamilyClass map[string]map[string]struct{}
	storagePathWritersByBucket      map[string]map[string]struct{}
	storagePathWritersByBucketClass map[string]map[string]struct{}
	staticReadRootsByCallable       map[string]map[string]struct{}
	staticReadPathsByCallable       map[string]map[string]struct{}
	staticBaseReadersByRoot         map[string]map[string]struct{}
	staticPathReadersByExact        map[string]map[string]struct{}
	staticPathReadersByBucket       map[string]map[string]struct{}
	directPublicCallables           map[string]struct{}
	directEntryPointsByCallable     map[string][]EntryPoint
	requestReachableCallables       map[string]struct{}
	requestOriginReachableCallables map[string]struct{}
	relevantCallables               map[string]struct{}
	recordReadCallables             map[string]struct{}
	callSinkRelevantUseOrders       map[string]map[string]int
	callSinkRelevantUsePaths        map[string]map[string]map[string]int
	callInputConsumingCallables     map[string]bool
	outputSinkRelevantUseOrders     map[string]map[string]int
	outputSinkRelevantUsePaths      map[string]map[string]map[string]int
	sqlSinkRelevantUseOrders        map[string]map[string]int
	actionSinkRelevantUseOrders     map[string]map[string]int
	actionSinkRelevantUsePaths      map[string]map[string]map[string]int
	fileSinkRelevantUseOrders       map[string]map[string]int
	fileSinkRelevantUsePaths        map[string]map[string]map[string]int
	includeSinkRelevantUseOrders    map[string]map[string]int
	includeSinkRelevantUsePaths     map[string]map[string]map[string]int
	actionCallbacks                 map[string][]string
	filterCallbacks                 map[string][]string
	summaryFingerprints             map[string]string
	summaryInputFingerprints        map[string]string
	storageStateFingerprints        map[string]string
	storagePathStateFingerprints    map[string]string
	staticStateFingerprints         map[string]string
	passWarmSummaryCache            map[string]summary
	passWarmSummaryInflight         map[string]chan struct{}
	passWarmSummaryMu               sync.RWMutex
	callbackClassHintMu             sync.RWMutex
	statementGuardWeakAuthMu        sync.RWMutex
	pathSanitizerCache              map[string]pathSanitizerInfo
	pathSanitizerMu                 sync.RWMutex
	// localArrayResolvers caches the per-callable localArrayLiteralResolver,
	// which is purely AST-derived (pass- and batch-invariant) but was rebuilt —
	// walking the whole callable body — on every call site, pass, and batch. A
	// shared pointer so engine clones reuse it across all sink-op batches.
	localArrayResolvers             *sync.Map
	// heapGauge holds the most recent sampled HeapAlloc (bytes), updated by a
	// background sampler so the hot path reads memory pressure cheaply (atomic
	// load) instead of a per-callable stop-the-world runtime.ReadMemStats.
	// Shared pointer so engine clones observe the same gauge. heapHardLimit is
	// the bytes ceiling at which in-flight callable analysis aborts gracefully
	// (0 keeps the legacy 3 GiB between-callable behavior).
	heapGauge                       *atomic.Uint64
	heapHardLimit                   uint64
	allowedSinkOps                  map[string]struct{}
	maxPasses                       int
	timingsEnabled                  bool
	instrumentationEnabled          bool
	currentBatchName                string
	statementGuardWeakAuthCache     map[string]locationCacheEntry
}

type pathSanitizerInfo struct {
	ParamIdx int
	OK       bool
}

type classHintCandidatesCacheEntry struct {
	Candidates []string
	Computed   bool
}

type locationCacheEntry struct {
	Locations []Location
	Computed  bool
}

type callSiteEdge struct {
	callee                string
	line                  int
	order                 int
	dataCarrier           bool
	booleanUse            bool
	argCarrier            bool
	argCount              int
	runtimeArgIdxs        map[int]struct{}
	hasReceiver           bool
	receiverCarrier       bool
	receiverStateRelevant bool
	assignedRoot          string
	literalArgs           map[int]string
}

type forwardEdge struct {
	callee      string
	dataCarrier bool
}

var maxNestedStaticPathsPerRoot = 64
var maxNestedStoragePathsPerRoot = 64
var maxNestedParamPathsPerRoot = 32
var maxRelativeOriginPathSegments = 16

const maxCrossRequestFamilyWideWriterFallback = 16

const conflictingLiteralArgHint = "\x00"

type callbackRegistration struct {
	TargetKey      string
	Entry          EntryPoint
	PermissionKeys []string
}

const (
	originSource    = "source"
	originContainer = "container"
	originParam     = "param"
	originReceiver  = "receiver"
)

var (
	pathTransversalMessage                = "Request-controlled path reaches an include or require primitive. Review local file inclusion and traversal controls."
	requestPathReadDeleteMessage          = "Request-controlled path reaches a raw file read, open, or delete primitive. Review path normalization, root restriction, authz, and whether the endpoint is attacker-reachable."
	requestRecordOutputMessage            = "Request-derived input selects stored content that is returned to the requester without a capability check. Review for unauthenticated disclosure or IDOR."
	requestFileUploadMessage              = "Request-supplied upload reaches a server-side file write primitive without a capability check. Review unauthenticated upload surfaces and AJAX or REST authorization."
	requestFileDeleteMessage              = "Request-controlled path reaches a server-side file delete primitive without a capability check. Review unauthorized delete surfaces, including AJAX and REST authorization."
	requestSensitiveActionMessage         = "Request-controlled input reaches a sensitive state-changing or administrative action without a definite capability check. Review missing authorization and dynamic capability routing."
	requestFinancialActionMessage         = "Request-controlled input reaches a financial refund or cancellation action without a definite capability check. Review AJAX or REST authorization around payment state changes."
	privilegeMutationMessage              = "Request-controlled data reaches a role or capability mutation primitive. Review privilege escalation via set_role(), add_cap(), default_role, or capability metadata writes."
	restPublicDataDisclosureMessage       = "Secret-derived data is embedded into a public REST route path that is visible in the route index. Review for bearer token, secret, or API key disclosure via route enumeration."
	publicTokenIssuanceSurfaceMessage     = "A REST callback issues a fresh token-like credential from requester-controlled scope without a definite prior token-validation guard. Review token refresh, bearer token scoping, and credential issuance from request-selected scope."
	issuedAuthLinkSurfaceMessage          = "A callback issues a login or auth URL that is later consumed by a public query-parameter login handler to set authentication cookies. Review alternate auth-link issuance and social-login account takeover paths."
	publicOAuthCallbackAuthSurfaceMessage = "A public OAuth or social-login callback wrapper dispatches into authentication-cookie issuance without a definite registration gate. Review public social-login and OAuth callback account-takeover surfaces."
	predictableIdentifierSurfaceMessage   = "A low-entropy security-sensitive identifier is reused in an exported or downloadable artifact name. Review guessable snapshot, token, or key-derived filenames and URLs."
	uploadValidationSurfaceMessage        = "Filename-derived logic weakens a WordPress upload validation callback by overriding extension or MIME decisions without an exact extension guard. Review authenticated upload-validation bypass surfaces."
	storedXSSOutputMessage                = "Data loaded from persistent storage is rendered to a public HTML output surface without a definite output-safe boundary. Review for stored XSS."
	reflectedXSSOutputMessage             = "Request-controlled data is echoed to HTML output without a definite output-safe boundary (esc_html/esc_attr/esc_url/wp_kses/numeric cast). Review for reflected XSS."
	renderCallbackMessage                 = "Array-backed function input reaches a dynamic callable without a capability check. Review public render or shortcode surfaces for unsafe callback execution."
	unsafeUseMessage                      = "Request-controlled data reaches a dangerous code-exec, command-exec, or dynamic-dispatch primitive."
	unsafeDeserializationMessage          = "Untrusted data reaches unserialize() without a safe class restriction. Review for object injection and gadget-based code execution or file read."
	taintedSQLMessage                     = "Request-controlled data reaches a raw SQL execution primitive without a clear parameterization boundary. Review for SQL injection."
	ssrfMessage                           = "Request-controlled data reaches the URL of an outbound HTTP request (wp_remote_*/curl). Review for server-side request forgery against internal services."
	openRedirectMessage                   = "Request-controlled data reaches a redirect target without host validation (wp_redirect / Location header). Review for open redirect."
	headerInjectionMessage                = "Request-controlled data reaches a raw response header. Review for HTTP header / CRLF response-splitting injection."
	storageFamilies                       = map[string]struct{}{
		"meta_value":           {},
		"option_value":         {},
		"site_option_value":    {},
		"transient_value":      {},
		"site_transient_value": {},
		"post_meta_value":      {},
		"user_meta_value":      {},
		"term_meta_value":      {},
		"comment_meta_value":   {},
		"post_record":          {},
		"post_content":         {},
		"post_excerpt":         {},
		"form_data":            {},
		"content":              {},
	}
)
