package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

var (
	recordReadPrefixes = []string{"get", "read", "fetch", "find", "load", "retrieve", "lookup", "query"}
	recordReadMarkers  = []string{"log", "record", "entry", "message", "content", "transcript", "detail", "details", "mail", "email"}
)

type sqlClauseFilterModel struct {
	Hook              string
	ArgIndex          int
	TaintCallbackArg0 bool
	RuleID            string
	Message           string
}

type uploadValidationFilterModel struct {
	Hook             string
	FilenameArgIndex int
	RuleID           string
	Message          string
}

type actionSinkModel struct {
	ArgIndex             int
	ArgIndexes           []int
	RuleID               string
	Message              string
	RequireConfigLike    bool
	RequireInstallerLike bool
	RequireUserLike      bool
}

func actionSinkArgIndexes(model actionSinkModel, argc int) []int {
	if len(model.ArgIndexes) != 0 {
		out := make([]int, 0, len(model.ArgIndexes))
		for _, idx := range model.ArgIndexes {
			if idx >= 0 && idx < argc {
				out = append(out, idx)
			}
		}
		return out
	}
	if model.ArgIndex >= 0 && model.ArgIndex < argc {
		return []int{model.ArgIndex}
	}
	return nil
}

var coreSQLClauseFilters = []sqlClauseFilterModel{
	{Hook: "posts_search", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_search_orderby", ArgIndex: 0, TaintCallbackArg0: true, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_where", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_join", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_groupby", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_orderby", ArgIndex: 0, TaintCallbackArg0: true, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_distinct", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "post_limits", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_fields", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_where_request", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_join_request", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_groupby_request", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_orderby_request", ArgIndex: 0, TaintCallbackArg0: true, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_distinct_request", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "post_limits_request", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_fields_request", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "posts_request", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
	{Hook: "get_meta_sql", ArgIndex: 0, RuleID: "tainted-sql-string", Message: taintedSQLMessage},
}

var coreUploadValidationFilters = []uploadValidationFilterModel{
	{Hook: "wp_check_filetype_and_ext", FilenameArgIndex: 2, RuleID: "upload-api-surface", Message: uploadValidationSurfaceMessage},
}

func isDirectRequestSourceFunc(name string) bool {
	switch normalizeName(name) {
	case "filter_input", "filter_input_array", "getallheaders", "apache_request_headers",
		// Gravity Forms request accessors (rgpost/rgget read $_POST/$_GET); these
		// are framework helper names, not plugin names.
		"rgpost", "rgget", "rgpost_array", "rgget_array":
		return true
	default:
		return false
	}
}

func isRemoteResponseSourceFunc(name string) bool {
	switch normalizeName(name) {
	case "wp_remote_get", "wp_remote_post", "wp_remote_request", "wp_safe_remote_get", "wp_safe_remote_post":
		return true
	default:
		return false
	}
}

func isRequestGetterMethod(name string) bool {
	switch strings.ToLower(name) {
	case "get_json_params", "get_body_params", "get_query_params", "get_file_params", "get_params", "get_param", "get_value", "get_header", "get_headers", "get_route_params", "getip", "get_ip",
		"getvar", "getint", "getcmd", "getstring", "getbool", "getarray", "getfloat":
		return true
	default:
		return false
	}
}

func isRequestGetterMethodCall(call *ast.ExprMethodCall) bool {
	if call == nil {
		return false
	}
	if isRequestGetterMethod(identifierText(call.Name)) {
		return true
	}
	if !strings.EqualFold(identifierText(call.Name), "all") {
		return false
	}
	switch typed := call.Var.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		return ok && strings.EqualFold(strings.TrimSpace(name), "request")
	case *ast.ExprPropertyFetch:
		return strings.EqualFold(strings.TrimSpace(identifierText(typed.Name)), "request")
	default:
		return false
	}
}

func isRequestGetterStaticCall(className string, name string) bool {
	className = requestGetterStaticClassLeaf(className)
	switch normalizeName(name) {
	case "get":
		switch className {
		case "request", "get", "post", "input", "util_request":
			return true
		}
	case "post", "input", "query":
		// Laravel/wpfluent-style request facades: Input::post(...),
		// Request::query(...). Matched by facade class-name idiom only.
		switch className {
		case "request", "input", "get", "post":
			return true
		}
	case "get_string", "get_integer", "get_float", "get_array", "get_bool", "get_as_array":
		return className == "util_request"
	}
	return false
}

func requestGetterStaticClassLeaf(className string) string {
	className = normalizeName(className)
	if idx := strings.LastIndex(className, `\`); idx != -1 {
		return className[idx+1:]
	}
	return className
}

func isPropagatingFunc(name string) bool {
	switch normalizeName(name) {
	case "rawurldecode", "urldecode", "rawurlencode", "urlencode", "base64_decode", "base64_encode", "substr", "trim", "ltrim", "rtrim", "strtok", "parse_url", "wp_parse_url", "str_replace", "preg_replace", "dirname", "basename", "realpath", "maybe_serialize", "maybe_unserialize", "json_encode", "wp_json_encode", "json_decode", "array_merge", "array_intersect_key", "array_map", "array_filter", "implode", "join", "explode", "reset", "acf_get_array", "acfe_parse_types", "acfe_parse_args_r", "wp_parse_args", "shortcode_atts", "plugins_api", "wp_remote_retrieve_body", "esc_sql", "sanitize_sql_orderby", "sanitize_text_field", "sanitize_textarea_field", "sanitize_key", "sanitize_email", "sanitize_title", "sanitize_url", "wp_unslash", "wp_normalize_path", "esc_html", "esc_attr", "esc_url", "esc_url_raw", "wp_kses", "wp_kses_post",
		// stream readers carry the taint of their handle/source argument so that
		// fopen('php://input') -> fread()/fgets()/stream_get_contents() flows.
		"stream_get_contents", "fread", "fgets", "fgetss", "stream_get_line":
		return true
	default:
		return false
	}
}

func isHTMLOutputSafeFunc(name string) bool {
	switch normalizeName(name) {
	// HTML body / generic escapers. NOTE: bare wp_kses(... custom allowlist) is
	// intentionally excluded — a caller-supplied allowlist can still permit XSS
	// (e.g. <a href> enabling javascript: URLs); only wp_kses_post/wp_kses_data
	// use WordPress' known-safe allowlists.
	case "wp_kses_post", "wp_kses_data", "esc_html", "esc_html__", "esc_html_e", "esc_html_x",
		"esc_attr", "esc_attr__", "esc_attr_e", "esc_attr_x", "esc_textarea",
		"wp_strip_all_tags", "htmlspecialchars", "htmlentities",
		"sanitize_text_field", "sanitize_textarea_field", "sanitize_key", "sanitize_email", "sanitize_title", "sanitize_html_class":
		return true
	// URL-context escapers (and url-encoders): neutralize the request->output
	// reflected vector for href/src and query-string output.
	case "esc_url", "esc_url_raw", "sanitize_url", "rawurlencode", "urlencode", "http_build_query":
		return true
	// JS / JSON structured output: esc_js and json_encode/wp_json_encode produce
	// escaped or structured (non-HTML-injectable) output, which is the dominant
	// shape of AJAX responses (echo json_encode($data); wp_die();).
	case "esc_js", "json_encode", "wp_json_encode":
		return true
	// Attribute-flag helpers return a fixed token (' selected="selected"', ...)
	// derived from a comparison, never the compared value itself, so their
	// result cannot carry request taint into output.
	case "selected", "checked", "disabled", "wp_readonly":
		return true
	// Additional WordPress / WooCommerce escapers + strict-format coercers that
	// produce HTML-safe output (XSS context only; SQL/path/SSRF unaffected).
	case "esc_xml", "tag_escape", "sanitize_hex_color", "sanitize_hex_color_no_hash", "sanitize_mime_type",
		"wp_filter_nohtml_kses", "antispambot", "number_format", "number_format_i18n",
		"wc_clean", "wc_sanitize_tooltip", "wc_sanitize_textarea", "wc_strtolower", "wc_sanitize_taxonomy_name":
		return true
	default:
		return false
	}
}

func isHTMLUnsafeTransformFunc(name string) bool {
	switch normalizeName(name) {
	case "html_entity_decode", "htmlspecialchars_decode":
		return true
	default:
		return false
	}
}

func unsafeDeserializationFuncArgIndex(call *ast.ExprFuncCall) (int, string, string, bool) {
	name := normalizeName(identifierText(call.Name))
	switch name {
	case "unserialize":
		if unserializeUsesSafeClassRestriction(call.Args) {
			return -1, "", "", false
		}
		return 0, "unsafe-deserialization", unsafeDeserializationMessage, true
	case "maybe_unserialize":
		return 0, "unsafe-deserialization", unsafeDeserializationMessage, true
	default:
		return -1, "", "", false
	}
}

func unsafeUseFuncArgIndexes(name string) ([]int, string, string, bool) {
	switch normalizeName(name) {
	case "assert", "exec", "system", "passthru", "shell_exec", "popen", "proc_open", "pcntl_exec":
		return []int{0}, "unsafe-use", unsafeUseMessage, true
	case "create_function":
		return []int{1}, "unsafe-use", unsafeUseMessage, true
	default:
		return nil, "", "", false
	}
}

func unsafeDeserializationCallbackArgIndexes(call *ast.ExprFuncCall) ([]int, string, string, bool) {
	name := normalizeName(identifierText(call.Name))
	if len(call.Args) < 2 {
		return nil, "", "", false
	}
	callback := strings.ToLower(strings.TrimSpace(strings.Trim(literalString(argValue(call.Args[0])), `"'`)))
	callback = strings.TrimPrefix(callback, `\`)
	switch callback {
	case "unserialize", "maybe_unserialize":
	default:
		return nil, "", "", false
	}
	switch name {
	case "array_map":
		indexes := make([]int, 0, len(call.Args)-1)
		for i := 1; i < len(call.Args); i++ {
			indexes = append(indexes, i)
		}
		return indexes, "unsafe-deserialization", unsafeDeserializationMessage, true
	case "array_walk", "array_walk_recursive":
		return []int{0}, "unsafe-deserialization", unsafeDeserializationMessage, true
	default:
		return nil, "", "", false
	}
}

func unserializeUsesSafeClassRestriction(args []ast.Node) bool {
	if len(args) < 2 {
		return false
	}
	options, ok := argValue(args[1]).(*ast.ExprArray)
	if !ok {
		return false
	}
	for _, rawItem := range options.Items {
		item, ok := rawItem.(*ast.ArrayItem)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(literalString(item.Key)), "allowed_classes") {
			continue
		}
		value := argValue(item.Value)
		switch typed := value.(type) {
		case *ast.ExprConstFetch:
			if strings.EqualFold(identifierText(typed.Name), "false") {
				return true
			}
		}
	}
	return false
}

func isPropagatingMethod(name string) bool {
	switch strings.ToLower(strings.TrimPrefix(normalizeName(name), `\`)) {
	case "purify", "purify_html", "sanitize", "sanitize_text_field", "sanitize_key", "sanitize_email", "sanitize_title", "escape", "clean", "filter", "normalize", "esc_html", "esc_attr", "esc_url", "trim", "ltrim", "rtrim",
		"decode", "decrypt", "decode_message", "decrypt_message",
		"get_array_value", "get_string_value", "get_integer_value", "encode_json", "convert_fileurl_to_filepath", "tostring", "to_string":
		return true
	default:
		return isPropagatingFunc(name)
	}
}

func isTemplatePathHelper(name string) bool {
	switch normalizeName(name) {
	case "locate_template":
		return true
	default:
		return false
	}
}

func structuralPropagatingArgIndexes(name string, argc int) []int {
	if argc <= 0 {
		return nil
	}
	name = normalizeName(name)
	switch name {
	case "array_merge":
		out := make([]int, 0, argc)
		for i := 0; i < argc; i++ {
			out = append(out, i)
		}
		return out
	case "json_encode", "json_decode", "maybe_serialize", "maybe_unserialize":
		return []int{0}
	case "array_map":
		out := make([]int, 0, argc-1)
		for i := 1; i < argc; i++ {
			out = append(out, i)
		}
		return out
	case "array_filter":
		return []int{0}
	case "array_intersect_key":
		return []int{0}
	case "implode", "join":
		if argc > 1 {
			return []int{1}
		}
		return []int{0}
	case "shortcode_atts":
		if argc > 1 {
			return []int{1}
		}
		return []int{0}
	case "wp_parse_args", "acf_parse_args", "acfe_parse_args_r":
		out := make([]int, 0, 2)
		for _, idx := range []int{0, 1} {
			if idx < argc {
				out = append(out, idx)
			}
		}
		return out
	default:
		if isPropagatingFunc(name) {
			return []int{0}
		}
		return nil
	}
}

func builtinSinkByFunc(name string) (int, string, string, string, bool) {
	switch normalizeName(name) {
	case "file_get_contents":
		return 0, "read", "request-path-read-delete", requestPathReadDeleteMessage, true
	case "readfile":
		return 0, "read", "request-path-read-delete", requestPathReadDeleteMessage, true
	case "fopen":
		return 0, "open", "request-path-read-delete", requestPathReadDeleteMessage, true
	case "unlink":
		return 0, "delete", "request-path-read-delete", requestPathReadDeleteMessage, true
	case "rmdir":
		return 0, "delete", "request-path-read-delete", requestPathReadDeleteMessage, true
	case "wp_delete_file":
		return 0, "delete", "request-path-read-delete", requestPathReadDeleteMessage, true
	case "file":
		return 0, "read", "request-path-read-delete", requestPathReadDeleteMessage, true
	case "parse_ini_file":
		return 0, "read", "request-path-read-delete", requestPathReadDeleteMessage, true
	case "simplexml_load_file":
		return 0, "read", "request-path-read-delete", requestPathReadDeleteMessage, true
	default:
		return -1, "", "", "", false
	}
}

// builtinSSRFSinkByFunc returns the URL-argument index for outbound-request
// functions, so request-controlled URLs can be flagged as SSRF. (wp_remote_*
// are also response SOURCES; this models their URL arg as a sink — the two are
// emitted independently.) esc_url/sanitize_url do NOT prevent SSRF.
func builtinSSRFSinkByFunc(name string) (int, bool) {
	switch normalizeName(name) {
	case "wp_remote_get", "wp_remote_post", "wp_remote_request", "wp_remote_head", "wp_remote_fopen", "wp_remote_retrieve_body_from_url",
		"wp_safe_remote_get", "wp_safe_remote_post", "wp_safe_remote_request", "wp_safe_remote_head":
		return 0, true
	default:
		return -1, false
	}
}

// leadingLiteralPrefix returns the constant string prefix of a (possibly
// concatenated/interpolated) expression and whether the WHOLE node is a literal.
func leadingLiteralPrefix(node ast.Node) (string, bool) {
	switch t := node.(type) {
	case *ast.ScalarString:
		return t.Value, true
	case *ast.ExprBinaryOpConcat:
		lp, lwhole := leadingLiteralPrefix(t.Left)
		if !lwhole {
			return lp, false
		}
		rp, rwhole := leadingLiteralPrefix(t.Right)
		return lp + rp, rwhole
	case *ast.ScalarInterpolatedString:
		var b strings.Builder
		for _, raw := range t.Parts {
			if part, ok := raw.(*ast.InterpolatedStringPart); ok {
				b.WriteString(part.Value)
				continue
			}
			return b.String(), false
		}
		return b.String(), true
	default:
		return "", false
	}
}

// requestControlsURLHost reports whether the tainted part of a URL expression
// can influence the HOST (true SSRF), as opposed to only a path/query appended
// after a constant scheme://host prefix (NOT SSRF). A URL whose constant prefix
// already contains a complete authority ("http://fixed.example/..." with a
// /, ?, or # after the host) has a fixed host.
func requestControlsURLHost(node ast.Node) bool {
	prefix, _ := leadingLiteralPrefix(node)
	low := strings.ToLower(strings.TrimSpace(prefix))
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(low, scheme) {
			rest := low[len(scheme):]
			return strings.IndexAny(rest, "/?#") < 0
		}
	}
	return true
}

// builtinRedirectHeaderSinkByFunc returns the sink arg index, rule, and message
// for redirect / raw-header functions. wp_safe_redirect is excluded (it host-
// validates by design). esc_url/esc_url_raw/wp_validate_redirect neutralize the
// redirect sub-class (modeled as output-safe / propagating sanitizers).
func builtinRedirectHeaderSinkByFunc(name string) (int, string, string, bool) {
	switch normalizeName(name) {
	case "wp_redirect":
		return 0, "wp-open-redirect", openRedirectMessage, true
	case "header":
		return 0, "wp-header-injection", headerInjectionMessage, true
	default:
		return -1, "", "", false
	}
}

func builtinReadReturnsContent(name string) bool {
	switch normalizeName(name) {
	case "file_get_contents", "file", "parse_ini_file", "simplexml_load_file":
		return true
	default:
		return false
	}
}

func fileUploadSinkArgIndexesByFunc(name string) ([]int, bool) {
	switch normalizeName(name) {
	case "move_uploaded_file", "copy", "rename", "stream_copy_to_stream":
		return []int{0, 1}, true
	case "unzip_file":
		// unzip_file($file, $to): both the archive and the extraction destination
		// are sink-relevant (zip-slip / request-controlled extraction target).
		return []int{0, 1}, true
	case "file_put_contents":
		return []int{0, 1}, true
	case "fwrite", "fputs":
		return []int{1}, true
	case "wp_upload_bits":
		return []int{0, 2}, true
	case "download_url":
		return []int{0}, true
	case "wp_handle_sideload", "wp_handle_upload", "media_handle_sideload":
		return []int{0}, true
	default:
		return nil, false
	}
}

func fileUploadReturnArgIndexByFunc(name string) (int, bool) {
	switch normalizeName(name) {
	case "wp_handle_upload", "wp_handle_sideload":
		return 0, true
	default:
		return -1, false
	}
}

func actionSinkModelByFunc(name string) (actionSinkModel, bool) {
	switch normalizeName(name) {
	case "update_option", "add_option", "update_site_option", "add_site_option":
		return actionSinkModel{
			ArgIndexes: []int{0, 1},
			RuleID:     "wp-request-sensitive-action-without-cap-check",
			Message:    requestSensitiveActionMessage,
		}, true
	case "add_post_meta", "update_post_meta":
		return actionSinkModel{
			ArgIndexes: []int{1, 2},
			RuleID:     "wp-request-sensitive-action-without-cap-check",
			Message:    requestSensitiveActionMessage,
		}, true
	case "add_user_meta", "update_user_meta", "delete_user_meta",
		"add_term_meta", "update_term_meta", "delete_term_meta",
		"add_comment_meta", "update_comment_meta", "delete_comment_meta":
		// object id + key (+ value) are all request-relevant: an attacker can
		// choose whose meta is written (IDOR) and what is written. The
		// wp_capabilities/level key is intercepted earlier as a privilege sink.
		return actionSinkModel{
			ArgIndexes: []int{0, 1, 2},
			RuleID:     "wp-request-sensitive-action-without-cap-check",
			Message:    requestSensitiveActionMessage,
		}, true
	case "wp_insert_post", "wp_update_post":
		return actionSinkModel{
			ArgIndex: 0,
			RuleID:   "wp-request-sensitive-action-without-cap-check",
			Message:  requestSensitiveActionMessage,
		}, true
	case "wp_create_user", "wp_insert_attachment":
		return actionSinkModel{
			ArgIndexes: []int{0, 1, 2},
			RuleID:     "wp-request-sensitive-action-without-cap-check",
			Message:    requestSensitiveActionMessage,
		}, true
	case "delete_option", "delete_site_option", "delete_network_option",
		"wp_delete_post", "wp_trash_post", "wp_delete_attachment",
		"wp_delete_user", "wp_delete_comment", "wp_delete_term", "switch_to_blog":
		return actionSinkModel{
			ArgIndex: 0,
			RuleID:   "wp-request-sensitive-action-without-cap-check",
			Message:  requestSensitiveActionMessage,
		}, true
	case "activate_plugin", "deactivate_plugins", "delete_plugins", "uninstall_plugin":
		return actionSinkModel{
			ArgIndex: 0,
			RuleID:   "wp-request-sensitive-action-without-cap-check",
			Message:  requestSensitiveActionMessage,
		}, true
	default:
		return actionSinkModel{}, false
	}
}

func builtinMethodSink(name string) (int, string, string, string, bool) {
	switch strings.ToLower(name) {
	case "set_role", "add_role", "add_cap":
		return 0, "call", "wp-request-tainted-privilege-mutation", privilegeMutationMessage, true
	case "get_contents", "delete":
		if strings.ToLower(name) == "delete" {
			return 0, "delete", "request-path-read-delete", requestPathReadDeleteMessage, true
		}
		return 0, "read", "request-path-read-delete", requestPathReadDeleteMessage, true
	default:
		return -1, "", "", "", false
	}
}

func fileUploadSinkArgIndexesByMethod(name string) ([]int, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "put_contents", "move", "copy":
		return []int{0, 1}, true
	case "extract", "extractto":
		// ZipArchive::extractTo($destination) and archive ->extract($path):
		// request-controlled extraction destination is a zip-slip / RCE sink.
		return []int{0}, true
	default:
		return nil, false
	}
}

func fileUploadSinkMethodMatchesMethodCall(name string, call *ast.ExprMethodCall, current callable, e *engine) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "extract", "extractto":
		return archiveLikeReceiverMethodCall(call, current, e)
	default:
		return true
	}
}

func fileUploadSinkMethodMatchesCall(name string, call *ast.ExprMethodCall, s *analysisState) bool {
	if s == nil {
		return false
	}
	return fileUploadSinkMethodMatchesMethodCall(name, call, s.current, s.engine)
}

func archiveLikeReceiverMethodCall(call *ast.ExprMethodCall, current callable, e *engine) bool {
	if call == nil {
		return false
	}
	if archiveLikeIdentifier(identifierText(call.Var)) {
		return true
	}
	if e == nil {
		return false
	}
	state := &analysisState{engine: e, current: current}
	if archiveLikeIdentifier(state.resolveClassExpr(call.Var)) {
		return true
	}
	for _, candidate := range e.resolveCallbackClassRefs(call.Var, current) {
		if archiveLikeIdentifier(candidate) {
			return true
		}
	}
	return false
}

func archiveLikeIdentifier(text string) bool {
	text = normalizeName(text)
	if text == "" {
		return false
	}
	return strings.Contains(text, "zip") || strings.Contains(text, "archive")
}

func actionSinkModelByMethod(name string) (actionSinkModel, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "set":
		return actionSinkModel{
			ArgIndex:          1,
			RuleID:            "wp-request-sensitive-action-without-cap-check",
			Message:           requestSensitiveActionMessage,
			RequireConfigLike: true,
		}, true
	case "install":
		return actionSinkModel{
			ArgIndex:             0,
			RuleID:               "wp-request-sensitive-action-without-cap-check",
			Message:              requestSensitiveActionMessage,
			RequireInstallerLike: true,
		}, true
	case "refund_payment", "cancel_subscription":
		return actionSinkModel{
			ArgIndex: 0,
			RuleID:   "wp-ajax-financial-action-without-cap-check",
			Message:  requestFinancialActionMessage,
		}, true
	default:
		return actionSinkModel{}, false
	}
}

func isConfigLikeReceiverClassName(className string) bool {
	className = normalizeName(className)
	return strings.Contains(className, "config") || strings.HasSuffix(className, "cfg") || strings.Contains(className, "settings")
}

func isInstallerLikeReceiverClassName(className string) bool {
	className = normalizeName(className)
	return strings.Contains(className, "upgrader") || strings.Contains(className, "installer")
}

func isInstallerLikeReceiverVarName(name string) bool {
	name = normalizeName(name)
	return strings.Contains(name, "upgrader") || strings.Contains(name, "installer")
}

func isUserLikeReceiverClassName(className string) bool {
	className = normalizeName(className)
	return className == "wp_user" || strings.Contains(className, "user")
}

func isUserLikeReceiverVarName(name string) bool {
	name = normalizeName(name)
	return strings.Contains(name, "user") || strings.Contains(name, "member")
}

func isConfigLikeReceiverVarName(name string) bool {
	name = normalizeName(name)
	return strings.Contains(name, "config") || strings.HasSuffix(name, "cfg") || strings.Contains(name, "settings")
}

func sqlExecutionFuncArgIndex(name string, argc int) (int, string, string, bool) {
	switch normalizeName(name) {
	case "mysql_query", "mysql_unbuffered_query":
		// query-first: mysql_query($query [, $link]).
		return 0, "tainted-sql-string", taintedSQLMessage, true
	case "mysqli_query", "mysqli_multi_query", "mysqli_real_query", "mysqli_send_query", "mysqli_prepare":
		// link-first: mysqli_query($link, $query).
		return linkFirstQueryArgIndex(argc), "tainted-sql-string", taintedSQLMessage, true
	case "pg_query", "pg_send_query", "sqlsrv_query":
		// link-first when a connection handle is passed, else query-first.
		return linkFirstQueryArgIndex(argc), "tainted-sql-string", taintedSQLMessage, true
	default:
		return -1, "", "", false
	}
}

// linkFirstQueryArgIndex returns the SQL-string argument index for database
// query functions whose connection/link handle is the first argument when
// present (mysqli_*, pg_*, sqlsrv_*). With a single argument the query is at
// index 0; otherwise it is at index 1.
func linkFirstQueryArgIndex(argc int) int {
	if argc >= 2 {
		return 1
	}
	return 0
}

func sqlExecutionMethodArgIndex(name string) (int, string, string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "query", "get_var", "get_row", "get_col", "get_results", "execute", "executequery",
		"multi_query", "real_query", "send_query":
		return 0, "tainted-sql-string", taintedSQLMessage, true
	default:
		return -1, "", "", false
	}
}

func sqlIdentifierWriteMethodArgIndexes(name string) ([]int, string, string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "insert", "replace":
		return []int{1}, "tainted-sql-string", taintedSQLMessage, true
	case "update":
		return []int{1, 2}, "tainted-sql-string", taintedSQLMessage, true
	default:
		return nil, "", "", false
	}
}

func sqlTemplateMethodArgIndex(name string) (int, string, string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "prepare",
		"where_raw", "whereraw", "orwhereraw",
		"select_raw", "selectraw",
		"join_raw", "joinraw",
		"having_raw", "havingraw",
		"order_by_raw", "orderbyraw":
		return 0, "tainted-sql-string", taintedSQLMessage, true
	default:
		return -1, "", "", false
	}
}

func sqlTemplateConstructorArgIndex(className string) (int, string, string, bool) {
	switch strings.ToLower(strings.TrimPrefix(normalizeName(className), `\`)) {
	case "rawsql":
		return 0, "tainted-sql-string", taintedSQLMessage, true
	default:
		return -1, "", "", false
	}
}

func sqlClauseFilterModelForHook(hook string) (sqlClauseFilterModel, bool) {
	needle := strings.ToLower(strings.TrimPrefix(normalizeName(hook), `\`))
	for _, model := range coreSQLClauseFilters {
		if needle == model.Hook {
			return model, true
		}
	}
	return sqlClauseFilterModel{}, false
}

func uploadValidationFilterModelForHook(hook string) (uploadValidationFilterModel, bool) {
	needle := strings.ToLower(strings.TrimPrefix(normalizeName(hook), `\`))
	for _, model := range coreUploadValidationFilters {
		if needle == model.Hook {
			return model, true
		}
	}
	return uploadValidationFilterModel{}, false
}

// isSafePreparedSQLTemplate reports whether the given $wpdb->prepare-style
// template argument produces a sanitized SQL string. It is true when:
//
//   - sqlQueryString resolves the template to a recognized SELECT/INSERT/
//     UPDATE/DELETE/REPLACE statement,
//   - the resolved template contains at least one typed wpdb placeholder
//     (%d/%i/%f/%s), and
//   - the template AST contains only constant-like parts (string literals,
//     const/class-const fetches, and `$this->prop` / `$wpdb->prop` /
//     `self::$prop` property fetches) — no request variables, arbitrary
//     local variables, or function/method calls that could introduce taint.
//
// When true, prepare()'s result is treated as a sanitized SQL string: its
// value args are escaped by wpdb, and its template has no attacker-reachable
// dynamic parts. Callers wrap this around sqlExecutionOrigins/sink emission
// for `prepare` so WordPress plugins that use literal prepared queries with
// class-level table identifiers no longer surface as SQL-injection candidates.
func isSafePreparedSQLTemplate(template ast.Node) bool {
	if template == nil {
		return false
	}
	query := strings.TrimSpace(strings.ToLower(sqlQueryString(template)))
	if query == "" {
		return false
	}
	hasVerb := strings.HasPrefix(query, "select ") ||
		strings.HasPrefix(query, "insert ") ||
		strings.HasPrefix(query, "update ") ||
		strings.HasPrefix(query, "delete ") ||
		strings.HasPrefix(query, "replace ")
	if !hasVerb {
		return false
	}
	if !strings.Contains(query, "%d") &&
		!strings.Contains(query, "%i") &&
		!strings.Contains(query, "%f") &&
		!strings.Contains(query, "%s") {
		return false
	}
	return preparedSQLTemplatePartsAreConstantLike(template)
}

// preparedSQLTemplatePartsAreConstantLike walks a template expression and
// returns true only when every part is a compile-time-ish constant:
// scalar literals, const fetches, or property fetches on `$this`, `$wpdb`,
// or `self::`. Any variable, array fetch, function/method call, or unknown
// node poisons the walk and returns false.
func preparedSQLTemplatePartsAreConstantLike(node ast.Node) bool {
	switch typed := node.(type) {
	case nil:
		return true
	case *ast.ScalarString,
		*ast.ScalarInt,
		*ast.ScalarFloat,
		*ast.ScalarMagicConstDir,
		*ast.ScalarMagicConstFile,
		*ast.ScalarMagicConstLine,
		*ast.ScalarMagicConstClass,
		*ast.ScalarMagicConstFunction,
		*ast.ScalarMagicConstMethod,
		*ast.ScalarMagicConstNamespace,
		*ast.ScalarMagicConstTrait:
		return true
	case *ast.ExprConstFetch:
		return identifierText(typed.Name) != ""
	case *ast.ExprClassConstFetch:
		return identifierText(typed.Class) != "" && identifierText(typed.Name) != ""
	case *ast.ExprBinaryOpConcat:
		return preparedSQLTemplatePartsAreConstantLike(typed.Left) &&
			preparedSQLTemplatePartsAreConstantLike(typed.Right)
	case *ast.ScalarInterpolatedString:
		for _, rawPart := range typed.Parts {
			switch part := rawPart.(type) {
			case *ast.InterpolatedStringPart:
				continue
			case ast.Node:
				if !preparedSQLTemplatePartsAreConstantLike(part) {
					return false
				}
			default:
				return false
			}
		}
		return true
	case *ast.ExprPropertyFetch:
		return isSafePreparedTemplateReceiver(typed.Var)
	case *ast.ExprStaticPropertyFetch:
		return identifierText(typed.Class) != ""
	}
	return false
}

// isSafePreparedTemplateReceiver returns true only for `$wpdb`, whose property
// identifiers (`$wpdb->prefix`, `$wpdb->posts`, ...) are framework constants.
// `$this` is intentionally NOT trusted: a plugin property interpolated into a
// prepare() template (e.g. `{$this->table}`) can hold attacker-controlled data,
// and prepare()'s %s/%d placeholders do not protect identifier context. When a
// template interpolates a `$this->prop`, isSafePreparedSQLTemplate no longer
// short-circuits to "safe"; the value is taint-checked at the call site instead
// (an untainted property still resolves to no finding).
func isSafePreparedTemplateReceiver(node ast.Node) bool {
	variable, ok := node.(*ast.ExprVariable)
	if !ok {
		return false
	}
	name, ok := variable.Name.(string)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(name), "wpdb")
}

func isSQLSanitizingFunc(name string, args []ast.Node) bool {
	switch normalizeName(name) {
	case "intval", "absint":
		return true
	case "array_map":
		if len(args) == 0 {
			return false
		}
		mapper := strings.ToLower(strings.Trim(literalString(argValue(args[0])), `"'`))
		return mapper == "intval" || mapper == "absint"
	default:
		return false
	}
}

// isPathTraversalSanitizingFunc returns true for functions that strip directory
// components from a string, making it safe for inclusion in file paths.
func isPathTraversalSanitizingFunc(name string) bool {
	switch normalizeName(name) {
	case "basename", "wp_basename", "sanitize_file_name":
		return true
	default:
		return false
	}
}

// directOutputFuncArgIndexes returns the argument indexes a function emits to
// HTML output (a reflected/stored-XSS sink), or ok=false. printf/vprintf are
// format-aware: their value args are only output-relevant when the format
// performs a string conversion (%s), so printf("count: %d", $_GET['n']) — where
// the value is coerced to an integer — is not flagged.
func directOutputFuncArgIndexes(call *ast.ExprFuncCall) ([]int, bool) {
	argc := len(call.Args)
	switch normalizeName(identifierText(call.Name)) {
	case "printf":
		if argc == 0 || !printfFormatHasStringConversion(argValue(call.Args[0])) {
			return nil, false
		}
		out := make([]int, 0, argc)
		for i := 0; i < argc; i++ {
			out = append(out, i)
		}
		return out, true
	case "vprintf":
		if argc == 0 || !printfFormatHasStringConversion(argValue(call.Args[0])) {
			return nil, false
		}
		if argc > 1 {
			return []int{0, 1}, true
		}
		return []int{0}, true
	case "wp_die":
		// wp_die($message, ...) renders $message as HTML. (Its early-exit
		// control-flow guard role is modeled separately in wordpress_context.go.)
		if argc == 0 {
			return nil, false
		}
		return []int{0}, true
	default:
		return nil, false
	}
}

// printfFormatHasStringConversion reports whether a printf-family format string
// contains an unescaped %s conversion. A non-literal (possibly tainted) format
// is treated conservatively as output-relevant.
func printfFormatHasStringConversion(node ast.Node) bool {
	str, ok := node.(*ast.ScalarString)
	if !ok {
		return true
	}
	format := str.Value
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		j := i + 1
		if j < len(format) && format[j] == '%' {
			i = j
			continue
		}
		for j < len(format) && strings.IndexByte("0123456789$.-+ '#", format[j]) >= 0 {
			j++
		}
		if j < len(format) && format[j] == 's' {
			return true
		}
	}
	return false
}

func isDisclosureOutputFunc(name string) bool {
	switch normalizeName(name) {
	case "wp_send_json", "wp_send_json_success", "wp_send_json_error":
		return true
	default:
		return false
	}
}

func isDownloadOutputFunc(name string) bool {
	switch normalizeName(name) {
	case "readfile", "fpassthru":
		return true
	default:
		return false
	}
}

func isAttachmentDispositionHeaderValue(node ast.Node, current callable, e *engine) bool {
	value := strings.ToLower(strings.TrimSpace(literalStringForCallable(node, current, e)))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(literalString(node)))
	}
	if value == "" {
		return false
	}
	value = strings.Trim(value, `"'`)
	return strings.HasPrefix(value, "content-disposition:") && strings.Contains(value, "attachment")
}

func isRecordReadName(name string) bool {
	name = strings.ToLower(strings.TrimPrefix(normalizeName(name), `\`))
	if name == "" {
		return false
	}
	hasPrefix := false
	for _, prefix := range recordReadPrefixes {
		if strings.HasPrefix(name, prefix) {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return false
	}
	for _, marker := range recordReadMarkers {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func recordReadSelectorOrigins(name string, args []originSet) originSet {
	if !isRecordReadName(name) {
		return originSet{}
	}
	for _, origins := range args {
		if len(origins) != 0 {
			return origins
		}
	}
	return originSet{}
}

func argValue(node ast.Node) ast.Node {
	if arg, ok := node.(*ast.Arg); ok {
		return arg.Value
	}
	return node
}
