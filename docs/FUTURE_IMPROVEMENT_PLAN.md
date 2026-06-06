## give false-positive pattern

- Plugin: `give`
- Candidate: `2069`
- Cases:
  - `src/DonationForms/V2/Endpoints/FormActions.php:150` looks like request-controlled post status reaching `wp_update_post()`, but the REST route is registered with a concrete `permission_callback`.
  - The permission callback delegates through `UserPermissions::donationForms()->canEdit()` and ultimately requires `current_user_can( 'edit_give_forms' )`.
- Example:

```php
register_rest_route(
    self::NAMESPACE,
    '/form/(?P<id>\\d+)/actions',
    [
        'methods'             => WP_REST_Server::CREATABLE,
        'callback'            => [$this, 'updateItem'],
        'permission_callback' => [$this, 'permissionsCheck'],
    ]
);
```

- Precision idea: keep REST `permission_callback` capability evidence attached to the sink even when the callback is indirect through plugin permission wrapper classes, so capability-gated REST state changes are not promoted as missing-authorization findings.

## user-registration false-positive pattern

- Plugin: `user-registration`
- Candidate: `749`
- Cases:
  - `modules/membership/includes/Admin/Repositories/OrdersRepository.php:211` looks like unauthenticated SQL injection because the taint engine only sees request-derived input reaching `$wpdb()->prepare(...)`.
  - The actual sink is a prepared `SELECT` with a literal `%d` placeholder and no attacker-controlled SQL structure:
    - `SELECT * from $this->table WHERE subscription_id = %d ORDER BY ID DESC LIMIT 1`
- Example:

```php
public function get_order_by_subscription( $subscription_id ) {
	return $this->wpdb()->get_row(
		$this->wpdb()->prepare(
			"
			SELECT * from $this->table
			WHERE subscription_id = %d
			ORDER BY ID DESC LIMIT 1
		",
			$subscription_id
		)
	);
}
```

- Precision idea: when the direct engine sees `$wpdb->prepare()` with a fixed format string and typed placeholders like `%d`, keep that parameterization boundary attached to the downstream `get_row()/get_results()` sink so literal prepared queries do not survive as raw SQL injection candidates.

## wp-retina-2x REST route registration false-positive pattern

- Plugin: `wp-retina-2x`
- Candidate: `601`
- Cases:
  - `classes/rest.php:260` looks like unauthenticated REST file upload because `/replace` has `permission_callback => '__return_true'`.
  - The route is registered inside `rest_api_init()` only after `current_user_can( 'upload_files' )`; unauthenticated users and subscribers never receive the route for dispatch.
  - `check_upload()` repeats the `upload_files` check and enforces image validation before the `rename()` sink.
- Example:

```php
function rest_api_init() {
	if ( !current_user_can( 'upload_files' ) ) {
		return;
	}
	register_rest_route( $this->namespace, '/replace', array(
		'methods' => 'POST',
		'permission_callback' => '__return_true',
		'callback' => array( $this, 'rest_replace' )
	) );
}
```

- Precision idea: when route registration is itself control-dependent on a capability check, carry that registration guard into the route access model before classifying `__return_true` callbacks as public REST surfaces.

## wp-ulike fixed identifier mapping false-positive pattern

- Plugin: `wp-ulike`
- Candidate: `600`
- Cases:
  - `includes/functions/queries.php:370` looks like unauthenticated SQL injection because an AJAX-supplied `type` flows toward dynamic table and column identifiers.
  - The request `type` is passed through `wp_ulike_setting_type::get_instance()`, which maps supported values to fixed table/column names and falls back to the fixed post table/column tuple for unknown values.
  - The remaining attacker-controlled query values at the primary sink are constrained with `absint()` and `%d` placeholders.
- Example:

```php
$this->settings_type = wp_ulike_setting_type::get_instance( $this->data['type'] );
wp_ulike_get_likers_template(
	$this->settings_type->getTableName(),
	$this->settings_type->getColumnName(),
	$this->data['id'],
	$this->settings_type->getSettingKey()
);
```

- Precision idea: recognize small server-side enum mapper classes that turn request selectors into fixed SQL identifiers, and do not preserve identifier taint when the unknown/default branch also resolves to a fixed identifier tuple.

## secure-custom-fields ACF AJAX nonce/query helper false-positive pattern

- Plugin: `secure-custom-fields`
- Candidate: `744`
- Cases:
  - `includes/ajax/class-acf-ajax-query.php:55` looks like unauthenticated SQL injection because public ACF AJAX query endpoints accept request search/query parameters.
  - Real field endpoints call `acf_verify_ajax()` with a field key or the ACF nonce before querying.
  - The reported SQL helper `_acf_orderby_post_type()` escapes each post type before interpolation and is reached through WordPress query construction rather than a raw public SQL string.
- Example:

```php
if ( ! acf_verify_ajax( $nonce, $key ) ) {
	die();
}
acf_send_ajax_results( $this->get_ajax_query( $_POST ) );
```

- Precision idea: propagate `acf_verify_ajax()` as a nonce guard for ACF-style `wp_ajax_nopriv_acf/...` endpoints, and distinguish array reordering/search helper code from raw SQL execution when the sink is in a generic query base class.

## colibri-page-builder public Google Fonts cache false-positive pattern

- Plugin: `colibri-page-builder`
- Candidate: `85`
- Cases:
  - `src/GoogleFontsLocalLoader.php:152` looks like unauthenticated arbitrary upload because `wp_ajax_nopriv_colibri_get_google_font_file` reaches `file_put_contents()`.
  - The endpoint requires a per-font `security` value generated from WordPress salts and the exact font path.
  - The write path is fixed to `wp-content/uploads/colibri-google-fonts-cache/<md5(font)>.woff2`.
  - The file content is fetched from `https://fonts.gstatic.com/s/<font>`, not uploaded from the request.
- Example:

```php
$valid_nonce = $this->verifySecurityKey( $security_key, "{$this->font_file_action}_{$font_file}" );
$google_font_url = "{$this->google_font_url}/{$font_file}";
$content = wp_remote_retrieve_body( wp_remote_get( $google_font_url ) );
file_put_contents( $this->getLocalFontFilePath( $font_file ), $content );
```

- Precision idea: model hash-derived cache filenames plus fixed remote-origin fetches as constrained cache writes, not arbitrary upload/file-write candidates, when the request cannot supply raw file content or extension.

## backup-backup init-time custom capability gate pattern

- Plugin: `backup-backup`
- Candidate: `2`
- Cases:
  - Many `includes/ajax.php` backup/restore sinks look like authenticated arbitrary file write/delete, PHP object injection, SQL execution, and sensitive state changes.
  - The `wp_ajax_backup_migration` handler is registered only after `current_user_can('do_backups') || administrator-role` passes during plugin initialization.
  - The AJAX constructor also verifies `check_ajax_referer('backup-migration-ajax', 'nonce')`.
  - The plugin does not grant `do_backups` to lower roles by default.
- Example:

```php
if (!current_user_can('do_backups') && !in_array('administrator', (array) $user->roles)) return;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	add_action('wp_ajax_backup_migration', [&$this, 'ajax']);
}
```

- Precision idea: carry init-time AJAX registration guards into all methods reachable through the registered dispatcher, and flag custom capabilities separately when the plugin does not assign them to low-privileged default roles.

## wp-job-manager metadata double-serialization false-positive pattern

- Plugin: `wp-job-manager`
- Candidate: `325`
- Cases:
  - `wp-job-manager-functions.php:1702` looks like PHP object injection because `job_manager_duplicate_listing()` copies raw postmeta rows and calls `maybe_unserialize()` on each `meta_value`.
  - A subscriber/job submitter can place a serialized-looking string such as `O:33:"CodexWPJMDuplicateListingPoiProbe":0:{}` into default text-field post meta through the front-end listing form.
  - The value is saved through `update_post_meta()`, and WordPress metadata storage double-serializes serialized-looking scalar strings before they reach the database.
  - At duplication time, one `maybe_unserialize()` unwraps the DB value into a string and does not recursively instantiate the object.
- Example:

```php
// Attacker-controlled text field saved through WordPress metadata API.
update_post_meta( $this->job_id, '_' . $key, $values[ $group_key ][ $key ] );

// Later raw copy path.
$post_meta = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, meta_value FROM {$wpdb->postmeta} WHERE post_id=%d", $post_id ) );
update_post_meta( $new_post_id, wp_slash( $meta_key ), wp_slash( maybe_unserialize( $meta_value ) ) );
```

- Precision idea: for POI candidates where attacker input reaches post/user/term/comment meta only through WordPress metadata APIs, treat serialized-looking scalar strings as double-serialized unless a raw SQL/write primitive can store the serialized object directly.

## customer-reviews-woocommerce plugin-owned comment meta deserialization pattern

- Plugin: `customer-reviews-woocommerce`
- Candidate: `326`
- Cases:
  - `includes/qna/class-cr-qna.php:608` and `:634` look like unauthenticated PHP object injection because `wp_ajax_nopriv_cr_vote_question` can trigger `maybe_unserialize()` on comment meta.
  - `includes/reviews/class-cr-reviews.php:902` and `:928` have the same shape through `wp_ajax_nopriv_cr_vote_review`.
  - The meta keys are written by the plugin as arrays of `$_SERVER['REMOTE_ADDR']` or registered user IDs via `update_comment_meta()`, not from attacker-supplied serialized bytes.
  - `includes/reviews/class-cr-reviews-media-download.php:99` unserializes review media meta, but the reviewed source writes that meta as `array( 'url' => esc_url_raw( ... ) )` behind order-secret REST review creation, while local uploads store attachment IDs under separate `*2` meta keys.
- Example:

```php
$unregistered_upvoters = get_comment_meta( $comment_id, 'cr_question_unreg_upvoters', true );
$unregistered_upvoters = maybe_unserialize( $unregistered_upvoters );
$unregistered_upvoters[] = $_SERVER['REMOTE_ADDR'];
update_comment_meta( $comment_id, 'cr_question_unreg_upvoters', $unregistered_upvoters );
```

- Precision idea: distinguish public triggers of deserialization from public writes of serialized bytes; when the same plugin owns all writes to the meta key and stores arrays/scalars through WordPress metadata APIs, classify as plugin-owned state rather than attacker-controlled POI unless a raw meta write path is found.

## wpdiscuz plugin-owned serialized cache false-positive pattern

- Plugin: `wpdiscuz`
- Candidate: `331`
- Cases:
  - `utils/class.WpdiscuzCache.php:128` looks like unauthenticated PHP object injection because `wp_ajax_nopriv_wpdLoadMoreComments` can reach `maybe_unserialize(file_get_contents($fileInfo["path"]))`.
  - The request influences cache selectors such as `postId`, `lastParentId`, `wpdType`, and sorting, but the path remains under `uploads/wpdiscuz/cache/comments/<post_id>/<md5(selectors)>_<last_parent_id>`.
  - Cache bytes are written by `WpdiscuzCache::setCache()` as `serialize(["commentList" => $commentList, "commentData" => $commentData])`.
  - `$commentList` comes from WordPress comment APIs and `$commentData` is plugin-generated pagination/count data. Attacker comment fields serialize as strings inside plugin-created `WP_Comment` objects; there is no public raw write to the cache file.
- Example:

```php
if (is_readable($fileInfo["path"]) && ($cache = maybe_unserialize(file_get_contents($fileInfo["path"]))) && is_array($cache)) {
    return $cache;
}

$data = ["commentList" => $commentList, "commentData" => $commentData];
file_put_contents($fileInfo["path"], serialize($data));
```

- Precision idea: for cache POI findings, require a public write of attacker-controlled serialized bytes to the exact cache file path. A public cache read plus plugin-owned `serialize()` write should not be ranked as object injection unless raw cache poisoning is reachable.

## tenweb-speed-optimizer critical CSS callback cache-write false-positive pattern

- Plugin: `tenweb-speed-optimizer`
- Candidate: `122`
- Cases:
  - `includes/OptimizerCache.php:153`, `:154`, and `:157` look like unauthenticated file writes because `wp_ajax_nopriv_two_set_critical` can eventually call `OptimizerCache::cache()`.
  - `includes/OptimizerCriticalCss.php:517` and `:634` look like request path read/delete because `createCriticalCSS()` reads and unlinks the uploaded temp file.
  - `includes/OptimizerUtils.php:2378` and `:2396` look like sensitive unauthenticated state changes in the same callback chain.
  - The callback requires `get_option('two_critical' . page_id) === $_POST['token']` before it processes `covered_css`; the token is generated server-side and sent to the 10Web service, not exposed to local unauthenticated visitors.
  - The alternate `two_update_critical=1&page_id=...` path fetches file content from the fixed 10Web performance API using the site's stored bearer token; local request input controls the page selector, not arbitrary file bytes.
  - `OptimizerCache::cache()` writes either a static PHP wrapper plus `.none` data, or fixed `.css` / `.json` cache files, so the flagged sinks do not become attacker-controlled PHP execution.
- Example:

```php
if (isset($_POST['token'], $_POST['page_id']) && get_option('two_critical' . sanitize_text_field($_POST['page_id'])) === $_POST['token']) {
    $uploadfile = $_FILES['covered_css']['tmp_name'];
    \TenWebOptimizer\OptimizerCriticalCss::createCriticalCSS($uploadfile, $triggerPostOptimizationTasks);
}
```

- Precision idea: model high-entropy service callback tokens stored in options as authorization gates for public callback endpoints, and distinguish fixed-origin remote cache refreshes from request-supplied arbitrary upload bytes.

## interactive-3d-flipbook plugin-owned custom-table serialization pattern

- Plugin: `interactive-3d-flipbook-powered-physics-engine`
- Candidate: `386`
- Cases:
  - `inc/post-pages.php:78` looks like public PHP object injection because `wp_ajax_nopriv_fb3d_send_post_pages` and related readers can trigger `unserialize()` on custom table rows.
  - The `wp_fb3d_pages` array fields are written through `serialize_page_records()`, which serializes plugin-built arrays before `insert_post_pages()` / `update_post_pages()`.
  - The editable source is built from JSON form data in `props_save()` and cast through field descriptors; there is no public raw serialized-byte writer to `page_source_data`, `page_thumbnail_data`, or `page_meta_data`.
  - For users below the plugin's editor level, page-layer HTML/JS/CSS fields are cleared before persistence.
- Example:

```php
if($d['type']=='%a') {
  $serialized['records'][$name] = serialize(isset($records[$name])? $records[$name]: $d['val']);
}

...

if($d['type']=='%a') {
  $un = unserialize($records[$name]);
}
```

- Precision idea: for custom plugin tables, distinguish public `unserialize()` read endpoints from attacker-controlled serialized-byte writes; if all writes pass through plugin-owned `serialize()` of arrays, classify as plugin-owned serialized state instead of POI.

## event-tickets guarded/internal sink false-positive cluster

- Plugin: `event-tickets`
- Candidate: `86`
- Cases:
  - `src/Tickets/Commerce/Gateways/PayPal/REST/On_Boarding_Endpoint.php:200` looks like unauthenticated sensitive option writes, but the public route first requires an opaque server-side PayPal signup hash generated from WordPress secrets and exposed only through admin onboarding/settings flows.
  - `common/src/Tribe/Ajax/Dropdown.php:290` looks like public dynamic dispatch, but the route requires the plugin dropdown nonce and only dispatches allowlisted sources.
  - `common/src/Tribe/Image/Uploader.php:167` looks like arbitrary file deletion, but it unlinks the temporary file returned by WordPress `download_url()`; local-file deletes require a plugin-code filter.
  - Multiple `maybe_unserialize()` findings read plugin-owned queue/order/ticket metadata written through plugin or WordPress APIs, not arbitrary serialized bytes from a public raw write.
  - SQL findings in repository, seating, and deprecated cache helpers are internal DSL/prepared-list patterns without a public raw request-to-SQL path.
- Example:

```php
$existing_hash = $signup->get_transient_hash();
$request_hash  = $request->get_param( 'hash' );

if ( $request_hash !== $existing_hash ) {
	$this->redirect_with( 'invalid-paypal-signup-hash', $return_url );
}

update_option( 'tickets_commerce_permissions_granted', $permissions_granted );
```

- Precision idea: model high-entropy server transient checks as authorization-like prerequisites when the attacker has no acquisition path, and downgrade public REST state-write findings where the route is part of a third-party OAuth/onboarding callback that also depends on external provider state.

## site-reviews shortcode option dynamic-dispatch false-positive pattern

- Plugin: `site-reviews`
- Candidate: `607`
- Cases:
  - `plugin/Controllers/Api/Version1/RestShortcodeController.php:27` looks like unauthenticated arbitrary method dispatch through `option`, but `get_items_permissions_check()` rejects non-logged-in users and validates the shortcode.
  - `plugin/Database/ShortcodeOptionManager.php` intentionally routes inaccessible option names through `__call()` into `get()`, then uses reflection to call only protected shortcode option methods.
  - The exposed protected methods return option lists such as assigned posts, terms, users, pagination modes, booleans, and review types; they are not code execution or arbitrary callback primitives.
  - Bundled Action Scheduler list-table SQL findings restrict `orderby` to known sortable columns, convert bulk IDs with `absint()`, and prepare/search-escape variable values.
- Example:

```php
if (!is_user_logged_in()) {
	return new \WP_Error('rest_forbidden_context', $error, [
		'status' => rest_authorization_required_code(),
	]);
}

$values = call_user_func([$manager, $args['option']], $args);
```

- Precision idea: when public REST route findings include a permission callback, prefer source-derived access over registration heuristics. For dynamic dispatch, distinguish arbitrary user-selected global callables from object-local option routers that only expose protected allowlist-like helper methods.

## accelerated-mobile-pages external-controller SQL trace false-positive pattern

- Plugin: `accelerated-mobile-pages`
- Candidate: `89`
- Cases:
  - `classes/class-ampforwp-photo-gallery-embed.php:121` and `:125` look like shortcode-render SQL injection because public shortcode attributes flow to `$controller->execute($params, ...)`.
  - The controller is not bundled in this plugin. It is loaded from `BWG()->plugin_dir . '/frontend/controllers/controller.php'`, which belongs to the separate Photo Gallery plugin.
  - The only local SQL in the wrapper fetches Photo Gallery shortcode text with `$wpdb->prepare("... WHERE id=%d", $params['id'])`.
  - Related stored-output findings are public renders of admin-controlled AMP settings/meta and not high-impact without a lower-privileged write primitive.
- Example:

```php
$shortcode = $wpdb->get_var($wpdb->prepare("SELECT tagtext FROM " . $wpdb->prefix . "bwg_shortcode WHERE id=%d", $params['id']));
require_once(BWG()->plugin_dir . '/frontend/controllers/controller.php');
$controller->execute($params, 1, $bwg);
```

- Precision idea: distinguish sinks inside the scanned plugin from delegated sinks in optional third-party plugin controllers. If the local wrapper only performs prepared lookups and passes data into an external plugin dependency, rank it as a dependency-review lead rather than a confirmed sink in the wrapper plugin.

## jetformbuilder fixed-template/admin-capability false-positive cluster

- Plugin: `jetformbuilder`
- Candidate: `92`
- Cases:
  - `includes/blocks/types/base.php:683` and `:705` look like unauthenticated path traversal, but both include fixed plugin template paths (`common/start-form-row.php`, `common/end-form-row.php`). The request-derived hidden-field value in the same render call is not used as the include path.
  - `modules/post-type/actions/import-action.php:82` looks like request-controlled file deletion, but the action is nonce-protected, requires `publish_posts`, and deletes the PHP-managed upload `tmp_name` after `wp_check_filetype_and_ext()` validation.
  - Onboarding `wp_insert_post()` findings in shortcode, Bricks, and block-editor builders all flow from `Use_Form_Endpoint::process()`, whose permission callback requires `publish_jet_fb_forms`; by default the plugin grants that custom capability only to users with `manage_options`.
  - `includes/blocks/conditional-block/render-state.php:218` is an option update reached through REST endpoints whose `check_permission()` requires `manage_options`.
- Example:

```php
public function has_permission(): bool {
	return current_user_can( 'publish_jet_fb_forms' );
}

$capability = apply_filters( 'jet-form-builder/capability/form', 'manage_options' );

if ( empty( $allcaps[ $capability ] ) ) {
	return $allcaps;
}
```

- Precision idea: treat hard-coded arguments to template resolver helpers as fixed paths even when request-tainted values exist in the same render method. For custom post type capabilities, resolve plugin `user_has_cap` grants back to the default base capability before ranking state-changing REST routes as lower-privileged.

## contact-form-entries shortcode/admin-owned data false-positive cluster

- Plugin: `contact-form-entries`
- Candidate: `761`
- Cases:
  - `includes/data.php:304`, `:353`, and `:375` look like public shortcode SQL injection, but `[vx-entries]` passes a fixed non-empty `$req` array to `get_entries()`, so search/status/type/user filters do not come from `$_REQUEST` in the shortcode render path.
  - `contact-form-entries.php:2542` looks like unauthenticated POI, but the serialized data is Ultimate Form Builder stored form metadata selected by an admin-authored shortcode `form-id`, not visitor-supplied bytes.
  - `contact-form-entries.php:1390` only deserializes lead detail values for records created before `2025-08-04 06:54:40 UTC`, blocking fresh attacker-created serialized entries on current installs.
  - `includes/plugin-pages.php:1197` and `:1222` are entry-maintenance file delete/upload paths behind plugin capabilities and admin nonces; the installer grants those caps only to administrators.
- Example:

```php
$req = array( 'start' => $start, 'vx_links' => 'false' );
$entries = $data->get_entries( $form_id, $limit, $req );

$old_lead = ! empty( $lead['created'] ) && strtotime( $lead['created'] ) < 1754290480 ? true : false;
if ( $old_lead && ! empty( $value ) ) {
	$value = maybe_unserialize( $value );
}
```

- Precision idea: distinguish admin-authored shortcode attributes from visitor-controlled request parameters. For legacy deserialization guards, model hard timestamp cutoffs as blocking current attacker creation unless there is a separate attacker path to set the row creation time.

## ultimate-addons-for-contact-form-7 admin-nonce/external-deserialization false-positive cluster

- Plugin: `ultimate-addons-for-contact-form-7`
- Candidate: `762`
- Cases:
  - `addons/database/database.php:675` looks like nopriv SQL injection/data exposure because `wp_ajax_nopriv_uacf7dp_get_table_data` reaches `$wpdb->get_results()`. The request `form_id` is forced through `intval()`, and the required `uacf7dp-nonce` is only localized on plugin admin screens registered with `manage_options`.
  - `addons/spam-protection/ultimate-spam-protection.php:306` is a public render `unserialize()`, but serialized bytes come from `http://ip-api.com/php/<ip>`. Ordinary request headers populate `HTTP_X_FORWARDED_FOR`, while the code checks `X_FORWARDED_FOR`; otherwise the source is `REMOTE_ADDR`. This leaves only external HTTP/MITM or service-compromise control, not direct web attacker control.
  - `addons/signature/inc/signature.php:114` runs on Contact Form 7 form save with an editor-panel nonce.
  - `admin/tf-options/classes/UACF7_Settings.php:1005` and `:1122` are settings import/font upload paths whose nonce is emitted on `manage_options` pages; uploads are limited to font extensions/MIME values.
  - `addons/database/database.php:716` is a file read helper used by an AJAX view path that checks `manage_options` before processing request table data.
- Example:

```php
wp_localize_script( 'uacf7dp-database-table-script', 'uACF7DP_Pram', array(
	'ajaxurl' => admin_url( 'admin-ajax.php' ),
	'nonce'   => wp_create_nonce( 'uacf7dp-nonce' ),
) );

$form_id = isset( $_POST['form_id'] ) && $_POST['form_id'] >= 0 ? intval( $_POST['form_id'] ) : 0;
$sql = sprintf( 'SELECT `fields_name` FROM `' . $wpdb->prefix . 'uacf7dp_data_entry` WHERE cf7_form_id = %d GROUP BY `fields_name`', $form_id );
```

- Precision idea: when a nopriv AJAX handler requires a nonce, track where that nonce is created and whether the script is localized only on admin screens with capability-gated menu pages. For `wp_remote_get()` to `unserialize()`, distinguish direct request-controlled response bodies from third-party HTTP response trust/MITM assumptions.

## wp-google-map-plugin fixed-shortcode/admin-router false-positive cluster

- Plugin: `wp-google-map-plugin`
- Candidate: `750`
- Cases:
  - `core/class.controller.php:115` looks like unauthenticated path traversal because the admin page router reads `$_GET['page']`, but the public shortcode path is fixed to `create_object('shortcode')->display('put-wpgmp', ...)`; visitors do not control the controller entity or view name.
  - Backend routing through `wpgmp_processor()` is registered by `add_menu_page()` / `add_submenu_page()` with plugin capabilities and caps are granted from `manage_options`, so the request-derived page slug is not public.
  - `wp_ajax_wpgmp_ajax_call` uses a frontend-localized nonce and can call public plugin methods for authenticated users, but it consumes the same `operation` key needed by model-level actions, blocking a clean subscriber-to-admin-model chain.
  - `core/class.initiate-core.php:55` includes template `.html` files using `template_type` plus sanitized `template_name`, but the endpoint is authenticated-only and no attacker-writable `.html` path into the plugin template tree was found.
  - Location import upload/delete findings require the backend `wpgmp-nonce`, run from capability-gated admin pages, accept CSV only, and delete plugin-managed upload paths.
- Example:

```php
$factoryObject = new WPGMP_Controller();
$viewObject    = $factoryObject->create_object( 'shortcode' );
$output        = $viewObject->display( 'put-wpgmp', $sanitized_atts );

function wpgmp_ajax_call() {
	check_ajax_referer( 'fc-call-nonce', 'nonce' );
	$operation = sanitize_text_field( wp_unslash( $_POST['operation'] ) );
	$this->$operation( wp_unslash( $_POST ) );
}
```

- Precision idea: separate shortcode-render constants from admin router variables when both reach a shared controller include sink. For dynamic dispatchers, model whether one request parameter is reused for two different dispatch layers before treating it as an exploitable chain.

## uncanny-automator nonce-only loopback/admin-capability false-positive cluster

- Plugin: `uncanny-automator`
- Candidate: `1206`
- Cases:
  - `src/core/actionify-triggers/class-trigger-arguments.php:66` looks like unauthenticated PHP object injection because `wp_ajax_nopriv_automator_trigger_engine_process_trigger` reaches `maybe_unserialize( base64_decode( $_POST['item'] ) )`. The handler requires `wp_verify_nonce( $nonce, 'automator_trigger_engine_process_trigger' )`, and the only source occurrence of `wp_create_nonce( 'automator_trigger_engine_process_trigger' )` is inside the plugin's own non-blocking loopback sender `Trigger_Queue::safe_process()`. No public localization or response path exposes that nonce.
  - `src/core/services/rest/endpoint/log-endpoint/queries/loop-logs-queries.php:163` and `resources/action-logs-resources.php:1009` are REST log readers behind `\Uncanny_Automator\Rest\Auth\Auth::verify_permission()`, which calls `current_user_can( automator_get_capability() )`; `automator_get_capability()` defaults to `manage_options`.
  - `src/core/automator-post-types/uo-recipe/class-recipe-post-rest-api.php` findings are all registered with `save_settings_permissions()`, requiring both a valid `wp_rest` nonce and `current_user_can( automator_get_capability() )`.
  - `src/core/admin/class-copy-recipe-parts.php:364`, `class-import-recipe.php:129`, and admin log SQL findings are admin-page flows with admin nonces or Automator admin menu capabilities.
  - Integration token-parser `maybe_unserialize()` sinks read plugin-managed recipe metadata or third-party plugin records; no lower-privileged raw serialized-byte writer into the selected values was found.
- Example:

```php
$body = array(
	'action' => 'automator_trigger_engine_process_trigger',
	'item'   => base64_encode( $this->packager->package( $item ) ),
	'nonce'  => wp_create_nonce( 'automator_trigger_engine_process_trigger' ),
);

if ( ! $nonce || ! wp_verify_nonce( $nonce, 'automator_trigger_engine_process_trigger' ) ) {
	wp_die( 'Invalid nonce' );
}

$package = $this->packager->unpack( base64_decode( $items ) );

function automator_get_capability() {
	return apply_filters( 'automator_capability', 'manage_options' );
}
```

- Precision idea: when a nopriv AJAX handler verifies a custom nonce, search all `wp_create_nonce()` occurrences for that action and distinguish loopback-only nonce creation from frontend localization. For dynamic capabilities that default to `manage_options`, avoid ranking as `custom_role` unless a plugin-owned setting or unauthenticated filter path lowers the capability.

## hummingbird-performance Critical CSS/cache helper false-positive cluster

- Plugin: `hummingbird-performance`
- Candidate: `339`
- Cases:
  - `core/class-filesystem.php:582` and `:555` look like unauthenticated file write because `Filesystem::write()` is reached from Critical CSS queue processing. The written path is produced by `Critical_Css::used_css_path($type)` under `wp-content/wphb-cache/critical-css/`, and `$type` comes from plugin page-type logic or `get_post_type($id) . '-' . $id`, not from raw request path bytes.
  - `core/modules/class-critical-css.php:437` reads the same plugin-owned Critical CSS file path; mobile selection only appends `-mobile` after checking existence.
  - `core/modules/class-critical-css.php:1354` deletes Critical CSS files only after `is_hb_critical_css_path()` confirms the path contains both `wphb-cache` and `critical-css`.
  - `core/class-filesystem.php:228`, `:236`, `:351`, and `:357` are cache-directory delete helpers. `HTTP_HOST` is used in cache-path selection, but the unauthenticated comment trigger still constrains the subpath to the approved comment's post permalink and does not create a clean arbitrary delete primitive.
  - Cross-sell REST install/activate findings are guarded by `current_user_can('install_plugins')` and `current_user_can('activate_plugins')` respectively.
  - Config import/upload and admin dynamic dispatch findings require `wphb-fetch` or admin action nonces plus `Utils::get_admin_capability()`, which defaults to `manage_options` or `manage_network`.
- Example:

```php
public function used_css_path( $type ) {
	return $this->get_critical_css_path() . '/' . $type . '-used.css';
}

public function check_permission( \WP_REST_Request $request ): bool {
	return $this->has_permission( $request, 'install_plugins' );
}
```

- Precision idea: model plugin helper sinks like `Filesystem::write()` with caller-specific path constructors before assigning request-path control. For cache purge helpers, distinguish host-header directory selection from arbitrary path deletion when the remaining path is produced from trusted permalink logic.

## woocommerce-ajax-filters custom-post save/public-AJAX association false positive

- Plugin: `woocommerce-ajax-filters`
- Candidate: `1282`
- Cases:
  - `berocket/includes/custom_post.php:344` was ranked as `ajax_nopriv` because plugin-level access evidence referenced an unrelated public product-loading AJAX route, but the sink belongs to `BeRocket_custom_post_class::wc_save_product_without_check()`.
  - The sink is reached from `add_action( 'save_post', array( $this, 'wc_save_product' ), 10, 2 )`, registered during custom-post admin initialization.
  - `wc_save_product()` calls `wc_save_check()` before `wc_save_product_without_check()`, and `wc_save_check()` requires the custom-post nonce emitted by the admin metabox.
- Example:

```php
add_action( 'save_post', array( $this, 'wc_save_product' ), 10, 2 );

if ( empty( $_REQUEST[$this->post_name . '_nonce'] )
	|| ! wp_verify_nonce( $_REQUEST[$this->post_name . '_nonce'], $this->post_name . '_check' ) ) {
	return false;
}

update_post_meta( $post_id, $this->post_name, $settings );
```

- Precision idea: do not attach plugin-level public AJAX evidence to class methods unless the public handler has a concrete call edge into the sink method. Treat `save_post`-only methods as admin/post-edit context when guarded by metabox nonces.

## wp-letsencrypt-ssl ACME challenge helper false positive

- Plugin: `wp-letsencrypt-ssl`
- Candidate: `1300`
- Cases:
  - `admin/le_ajax.php:90`, `:96`, and `:114` were ranked as authenticated request-controlled file upload/write because `wp_ajax_wple_admin_httpverify` reaches `file_put_contents()`.
  - The handler requires `wp_verify_nonce( $_POST['nc'], 'verifyhttprecords' )`. The nonce is rendered by `WPLE_Subdir_Challenge_Helper::HTTP_challenges_block()` on the plugin's `manage_options` admin page.
  - The file name and content are loaded from stored ACME challenge option data, sanitized with `sanitize_file_name()` and `esc_html()`, then written only under `.well-known/acme-challenge/`.
- Example:

```php
if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nc'])), 'verifyhttprecords')) {
	exit('Unauthorized');
}

$httpch = $opts['challenge_files'];
$chfile = sanitize_file_name($ch['file']);
$chval = esc_html($ch['value']);
file_put_contents($fpath . $chfile, trim($chval));
```

- Precision idea: for nonce-only AJAX file writes, trace nonce emitters to frontend versus admin-only pages, and avoid treating option-derived ACME challenge data as direct upload control.

## secure-custom-fields ACF admin/form helper false-positive cluster

- Plugin: `secure-custom-fields`
- Candidate: `885`
- Cases:
  - `includes/ajax/class-acf-ajax-query.php:55` is a base query helper that calls `get_results()`, but the base implementation returns an empty array and concrete public query handlers verify ACF field/global nonces before querying.
  - `includes/api/api-helpers.php:2419` is the basic ACF file-input upload helper. It requires a per-field `acf/file_uploader_nonce/<field_key>` nonce and uses WordPress `wp_handle_upload()`, so it does not provide arbitrary executable upload.
  - `includes/class-acf-internal-post-type.php:514`, `includes/local-json.php:464`, and `includes/local-json.php:492` are ACF internal post/local JSON admin flows behind the SCF admin capability, which defaults to `manage_options`.
  - `includes/blocks.php:832` and `pro/blocks-auto-inline-editing.php:97/:109` include server-registered block template paths, not raw request paths.
  - `includes/api/api-template.php:203` updates only the escaped-HTML admin notice log, and `includes/admin/tools/class-acf-admin-tool-import.php:170` reads PHP's uploaded JSON temp file after admin tool nonce and capability gates.
- Example:

```php
if ( empty( $_REQUEST['acf'][ $nonce_name ] ) || ! wp_verify_nonce( sanitize_text_field( $_REQUEST['acf'][ $nonce_name ] ), 'acf/file_uploader_nonce/' . $field_key ) ) {
	return;
}

$page = add_submenu_page( 'edit.php?post_type=acf-field-group', __( 'Tools', 'secure-custom-fields' ), __( 'Tools', 'secure-custom-fields' ), acf_get_setting( 'capability' ), 'acf-tools', array( $this, 'html' ) );

if ( wp_doing_ajax() && ( $ajax_capability !== false ) && ! current_user_can( $ajax_capability ) ) {
	return;
}
```

- Precision idea: distinguish ACF public form/file-input helper paths from arbitrary upload sinks by requiring field nonce and WordPress MIME enforcement, and keep server-registered block template includes separate from request-provided block preview data.

## auxin-elements frontend template include allowlist false positive

- Plugin: `auxin-elements`
- Candidate: `98`
- Cases:
  - `includes/elements/recent-posts-grid-carousel.php:1116` and `includes/elements/recent-products.php:587` were ranked as public path traversal/LFI because frontend AJAX load-more request data reaches callbacks that include template files.
  - The frontend nonce is intentionally public for load-more widgets, but `template_part_file` is checked against fixed allowlists before `auxin_get_template_file()` is included.
  - Related sensitive-action/read/deserialization findings in the same plugin are admin lifecycle hooks, admin nonce/capability flows, or WordPress.org plugin-info response parsing rather than raw attacker-controlled data.
- Example:

```php
$acceptedTemplateFiles = apply_filters( 'auxin_recent_posts_accepted_template_files', [
	'theme-parts/entry/post-column',
	'theme-parts/entry/post-flip',
	'theme-parts/entry/post-land',
	'theme-parts/entry/post-tile',
	'theme-parts/entry/post',
	'woocommerce/content-product'
]);

if ( ! in_array( $template_part_file, $acceptedTemplateFiles ) ) {
	return;
}

include auxin_get_template_file( $template_part_file, '', $extra_template_path );
```

- Precision idea: when request data reaches a template include through widget attributes, preserve same-function allowlist checks and treat filter-extensible allowlists as not attacker-controlled unless a public filter-registration path is found.

## sina-extension-for-elementor blogpost layout include false positive

- Plugin: `sina-extension-for-elementor`
- Candidate: `1180`
- Case:
  - `inc/sina-ext-hooks.php:259` was ranked as public path traversal/LFI because `$_POST['posts_data']` is JSON-decoded and `layout` is concatenated into `SINA_EXT_LAYOUT.'/blogpost/'.$data['layout'].'.php'` before `include realpath(...)`.
  - The `sina_load_more_posts` nonce is intentionally exposed by the frontend blogpost widget, so the AJAX endpoint is visitor-reachable.
  - The include is immediately guarded by `if ( 'grid' == $data['layout'] || 'list' == $data['layout'] )`, reducing the reachable include target to the bundled `grid.php` and `list.php` templates.
- Example:

```php
$data = sanitize_text_field( $_POST['posts_data'] );
$data = json_decode(stripslashes($data), true);

if ( 'grid' == $data['layout'] || 'list' == $data['layout']):
	include realpath( SINA_EXT_LAYOUT.'/blogpost/'.$data['layout'].'.php' );
endif;
```

- Precision idea: preserve exact same-variable literal guards adjacent to include sinks, especially widget layout selectors with small literal allowlists.

## woocommerce-ajax-filters framework/admin helper false-positive cluster

- Plugin: `woocommerce-ajax-filters`
- Candidate: `1181`
- Cases:
  - `berocket/includes/libraries.php:22` was ranked as public path traversal because `BeRocket_framework_libraries::__construct()` includes `$library_file`, but `$libraries` comes from a hardcoded `$active_libraries` array plus WordPress filters, not request data.
  - `addons/custom_postmeta/postmeta.php:301`, `:312`, and `:327` were ranked as PHP object injection because product meta values reach `maybe_unserialize()`. Authenticated AJAX can choose the custom postmeta key for display, but the value is stored product postmeta, not request-injected serialized data.
  - `berocket/includes/custom_post.php:344`, `berocket/includes/updater.php:600`, and `includes/wizard.php:488` are `save_post`, account page, or setup wizard state updates behind core post-edit authorization, `manage_options`-derived plugin capabilities, and/or wizard/admin nonces.
  - `berocket/includes/admin_notices.php:178` fetches a code-defined admin notice image URL; no low-privileged request path controls `image.global`.
- Example:

```php
$this->active_libraries = apply_filters('bapf_active_libraries', array('addons', 'feature', 'tippy', 'popup', 'tutorial'));
$this->libraries = new BeRocket_framework_libraries($this->active_libraries, $this->info, $this->values, $this->get_option());

$post_metas = $wpdb->get_results($query);
return $this->build_terms_list($post_metas, $name, $exclude_same);
```

- Precision idea: require concrete request-to-argument call edges for framework constructors, distinguish selector/key control from value control for stored metadata deserialization, and avoid attaching unrelated public AJAX evidence to admin/save_post helpers.

## visual-portfolio guarded template include and low-value state-write false positives

- Plugin: `visual-portfolio`
- Candidate: `763`
- Cases:
  - `classes/class-templates.php:53` was ranked as frontend path traversal/LFI because layout style attributes flow into `include_template()` and then `include $template`.
  - `include_template()` rejects traversal with `validate_file()`, resolves the target with `realpath()`, and only includes files under fixed plugin/theme/pro template directories.
  - The request-derived style segments are `icons_selector` controls. `sanitize_icons_selector()` rejects traversal and enforces strict option allowlists for item style, filter style, sort style, pagination style, and pagination type.
  - `classes/class-archive-mapping.php:769`, `classes/class-ask-review.php:125`, and `classes/class-custom-post-meta.php:227` were ranked as missing-cap state writes, but they are admin permalink nonce handling, cosmetic review-notice dismissal, and core `save_post` meta handling respectively.
- Example:

```php
if ( validate_file( $template_name ) !== 0 ) {
	return;
}

$real_path = realpath( $template );
if ( $real_path && self::is_allowed_template_path( $real_path ) ) {
	include $template;
}
```

```php
if ( ! empty( $valid_options ) && ! in_array( $attribute_string, $valid_options, true ) ) {
	$attribute = self::reset_control_attribute_to_default( $attribute, $control );
}
```

- Precision idea: preserve `validate_file()` plus `realpath()` allowed-root guards for template includes, and avoid promoting nonce-protected cosmetic/admin notice state updates or core post-save meta callbacks as high-impact authorization issues without a lower-privileged acquisition path and security-relevant state.

## woo-product-filter module/table framework false positives and stale-version derived issue

- Plugin: `woo-product-filter`
- Candidate: `764`
- Cases:
  - `classes/modInstaller.php:57` was ranked as path traversal/LFI because module metadata reaches `require $moduleLocationDir . $module['code'] . '/mod.php'`. The reviewed call path is module install/loading metadata, with default module codes seeded from hardcoded installer values and no low-privileged request path to create an arbitrary module code or external module directory.
  - `classes/utils.php:100` was ranked as file read because `simplexml_load_file($path)` is reachable from module installation helpers. The path is built internally as the plugin directory plus `install.xml`, not user-controlled request input.
  - `classes/frame.php:443` was ranked as path traversal/LFI because table names reach `require $tablesDir . $tableName . '.php'`. `_extractTables()` enumerates bundled table directories and passes discovered filenames, not request-controlled table names.
  - An adjacent derived unauthenticated destructive `clear` action reproduced on queued source version `3.1.1`, but current WordPress.org `3.1.6` blocks it with HTTP `403` and leaves `wp_wpf_filters` unchanged. Treat stale queued plugin copies as needing a latest-release validation gate before packaging.
- Example:

```php
DbWpf::query("INSERT INTO `@__modules` (id, code, active, type_id, label) VALUES
	(NULL, 'adminmenu',1,1,'Admin Menu'),
	(NULL, 'woofilters',1,1,'woofilters'),
	(NULL, 'overview',1,1,'overview');");

$locations['xmlPath'] = $locations['plugDir'] . DS . 'install.xml';
$modules = self::_getModulesFromXml($locations['xmlPath']);

while ( ( $file = readdir($mDirHandle) ) !== false ) {
	if ( is_file($tablesDir . $file) && strpos($file, '.php') ) {
		$this->_extractTable( str_replace('.php', '', $file), $tablesDir );
	}
}
```

- Precision idea: require concrete request-controlled writes into framework module/table registries before flagging dynamic module or table includes, keep internally constructed install XML reads separate from arbitrary file reads, and prefer latest-release replay for high-impact derived issues when the queue source version is stale.

## go-live-update-urls admin migration unserialize false positive

- Plugin: `go-live-update-urls`
- Candidate: `385`
- Case:
  - `src/Serialized.php:127` was ranked as unsafe deserialization because selected database rows are passed to `@unserialize()` during URL migration.
  - The trigger path is the Tools admin form (`src/Admin.php`) or internal `Core::update()` helper. The form validates `go-live-update-urls/nonce/update-tables`, and the nonce is rendered only on a Tools page registered with the plugin admin capability, defaulting to `manage_options`.
  - No public, subscriber, AJAX, REST, shortcode, or block-render route was found to call `Database::update_the_database()` or expose the nonce.
- Example:

```php
add_submenu_page( self::PARENT_MENU, 'Go Live Update Urls', 'Go Live', $this->get_admin_capability(), self::NAME, [ $this, 'admin_page' ] );

if ( ! isset( $_POST[ static::NONCE ] ) || false === wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST[ static::NONCE ] ) ), static::NONCE ) ) {
	wp_die( esc_html__( 'Ouch! That hurt! You should not be here!', 'go-live-update-urls' ) );
}

$clean = $this->replace_tree( @unserialize( $row->{$column} ) );
```

- Precision idea: do not attach generic `init` POST handling to public reachability when the only action is gated by an admin-page nonce and the nonce source is a `manage_options` submenu page. Model admin migration utilities as admin-triggered unless a concrete low-privilege nonce acquisition or trigger path exists.

## download-monitor stored download/template and admin/API-gated sink false positives

- Plugin: `download-monitor`
- Candidate: `120`
- Cases:
  - `src/DownloadHandler.php:1182` was ranked as request-controlled file read because public download requests eventually call `fopen($file, 'rb')`. The path is selected from stored `dlm_download_version` mirror metadata, and `DLM_Download::set_version()` rejects `v=<version_id>` unless the version belongs to the requested download.
  - `src/RestAPI/class-dlm-download-rest.php:287` was ranked as a sensitive metadata update without a clear cap check. The download/version REST routes explicitly use `DLM_Rest_API::check_api_rights()`, which requires matching `x_dlm_api_key` and `x_dlm_api_secret` values from the `dlm_api_keys` table; the legacy `__call()` MD5 option fallback is not the permission callback for these routes.
  - `src/TemplateHandler.php:117` was ranked as LFI because a resolved `$template` is included. Attacker-facing callers use static slugs, sanitize the `$name` with `sanitize_file_name()`, and pass an empty custom directory; non-empty custom directories are fixed plugin template directories.
  - `src/AjaxHandler.php:293` was ranked as a missing-capability metadata write. The AJAX action is nonce-gated by `add-file`, and that nonce is emitted only on the `dlm_download` edit metabox, whose CPT capabilities map to `manage_downloads`.
- Example:

```php
if ( $version->get_download_id() == $this->get_id() ) {
	$this->version = $version;
}

register_rest_route(
	'download-monitor/v1',
	'/download/(?P<id>\d+)',
	array(
		'permission_callback' => array( $dlm_rest_api, 'check_api_rights' ),
	)
);

$name = sanitize_file_name( $name );
include $template;
```

- Precision idea: distinguish public reads of stored administrator-configured download files from arbitrary path reads, propagate parent-object checks on version selectors, bind REST route permission callbacks instead of fallback `__call()` methods, and require user-controlled custom directory or unsanitized slug/name flow before ranking template helpers as LFI.

## ays-popup-box shortcode SQL and nopriv admin AJAX false positives

- Plugin: `ays-popup-box`
- Candidate: `1160`
- Cases:
  - `includes/class-ays-pb-data.php:87` and `includes/class-ays-pb-data.php:64` were ranked as shortcode-render SQL injection because shortcode attributes reach helper methods that concatenate IDs into SQL. The actual shortcode callbacks normalize IDs with `absint( sanitize_text_field(...) )` before calling the helpers.
  - `admin/partials/settings/popup-box-settings-actions.php:14` was ranked as public SQL injection because frontend rendering calls `ays_get_setting()`. Public callers pass hardcoded keys such as `options`; no request-controlled `$meta_key` path was found.
  - Startup review found `wp_ajax_nopriv_ays_pb_install_plugin`, `wp_ajax_nopriv_ays_pb_activate_plugin`, and `wp_ajax_nopriv_ays_pb_change_status`. Install/activate require an admin-only nonce and `install_plugins`/`activate_plugins`; status toggling requires a nonce generated inside the `manage_options` list table.
- Example:

```php
$id = (isset($attr['id']) && $attr['id'] != '') ? absint( sanitize_text_field($attr['id']) ) : null;
$results = Ays_Pb_Data::get_category_by_id($id);

$settings_options = $this->settings->ays_get_setting('options');

check_ajax_referer( $this->plugin_name . '-install-plugin-nonce', sanitize_key($_REQUEST['_ajax_nonce']) );
if (!self::ays_pb_can_install($type)) {
	wp_send_json_error($generic_error);
}
```

- Precision idea: carry caller-side numeric normalization into helper SQL sinks, distinguish hardcoded frontend setting lookups from request-controlled keys, and do not rank `wp_ajax_nopriv_*` as attacker-doable when the handler requires an admin-only nonce and a filesystem/plugin-management capability.

## booking numeric-list SQL, option unserialize, and captcha file false positives

- Plugin: `booking`
- Candidate: `1165`
- Cases:
  - `includes/_capacity/create_booking.php:1028`, `:1039`, `:1045`, and `:1136` were ranked as public SQL injection. The edit path gets the booking id from a booking-hash lookup and casts it to `(int)`, while insert/update/date values are passed through `$wpdb->prepare()` or `wpbc_prepare_date_row()`.
  - `core/wpbc-dates.php:323`, `core/wpbc-dates.php:826`, `includes/_capacity/capacity.php:172`, `includes/_capacity/resource_support.php:142`, and related booking-listing SQL sinks were ranked as request-controlled SQL. The interpolated ids are normalized by `wpbc_clean_digit_or_csd()` / `wpbc_sanitize_digit_or_csd()`, which rebuild comma-separated lists from `intval()` components.
  - `includes/page-bookings/bookings__actions.php:366`, `core/sync/wpbc-gcal-class.php:423`, and form-simple unserialize sinks were ranked as object injection. The inputs are administrator-controlled plugin options; no lower-privilege or public option write path was found. The generic option saver requires `manage_options`.
  - `js/captcha/captcha.php:189` and `:223` were ranked as request-path file write/read. The prefix is server-generated with `wp_rand()`, filenames are sanitized under a fixed captcha tmp directory, and answer-file content is server-generated salt/HMAC data.
- Example:

```php
$booking_id = (int) $create_params['is_edit_booking'];
$sql = $wpdb->prepare( "UPDATE {$wpdb->prefix}booking SET {$sql_prepare_arr['set']} WHERE booking_id={$booking_id};", $sql_prepare_arr['value'] );

$result[] = intval( $check_element );
$result = implode( ',', $result );

$prefix = wp_rand();
$captcha_instance->generate_image( $prefix, $word );
```

- Precision idea: model numeric-list sanitizers as integer-list safe for `IN (...)` clauses, propagate booking-hash-to-int constraints, distinguish stored administrator options from request-controlled serialized data, and avoid file-path findings when the filename prefix and file content are generated server-side under a fixed directory.

## product-import-export-for-woo bounded import/export/log helper false positives

- Plugin: `product-import-export-for-woo`
- Candidate: `246`
- Cases:
  - `admin/modules/history/history.php:912` and `:916` were ranked as request-controlled file reads. The admin-init download path requires `Wt_Iew_Sh::check_write_access(WT_IEW_PLUGIN_ID_BASIC)`, a `.log` extension, `realpath()`, and a prefix check against the plugin log directory before `readfile()` / `fopen()`.
  - `admin/modules/history/history.php:311`, `:655`, `:688`, and `:695` were ranked as request-controlled deletes. Raw log delete has the same nonce/role and realpath root checks; history delete receives `absint()` ids and derives file paths from stored history records plus fixed module helpers.
  - `admin/modules/import/classes/class-import-ajax.php:176` / `:201` and `admin/modules/import/import.php:570` / `:584` were ranked as file upload/write. These flows are authenticated import actions, allow only import data extensions, and write generated filenames under `WP_CONTENT_DIR.'/webtoffee_import'`.
  - `admin/modules/history/history.php:542`, `:543`, `:554`, `:559`, `:703`, and `:836` were ranked as SQL injection. History filters use fixed column/format maps and `$wpdb->prepare()`, while ids are normalized as integers.
  - Banner/review option updates were ranked as sensitive actions, but they are nonce-gated low-value notice state changes and not privilege-changing.
- Example:

```php
if(Wt_Iew_Sh::check_write_access(WT_IEW_PLUGIN_ID_BASIC)) {
	$file_path = Wt_Import_Export_For_Woo_Basic_Log::get_file_path($file_name);
	$file_path = realpath($file_path);
	$real_log_dir = realpath(WP_CONTENT_DIR.'/webtoffee_iew_log');
	if($file_path && $real_log_dir && strpos($file_path, $real_log_dir) === 0 && file_exists($file_path)) {
		readfile($file_path);
	}
}

$history_id_arr = Wt_Iew_Sh::sanitize_item($history_id_arr, 'absint_arr');
$wpdb->query($wpdb->prepare("DELETE FROM {$tb} WHERE id IN(" . implode(",", array_fill(0, count($where_data), '%d')) . ")", $where_data));
```

- Precision idea: recognize plugin-local realpath root checks, generated import/log filenames, and fixed column maps as strong constraints. Separately, flag string-prefix directory checks without a separator as a lower-priority hardening note unless a reachable attacker-created sibling path exists.

## wp-health backup-script remote-service file primitive false positives

- Plugin: `wp-health`
- Candidate: `772`
- Cases:
  - `backup-script/Context.php:366`, `Context.php:375`, `Context.php:405`, `Cleanup.php:35`, `Cleanup.php:39`, `Cleanup.php:43`, `Cleanup.php:59`, `Cleanup.php:63`, and `DatabaseBackup.php:111` / `:123` were ranked as request-controlled file write/delete. These are inside the generated backup `cloner.php` flow; `backup-script/script.php` dies while the backup key is still a placeholder, and the generated file requires `hash_equals(UMBRELLA_BACKUP_KEY, $_GET['umbrella-backup-key'])` before executing backup actions.
  - `src/Controller/BackupV4/UploadModule.php:22` is a real dangerous upload/write primitive, including a branch that can write attacker-provided content under `ABSPATH` or the root backup module. The route is registered with `Controller::PERMISSION_WITH_SECRET_TOKEN`, and both REST and PHP execution paths require the WP Umbrella API key and hashed secret token.
  - Action Scheduler list-table SQL findings and datastore unserialize findings were vendor/admin or scheduler-internal surfaces without a public write path to the dangerous sink.
- Example:

```php
if (!hash_equals(UMBRELLA_BACKUP_KEY, $_GET['umbrella-backup-key'])) {
	$html->render('hash-not-equal');
	return;
}

'/v1/upload-module' => [
	'method' => 'POST',
	'class' => \WPUmbrella\Controller\BackupV4\UploadModule::class,
	'options' => [
		'permission' => Controller::PERMISSION_WITH_SECRET_TOKEN,
	],
],
```

- Precision idea: recognize generated backup-agent scripts with per-request key replacement as gated execution, propagate controller permission options into REST/PHP route callbacks, and distinguish trusted remote-service backup upload capabilities from public webshell upload surfaces.
### brizy admin-instantiated import and bounded editor helper false positives

- Plugin: `brizy`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `619`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/619-brizy-source-review.md`
- False-positive pattern:
  - `import/main.php:15` registers `wp_ajax_brizy-import-demo`, and `import/importer.php:716` copies an extracted demo attachment to uploads.
  - The registering object is instantiated at `editor.php:190-191` only when `( current_user_can( 'manage_options' ) && is_admin() ) || WP_CLI`, so lower-privileged AJAX requests never register the action.
  - `editor/block-screenshot-api.php:56-87` and `editor/screenshot/manager.php:35-56` are bounded by editor authorization, nonce/version checks, JPEG validation, UID validation, and fixed `.jpeg` paths.
  - `editor/storage/project.php:91` is a stored legacy metadata repair path, not direct request-to-`maybe_unserialize()`.
- Improvement idea:
  - Track conditional object instantiation as an action-registration guard when an AJAX action is added inside a class constructor.
  - Carry `current_user_can()` conditions from the caller that instantiates the class into the registered method's effective access level.
  - Distinguish bounded media/screenshot helper writes from arbitrary upload or path-write sinks when filename, extension, MIME, and destination directory are fixed.

### siteground-migrator migration-secret and internal queue false positives

- Plugin: `siteground-migrator`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `623`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/623-siteground-migrator-source-review.md`
- False-positive pattern:
  - `core/Files_Service/Files_Service.php:394` was ranked as a request-path file read. The public AJAX handler accepts `$_GET['path']`, but calls `Api_Service::authenticate( $maybe_path )` first; authentication requires stored `siteground_migrator_transfer_id`, stored `siteground_migrator_transfer_psk`, timestamp, and an `auth` hash that includes the requested path.
  - `core/Transfer_Service/Transfer_Service.php:479` was ranked as a sensitive option update without a capability check. The public status endpoint also calls `Api_Service::authenticate( stripcslashes( $_POST['data'] ) )` before status/progress writes.
  - `core/Background_Process/Siteground_WP_Background_Process.php:302` was ranked as unsafe deserialization. The deserialized option value is an internal background-process batch written by `save()` from fixed arrays in `Transfer_Service::run_background_processes()`, and the exposed background handler requires `check_ajax_referer( $this->identifier, 'nonce' )`.
  - The transfer token routes that set or reveal migration token material are REST routes gated by `current_user_can( 'manage_options' )`.
- Improvement idea:
  - Track custom secret-token authenticators when the sink is behind a required hash over request data plus stored secret options.
  - Propagate REST `permission_callback` capability checks into option writes that seed later AJAX-authenticated flows.
  - Distinguish framework/internal background queue deserialization from request-controlled PHP object injection when the only writer stores fixed queue item structures.

### learnpress profile/material/admin-helper false positives

- Plugin: `learnpress`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `333`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/333-learnpress-source-review.md`
- False-positive pattern:
  - `inc/rest-api/v1/frontend/class-lp-rest-profile-controller.php:565` and `:566` were ranked as unauthenticated upload writes. The REST routes require `get_current_user_id()`, use server-generated names, and write only image extensions under LearnPress profile upload directories.
  - `inc/rest-api/v1/frontend/class-lp-rest-material-controller.php:189` was ranked as file upload without a capability check. The permission callback allows only administrators or the `lp_teacher` author of the target item, and uploads are checked by extension/MIME before `wp_handle_upload()`.
  - `inc/settings/class-lp-settings-courses.php:30` was ranked as privilege mutation. The reachable save path is the LearnPress settings page and requires administrator capability plus the settings nonce before toggling teacher capabilities.
  - `inc/class-lp-helper.php:24` and `:32` were ranked as unsafe deserialization. The traced path reads LearnPress session/cache rows by a session key; guest cookies are not serialized payloads, and the legacy `$_COOKIE['LP']` unserialize code is commented out.
  - Template include and filesystem helper findings are generic helpers reached through bounded LearnPress template resolution or server-generated upload paths, not raw request-controlled filesystem paths.
- Improvement idea:
  - Propagate REST `permission_callback` results that use `get_current_user_id()`, post authorship, and role checks into upload/file/delete sink access levels.
  - Distinguish own-profile image uploads and teacher-owned material uploads from arbitrary webshell upload primitives when filename, extension, MIME, and destination are constrained.
  - Treat commented-out request deserialization blocks and session-key-to-DB lookup deserialization separately from direct cookie/body PHP object injection.

### blogger-importer importer-capability and attachment-path false positives

- Plugin: `blogger-importer`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `758`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/758-blogger-importer-source-review.md`
- False-positive pattern:
  - `blogger-importer.php:337` was ranked as request-controlled privilege mutation through `wp_insert_user()`. The importer callback is registered with `register_importer()` and is only called by WordPress core after `current_user_can( 'import' )`; stock core grants `import` only to administrators.
  - `blogger-importer.php:847` was ranked as request-controlled file read. The request value is cast to an attachment id, resolved with `get_attached_file()`, and produced by the prior `wp_import_handle_upload()` flow that stores a private import attachment.
  - Both importer steps are nonce-gated with `check_admin_referer( 'import-upload' )` and `check_admin_referer( 'import-blogger' )`.
- Improvement idea:
  - Model `register_importer()` callbacks as admin importer surfaces guarded by core `current_user_can( 'import' )`.
  - Propagate integer attachment-id resolution through `get_attached_file()` as a bounded WordPress attachment path rather than a raw request path.
  - Track nonce URLs/fields generated by core importer helpers into the follow-up importer POST steps.

### woo-smart-compare remote-api deserialization and admin-page false positives

- Plugin: `woo-smart-compare`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `388`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/388-woo-smart-compare-source-review.md`
- False-positive pattern:
  - `includes/dashboard/wpc-dashboard.php:111`, `includes/dashboard/wpc-dashboard.php:189`, and `includes/kit/wpc-kit.php:98` were ranked as PHP object injection. The serialized bytes come from `wp_remote_post( 'http://api.wordpress.org/plugins/info/1.0/' )`, not request data; a web attacker can trigger authenticated AJAX with a nonce but cannot choose the response without network-path or remote-service control.
  - `includes/kit/wpc-kit.php:51` was ranked as plugin activation without a capability check. The callback is registered through `add_submenu_page()` with `manage_options`, and WordPress core blocks lower-privileged plugin-page access via `user_can_access_admin_page()`.
  - `wpc-smart-compare.php:2592` was ranked as sensitive option creation. The frontend share endpoint stores bounded compare-list share options from sanitized product ids/cookies and does not mutate privileged state.
- Improvement idea:
  - Distinguish request-controlled serialized payloads from fixed remote-service HTTP API responses, possibly reporting plain-HTTP remote unserialize as a separate hardening class rather than direct POI.
  - Propagate `add_menu_page()` / `add_submenu_page()` capability requirements into page callbacks and sensitive sinks executed inside them.
  - Treat bounded frontend share-token option creation as low-value application state unless the option name/value crosses into privileged configuration.

### rometheme-for-elementor fixed-suffix include and admin template filesystem false positives

- Plugin: `rometheme-for-elementor`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1179`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1179-rometheme-for-elementor-source-review.md`
- False-positive pattern:
  - `Inc/Modules/Templatekits/TemplatekitAPI.php:39` was ranked as path traversal into `require_once`. The AJAX action is nonce-only and the nonce can be exposed from Elementor editor scripts, but the include path has a fixed plugin `views/` prefix and a fixed `_templates.php` suffix. The reviewed plugin does not give lower roles a way to create a matching PHP file.
  - `views/installed_templates.php:15`, `Inc/Modules/Helper/EditorCanvas.php:110`, and `Inc/Modules/Templatekits/TemplatekitModule.php:143` read `manifest.json` under the RTMKit template directory, reached either through the bounded render view path or `manage_options`-gated import flows.
  - `Inc/Modules/Templatekits/TemplatekitAPI.php:256`, `:264`, `:369`, `:380`, `:382`, `:390`, `:527`, and `:561` are admin-only template download/upload/import cleanup or extraction paths. The ZIP extractor blocks traversal, PHP-like extensions, absolute paths, and embedded PHP in extracted files.
  - `Inc/Core/PluginApi.php:78` includes a view selected from RTMKit menu metadata and is gated by `current_user_can( 'manage_options' )`.
- Improvement idea:
  - Track fixed include prefixes/suffixes and require an attacker-controlled matching file write primitive before ranking as high-impact LFI/RCE.
  - Propagate Elementor-editor nonce exposure separately from capability checks so nonce-only AJAX actions are still reviewed, but avoid upgrading them when the sink requires an unavailable file shape.
  - Model hardened ZIP extraction constraints, especially extension allowlists and traversal rejection, before linking file uploads to later PHP include sinks.

### navz-photo-gallery fixed-option unserialize and gallery-meta false positives

- Plugin: `navz-photo-gallery`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `778`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/778-navz-photo-gallery-source-review.md`
- False-positive pattern:
  - `includes/acf_photo_gallery.php:74` was ranked as unsafe deserialization. The deserialized value is the plugin's own `apgf_donation` option; the reviewed writer at `includes/acf_photo_gallery.php:67` stores `serialize(array("option" => $option, "timestamp" => ...))` and constrains `$option` to `yes`, `no`, `already`, or `later`.
  - `includes/acf_photo_gallery.php:67` was ranked as missing authorization. The action is nonce-gated and only changes a donation-banner state option with fixed value choices.
  - `includes/acf_photo_gallery_remove_photo.php:25` was ranked as a sensitive write. The handler uses a metabox nonce and only removes a known attachment id from a known gallery post-meta list; it does not delete files or attachments.
  - `includes/acf_photo_gallery_save.php:40` was ranked as a nonce-only post-meta write, but it runs inside core `save_post` for the post currently being edited and writes sanitized attachment ids from the gallery metabox.
- Improvement idea:
  - Treat `unserialize(get_option(...))` as lower risk when all in-plugin writers to that option serialize fixed arrays with enum-constrained request fields.
  - Distinguish content-only gallery metadata changes from file deletion when there is no filesystem sink and no `wp_delete_attachment()`/`unlink()` call.
  - Propagate WordPress core `save_post` edit authorization into metabox nonce-backed post-meta saves.

### greenshift attachment-id file read and font-cleanup false positives

- Plugin: `greenshift-animation-and-page-builder-blocks`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `878`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/878-greenshift-source-review.md`
- False-positive pattern:
  - `init.php:3195` was ranked as request-controlled file read. The REST route requires `edit_posts`, casts `imageid` with `intval()`, and resolves the path via `wp_get_original_image_path( $imageid )`; the attacker controls an attachment id, not a filesystem path.
  - `settings.php:1542`, `settings.php:1555`, and `settings.php:1559` were ranked as file read/delete. These are admin settings/font-upload helpers, gated by nonce plus `manage_options`, using uploaded temp files and plugin-built upload subdirectories.
  - `blockrender/element/block.php:1137` was ranked as sensitive post creation. It is a public contact-form feature that stores sanitized contact submissions in a `contactform` CPT.
- Improvement idea:
  - Treat integer IDs resolved through WordPress attachment APIs as bounded media paths, not raw request paths.
  - Carry settings-page nonce/capability guards into helper methods used by admin-only font upload flows.
  - Classify public contact-form storage separately from privileged post creation when the post type and sanitized fields are fixed.

### real-time-auto-find-and-replace admin list orderby false positive

- Plugin: `real-time-auto-find-and-replace`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1197`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1197-real-time-auto-find-replace-source-review.md`
- False-positive pattern:
  - `core/admin/options/functions/AllMaskingRulesList.php:236` was ranked as SQL injection because `$_GET['order']` reaches an `ORDER BY` fragment. The page callback is internally gated by `manage_options` or plugin custom caps, and the custom caps are added only to administrators by default.
  - The `order` value is passed through `Util::cs_sanitize_sql_orderby()`, which wraps WordPress `sanitize_sql_orderby()`.
  - `core/admin/builders/NoticeBuilder.php:57` was ranked as a sensitive option update, but the write only records plugin notice dismissal state under the plugin prefix.
- Improvement idea:
  - Model `sanitize_sql_orderby()` as a sanitizer for order-by fragments.
  - Propagate callback-internal capability checks when `add_submenu_page()` uses broad `read` but the callback immediately renders access-denied for users without stronger caps.
  - Treat plugin notice-dismissal options as low-value state unless they disable a security control.

### filter-everything admin-created filter configuration deserialization false positive

- Plugin: `filter-everything`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1205`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1205-filter-everything-source-review.md`
- False-positive pattern:
  - `src/Entities/EntityManager.php:607` was ranked as unsafe deserialization because `filter-field` post content reaches `maybe_unserialize()`. The reviewed writers serialize plugin filter configuration arrays from the filter-set save flow.
  - `src/Admin/FilterSet.php:609-616` gates filter-set saves with the plugin nonce and `current_user_can( flrt_plugin_user_caps() )`; `flrt_plugin_user_caps()` defaults to `manage_options`.
  - `src/Admin/Admin.php:103-116` blocks direct admin screens for both plugin post types unless the user has the same plugin capability.
  - The secondary stored-output item is taxonomy/filter display content; the traced image field is cast with `absint()` before storage and is not a high-impact sink.
- Improvement idea:
  - Track custom post content writers and distinguish admin-created serialized configuration from request-controlled serialized object payloads.
  - Propagate plugin capability helper defaults such as `flrt_plugin_user_caps() -> manage_options` into save hooks and AJAX helper methods.
  - Avoid promoting stored term/display HTML output to high-impact unless the source is attacker-writable by a low-privilege role and affects privileged viewers.

### wp-rss-aggregator sysinfo, updater, and nonce-only option-state false positives

- Plugin: `wp-rss-aggregator`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1214`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1214-wp-rss-aggregator-source-review.md`
- False-positive pattern:
  - `v4/includes/system-info.php:188` was ranked as unsafe deserialization. The sink deserializes existing `wprss%` and `wpra%` options for an admin diagnostic download; the download handler checks `wpra_dl_sys_info_nonce` and the Tools UI requires `manage_options`.
  - `v4/includes/Aventura/Wprss/Core/Licensing/AjaxController.php:134` was ranked as unsafe dynamic dispatch. The nonce-protected AJAX action dynamically calls only existing `handleAjaxLicense*` methods; the reviewed class exposes activate/deactivate license handlers, not arbitrary execution primitives.
  - `core/edd-sl-updater.php:577`, `:583`, and `:587` were ranked as PHP object injection. The serialized values are EDD updater API response metadata (`sections`, `banners`, `icons`), not a web request-controlled serialized payload.
  - `v4/includes/v5-notices.php:31`, `v4/includes/admin-ajax-notice.php:81`, and `v4/includes/admin-help.php:101` are nonce-gated notice/help option writes with no privileged security-state impact.
  - `v4/includes/feed-blacklist.php:42` is a nonce-gated editor/admin feed-item blacklist action against an already trashed feed item, not arbitrary post or file deletion.
- Improvement idea:
  - Propagate `manage_options` page capability into admin tool handlers reached by admin-init callbacks.
  - Limit dynamic-dispatch findings when the request-controlled method prefix resolves only to an allowlisted set of benign in-class handlers.
  - Distinguish EDD/WordPress update API response metadata deserialization from attacker-controlled web-request deserialization.
  - Downgrade plugin notice/help option writes unless the option name or value can cross into privileged configuration.

### responsive-menu admin-only nonce and file-helper false positives

- Plugin: `responsive-menu`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `506`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/506-responsive-menu-source-review.md`
- False-positive pattern:
  - `v4.0.0/inc/classes/class-editor-manager.php:87` was ranked as a missing-cap state change. The handler lacks a direct `edit_post` check, but it requires `rmp_nonce`; that nonce is localized only by `Assets::admin_enqueue_scripts()` after `post_type=rmp_menu` and `current_user_can( 'administrator' )`.
  - `v4.0.0/inc/classes/class-admin.php:580` was ranked as request path read/delete. The file read is limited to WordPress' uploaded temp file, requires `rmp_nonce` and `current_user_can( 'edit_post', $menu_id )`, and the content is decoded as JSON before updating menu metadata.
  - `v4.0.0/inc/classes/class-theme-manager.php:379/389` and `:1117/:1127` are ZIP extraction helpers, but the upload endpoints are nonce-gated and require `manage_options` or `administrator`.
  - `v4.0.0/inc/helpers/custom-functions.php:416` writes nav-menu item visibility metadata inside WordPress core nav-menu update flow, not through a standalone low-privilege plugin entrypoint.
- Improvement idea:
  - Track nonce creation locality: when the only nonce source is an admin script gated by `administrator`, avoid ranking nonce-only AJAX helpers as lower-privileged even if their sink lacks a local cap check.
  - Treat reads from `$_FILES[*]['tmp_name']` as uploaded-temp-file reads, not arbitrary filesystem paths, unless the path can be attacker-chosen outside PHP upload handling.
  - Propagate high-level endpoint caps (`manage_options`, `administrator`) into helper methods that call `unzip_file()` or recursive delete on plugin-owned theme directories.

### hello-plus admin row-action nonce and public form response false positives

- Plugin: `hello-plus`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `416`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/416-hello-plus-source-review.md`
- False-positive pattern:
  - `modules/template-parts/components/document.php:82` was ranked as a missing-cap post mutation. The handler lacks a local capability check, but it requires `check_admin_referer( 'hello_plus_set_as_entire_site_' . $post )`; the reviewed nonce source is an Elementor admin row action, not a public or low-privileged disclosure.
  - `modules/forms/components/ajax-handler.php:211` was ranked as public record output. The nopriv endpoint is a normal frontend form submission handler with a public form nonce; it returns configured success/error data, while admin diagnostics are gated by `current_user_can( 'edit_post', $post_id )`.
- Improvement idea:
  - Track action-specific nonces generated only in admin row actions and avoid treating the downstream `admin_init` mutation as low-privileged when no frontend nonce source exists.
  - Distinguish public contact/form submission response paths from stored-record disclosure unless the response contains non-public records or privileged diagnostics for unauthenticated users.

### real-time-find-and-replace settings-page capability false positive

- Plugin: `real-time-find-and-replace`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `424`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/424-real-time-find-and-replace-source-review.md`
- False-positive pattern:
  - `real-time-find-and-replace.php:87` was ranked as a nonce-only sitewide option update. The sink writes powerful output-replacement rules, but the callback is only registered through `add_submenu_page()` with the `activate_plugins` capability and the nonce is emitted on that same admin form.
- Improvement idea:
  - Propagate `add_submenu_page()` capability requirements into same-file page callbacks before classifying settings-form updates as low-privileged nonce-only actions.

### simple-author-box static settings-registry option writes

- Plugin: `simple-author-box`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `427`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/427-simple-author-box-source-review.md`
- False-positive pattern:
  - `inc/class-simple-author-box-admin-page.php:1111` was ranked as a dynamic option-name write from `$_POST['sabox-settings']`. The settings save is hooked on `admin_init`, but the required `sabox-plugin-settings` nonce is only emitted by the Appearance settings page registered with `manage_options`.
  - The option names are selected by iterating the plugin's static `$this->settings` registry, not by using arbitrary request keys.
- Improvement idea:
  - Track page-local nonce creation plus page capability for `admin_init` settings-save callbacks.
  - Recognize static settings registries as bounds on dynamic `update_option($key, ...)` option names when the request only supplies values.

### better-font-awesome settings-api nonce-only AJAX false positive

- Plugin: `better-font-awesome`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `629`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/629-better-font-awesome-source-review.md`
- False-positive pattern:
  - `better-font-awesome.php:504` was ranked as nonce-only AJAX option write. The AJAX handler lacks a local capability check, but the `bfa_nonce` value is the Settings API nonce printed by `settings_fields()` on an options page registered with `manage_options`.
  - The request controls only three boolean settings, not an arbitrary option name, external asset URL, or privileged security state.
- Improvement idea:
  - Propagate Settings API page capabilities and `settings_fields($group)` nonce provenance into AJAX settings-save handlers that reuse the page nonce.

### wp-post-page-clone post-meta double-serialization false positive

- Plugin: `wp-post-page-clone`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `451`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/451-wp-post-page-clone-source-review.md`
- False-positive pattern:
  - `wp-post-page-clone.php:127` was ranked as PHP object injection because the plugin calls `maybe_unserialize()` while cloning source post metadata.
  - A contributor can create and clone their own draft post, but attacker-supplied serialized-looking custom field strings saved through normal WordPress metadata APIs are double-serialized by `maybe_serialize()`.
  - The plugin's single `maybe_unserialize()` unwraps the raw meta value to a string, not an object, so `__wakeup()` does not fire without an additional raw post-meta write primitive outside this plugin.
  - `wp-post-page-clone.php:128` copies the source post's metadata into another contributor-owned draft; no standalone privilege escalation or high-impact state change was proven.
- Improvement idea:
  - Model WordPress metadata writes as double-serializing strings that already match serialized syntax, and require a raw database/meta-write primitive before promoting a post-meta clone `maybe_unserialize()` call to POI.
  - Downgrade clone/copy `update_post_meta()` findings when source and destination posts are both owned/editable by the same low-privileged user and the destination is forced to draft.

### wordfence-login-security prepared role query and admin-only capability settings

- Plugin: `wordfence-login-security`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `628`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/628-wordfence-login-security-source-review.md`
- False-positive pattern:
  - `classes/controller/users.php:879` was ranked as SQL injection. The role list view uses `$_GET['role']`, but the path is gated by `wf2fa_activate_2fa_others`, which the plugin grants to administrators by default. The role key is serialized, passed through `esc_like()`, and bound with `%s` in `$wpdb->prepare()`; pagination is integer-cast.
  - `classes/controller/permissions.php:298` was ranked as request-tainted privilege mutation. The `add_cap()` sink is reached from install-time setup or administrator-only settings save. The `wordfence_ls_save_options` AJAX action requires a valid `wp-ajax` nonce and `wf2fa_manage_settings`, also administrator-only by default.
- Improvement idea:
  - Preserve `$wpdb->prepare()` boundaries when the tainted expression is the first argument but tainted values are only appended to the parameter list after escaping.
  - Propagate custom plugin capabilities granted only to administrators during install into admin menu and AJAX permission checks.

### shopengine importer, notice-state, and updater false positives

- Plugin: `shopengine`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `274`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/274-shopengine-source-review.md`
- False-positive pattern:
  - `core/export-import/import.php:23` was ranked as request-controlled file read. The sink parses an attachment file and can update option names from XML, but the callback is only registered on WordPress' `import_start` hook. Core importer execution reaches it through `wp-admin/admin.php?import=...`, which requires `current_user_can( 'import' )`; the lab role check showed `import` only on administrator by default.
  - `libs/rating/rating.php:250/354` and `utils/notice/notice.php:388` are nonce-only authenticated AJAX actions, but the sinks only mutate rating/banner dismissal state, user meta, transients, or a per-user dismissal counter.
  - `libs/updater/plugin-updater.php:618/624/628` deserializes fields from the vendor EDD updater response in an `update_plugins`/pro-updater context, not from attacker-controlled request input.
  - `core/page-templates/page-templates.php:71` and `modules/quick-view/quick-view.php:69` only update the preview product option in admin preview flow and were classified as `manage_options`.
- Improvement idea:
  - Treat callbacks registered solely on WordPress importer hooks as requiring the core `import` capability unless another public plugin entrypoint invokes them.
  - Downgrade notice/rating/banner dismissal state writes that only affect UX state and do not alter security-sensitive options.
  - Preserve updater-response provenance and `update_plugins` capability context around EDD updater helper deserialization.

### simply-schedule-appointments prepared model queries and stale fields-list SQLi

- Plugin: `simply-schedule-appointments`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `806`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/806-simply-schedule-appointments-source-review.md`
- False-positive and stale-vuln pattern:
  - `includes/class-appointment-model.php:1776/1789/1823` were ranked as SQL injection, but appointment meta query filters bind `appointment_id` with `%d` and `meta_key`/`meta_value` with `%s`.
  - `includes/class-shortcodes.php:568/1014/1026` were ranked as shortcode SQL injection, but shortcode `type` and label input are sanitized and then routed through model query filters that bind slug/name/status/label IDs.
  - `includes/class-notices-api.php:203/232` and `includes/class-error-notices.php:296` only mutate notice or error-notice bookkeeping state, not privileged configuration or execution state.
  - The scanned local version had an adjacent real SQLi shape in `TD_DB_Model::db_query()` where request `fields[]` was directly joined into the SELECT list and public-nonce read endpoints could reach it. Current wordpress.org `1.6.10.4` patches this by sanitizing requested fields and intersecting them with `$this->get_fields()`.
- Improvement idea:
  - Preserve model-specific `filter_where_conditions()` prepare boundaries when generic query wrappers use `$wpdb->get_results()`.
  - Recognize notice dismissal/pinning option writes as low-value UX state unless they control security-sensitive behavior.
  - Add a scan-staleness signal when a locally downloaded plugin version is older than the current wordpress.org version and the current version has a nearby hardening change.

### superb-blocks admin-only uploaded-temp-file import false positive

- Plugin: `superb-blocks`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `552`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/552-superb-blocks-source-review.md`
- False-positive pattern:
  - `src/data/controllers/class-css-controller.php:201` was ranked as request-controlled file read. The endpoint is `POST /wp-json/superbaddons/css-blocks`, but its `CSSCallbackPermissionCheck()` requires `Capabilities::ADMIN`, which maps to `manage_options`.
  - The path read is from `WP_REST_Request::get_file_params()['files']['tmp_name']`, so it is a PHP-upload temporary file generated by the request parser rather than an arbitrary path parameter.
  - The content is decoded as base64 JSON, sanitized into CSS block option state, and generated CSS deletion is restricted to the plugin's upload subdirectory.
- Improvement idea:
  - Recognize `get_file_params()['tmp_name']` as uploaded-temp-file provenance, not arbitrary filesystem path control.
  - Propagate route-level `permission_callback` capability checks into file-read/file-delete findings.

### bookly diagnostics admin-only uploaded-temp-file import false positive

- Plugin: `bookly-responsive-appointment-booking-tool`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `695`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/695-bookly-diagnostics-source-review.md`
- False-positive pattern:
  - `backend/modules/diagnostics/Ajax.php:140` was ranked as request-controlled file read. The sink reads `$_FILES['import']['tmp_name']`, so the path is a PHP-upload temporary file, not an arbitrary request path.
  - The action is registered by Bookly's Ajax base class. `importData()` is not in the controller's anonymous permissions map, so it falls back to default `admin` access and also requires a valid `bookly` CSRF token.
- Improvement idea:
  - Recognize `$_FILES[*]['tmp_name']` as upload-temp provenance.
  - Model Bookly `Lib\Base\Ajax::permissions()` defaults: unlisted public methods require admin access, while only explicitly mapped methods inherit weaker access.

### wp-carousel-free wordpress.org API unserialize and admin UI state false positives

- Plugin: `wp-carousel-free`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `649`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/649-wp-carousel-free-source-review.md`
- False-positive pattern:
  - `admin/help-page/help.php:168` was ranked as PHP object injection, but the data source is the fixed WordPress.org Plugin API response for a static author query on an admin help page registered with `manage_options`.
  - `admin/help-page/help.php:389` activates a plugin from request parameters, but the code is in the same `manage_options` help-page callback and requires WordPress plugin action nonces.
  - `admin/views/notices/offer-banner.php:158` is nonce-only AJAX, but the nonce is rendered only to administrators and the sink only changes marketing-banner dismissal state.
  - `admin/views/sp-framework/classes/metabox-options.class.php:480` persists sanitized metabox fields during normal `save_post` handling for the plugin's admin-only carousel post type.
- Improvement idea:
  - Preserve admin submenu capability context for callbacks reached only through `add_submenu_page()`.
  - Distinguish WordPress.org Plugin API/updater responses from attacker request input when ranking `unserialize()`.
  - Downgrade marketing-banner dismissal and normal post-metabox persistence unless a security-sensitive state change is proven.

### google-calendar-events vendor OAuth response deserialization and settings-page token state

- Plugin: `google-calendar-events`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1257`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1257-google-calendar-events-source-review.md`
- False-positive pattern:
  - `includes/oauthhelper/oauth-service-actions.php:235` and `includes/feeds/google.php:573` deserialize fields returned by the fixed vendor OAuth helper service at `https://auth.simplecalendar.io/`, not requester-supplied serialized bytes.
  - `includes/oauthhelper/class-oauth-service.php:82` stores an `auth_token` from `$_GET`, but only while rendering the plugin settings page registered with `manage_options`.
  - `includes/admin/post-types.php:287` copies existing calendar post meta through `maybe_unserialize()` after nonce and `edit_posts` checks, matching the normal post-meta double-serialization false-positive pattern.
  - `includes/admin/updater.php:346` deserializes EDD updater response sections in an updater/changelog flow gated by `update_plugins`.
  - `includes/admin/pages/system-status.php:605` prints admin system-status fields under `manage_options` plugin pages.
- Improvement idea:
  - Track fixed vendor OAuth/updater response provenance separately from request-controlled remote URL or body provenance.
  - Propagate `add_submenu_page()` capability checks to callbacks that write settings during page render.
  - Reuse the post-meta double-serialization heuristic for clone/copy helpers that only read existing metadata and write it to a duplicate post.

### wp-add-mime-types admin-generated serialized settings false positives

- Plugin: `wp-add-mime-types`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1355`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1355-wp-add-mime-types-source-review.md`
- False-positive pattern:
  - `includes/admin.php:29`, `includes/admin.php:163`, and `includes/network-admin.php:28` deserialize stored MIME settings that the plugin previously generated with `serialize($mime_type_values)`.
  - The normal settings page is registered with `manage_options`; the network settings page is registered with `manage_network_options`.
  - Both save paths require `check_admin_referer()` before updating `wp_add_mime_types_array` or `wp_add_mime_types_network_array`.
  - Runtime upload filters call `maybe_unserialize()` on the same admin-controlled settings, but no lower-privileged setting write path exists.
- Improvement idea:
  - Track plugin-generated serialized option values when the only writer serializes sanitized line arrays behind an admin settings page and nonce.
  - Propagate `add_options_page()` and network `add_submenu_page()` capabilities into option-read deserialization findings.

### bold-page-builder sanitized template basename file-read false positives

- Plugin: `bold-page-builder`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1412`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1412-bold-page-builder-source-review.md`
- False-positive pattern:
  - `bold-builder-fe.php:812/814/817` read template files from child theme, parent theme, or plugin template roots.
  - The request `layout` is passed through `preg_replace( '/[^a-zA-Z0-9_\-\+]/', '', $layout )`, then `+` is replaced with `_`, and `.txt` is appended.
  - Directory separators, dots, stream-wrapper punctuation, and URL punctuation are stripped before path construction, so traversal and wrapper injection are not viable.
  - The handler also requires `bt_bb_fe_nonce` and only returns content after `current_user_can( 'edit_post', $post_id )`.
- Improvement idea:
  - Recognize basename allowlist sanitizers that remove both dot and slash characters before appending a fixed extension under a fixed template root.
  - Treat builder template loaders as low risk when request control is reduced to a constrained basename and output is gated by post-edit capability.

### wp-members default-role registration, admin settings, and upload index-file false positives

- Plugin: `wp-members`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1454`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1454-wp-members-source-review.md`
- False-positive pattern:
  - `includes/api/api-users.php:817` was ranked as privilege mutation, but the inserted role comes from `$wpmem->user->post_data['user_role']`, which the default registration flow sets from `get_option( 'default_role' )`, not a request parameter.
  - `includes/api/api-utilities.php:324` was ranked as request-controlled file write. In-plugin callers pass fixed `index.php` or `.htaccess` names, fixed contents, and paths under `wp_upload_dir()` plus plugin-generated random hashes.
  - Admin tab settings writes and nav-menu metadata writes are nonce-protected and reached through core/admin pages registered with `manage_options` or WordPress nav-menu save handling.
  - The widget echo sink is the generated login widget form and optional login-failure message, not request-selected sensitive record disclosure.
- Improvement idea:
  - Track user role sources through registration flows and downgrade default-role assignment when the value comes from `get_option( 'default_role' )`.
  - Recognize fixed safety-file creation helpers that only write `index.php` or `.htaccess` with constant contents under WordPress upload directories.
  - Propagate admin page capabilities and core nav-menu save context into option/meta update findings.

### index-wp-mysql-for-speed admin-framework import and debug utility false positives

- Plugin: `index-wp-mysql-for-speed`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1548`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1548-index-wp-mysql-for-speed-source-review.md`
- False-positive pattern:
  - `AdminPageFramework_Debug.php:204` writes a debug log file, but the request-controlled value in the trace is only `REQUEST_URI` included in log content via `getCurrentURL()`, not the log file path.
  - `AdminPageFramework_ImportOptions.php:25` reads `$_FILES['__import'][...]['tmp_name']`, which is the PHP upload temporary file path, not an arbitrary path parameter.
  - `AdminPageFramework_ImportOptions.php:38` deserializes uploaded import data only inside Admin Page Framework form submission processing.
  - The plugin only loads its admin page framework for `is_admin()` users with `activate_plugins`; form submissions also require referer equality and a user-specific Admin Page Framework nonce.
  - The reviewed plugin page does not define an import field, so the generic framework import path is not exposed by this plugin's UI.
- Improvement idea:
  - Distinguish file-path arguments from log-content values when a request URL is only appended to diagnostics.
  - Recognize `$_FILES[*]['tmp_name']` as uploaded-temp-file provenance for import helpers.
  - Propagate plugin-level framework load guards and submenu capabilities into bundled Admin Page Framework sink findings.

### wp-dbmanager install_plugins-gated database admin false positives

- Plugin: `wp-dbmanager`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `845`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/845-wp-dbmanager-source-review.md`
- False-positive pattern:
  - `wp-dbmanager.php:625` persists `dbmanager_options`, but the callback is registered only through `add_submenu_page(..., 'install_plugins', 'wp-dbmanager/wp-dbmanager.php', 'dbmanager_options')` and requires `check_admin_referer('wp-dbmanager_options')`.
  - `database-backup.php`, `database-manage.php`, `database-empty.php`, `database-optimize.php`, `database-repair.php`, and `database-run.php` all begin with `current_user_can('install_plugins')` and require page-specific nonces before SQL, backup, restore, delete, or command execution.
  - The command builders use `escapeshellcmd()` and `escapeshellarg()` around command components; scheduled backup reads the same admin-controlled option values and no lower-privileged writer was found.
  - `init` helpers such as `download_database()` and `dbmanager_try_fix()` lack inline capability checks but rely on nonces rendered from the admin-only plugin screens.
- Improvement idea:
  - Propagate `add_submenu_page()` capabilities into callback functions even when the callback file is also the main plugin file.
  - Treat bundled admin-page include files with top-of-file `current_user_can()` and nonce checks as admin-only for SQL and command sink ranking.
  - Downgrade nonce-only `init` helpers when their nonce is generated only inside an admin page protected by a stronger capability.

### side-cart-woocommerce framework settings and template include false positives

- Plugin: `side-cart-woocommerce`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `482`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/482-side-cart-woocommerce-source-review.md`
- False-positive pattern:
  - `includes/xoo-framework/admin/class-xoo-admin-settings.php:224` imports arbitrary option keys from JSON, but only after `wp_verify_nonce('xoo-ff-nonce')` and `current_user_can($this->capability)`, where the framework default capability is `manage_options`.
  - `class-xoo-admin-settings.php:127` stores only telemetry consent (`xoo_tracking_consent_{slug}`) from an admin notice nonce, not a security-sensitive setting.
  - `includes/xoo-framework/class-xoo-helper.php:68` includes located templates, but reviewed callers pass fixed plugin/admin template names; the only dynamic frontend branch selects between two fixed product template names.
  - The adjacent `install_loginpopup()` AJAX handler can install/activate a fixed companion plugin, but its nonce is localized only by the admin settings page script protected by `manage_options`, so no lower-privileged nonce acquisition path was found.
- Improvement idea:
  - Propagate framework default capabilities from class properties into AJAX methods that use `$this->capability`.
  - Downgrade template loader includes when all in-plugin call sites pass fixed template names and request control only affects non-path template arguments.
  - Rank missing-capability AJAX plugin-install helpers separately from exploitable cases when their only nonce source is an admin-only settings page.

### gutenkit-blocks-addon REST callback inline auth false positives

- Plugin: `gutenkit-blocks-addon`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1136`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1136-gutenkit-blocks-addon-source-review.md`
- False-positive pattern:
  - Multiple REST routes use `permission_callback => '__return_true'`, but the state-changing callbacks check `wp_verify_nonce( X-WP-Nonce, 'wp_rest' )` and `current_user_can( 'manage_options' )` before option writes in `BlocksData`, `FavoriteTemplates`, `ModulesData`, `SettingsData`, and `OnboardData`.
  - The adjacent `install-active-plugin` route accepts a plugin ZIP URL and reaches `download_url()` plus `unzip_file()` into `WP_PLUGIN_DIR`, but the callback checks `current_user_can( 'install_plugins' )` before reading request parameters or touching the filesystem.
- Improvement idea:
  - For REST routes with open `permission_callback`, propagate inline callback guards before ranking sinks as lower-privilege reachable.
  - Specifically model early-return `current_user_can()` checks inside REST callbacks before dangerous file operations such as `download_url()` and `unzip_file()`.
- `getwid` (`includes/functions.php:45`) - path traversal include FP where `postType` controls `getwid_get_template_part()` slug, but the same value is also used as the `WP_Query` `post_type`, and the `require $template;` call is only reached inside the posts loop. Traversal payloads make the query return no posts, while valid post types force non-traversal template slugs. Example sink: `require $template;`.
- `smart-custom-fields` (`classes/models/class.meta.php:467`) - file delete FP where `$this->delete( $field_name )` is an internal metadata model method, not a filesystem primitive. The method dispatches to `delete_metadata()` or option-array cleanup via `delete_option_metadata()`. Example sink: `$this->delete( $field_name );`.

### post-and-page-builder editor save-state false positives

- Plugin: `post-and-page-builder`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1028`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1028-post-and-page-builder-source-review.md`
- False-positive pattern:
  - `controls/class-boldgrid-controls-page-title.php:98` writes `boldgrid_hide_page_title` from `$_POST`, but it is a `save_post` post-editor state toggle reached through WordPress core post-save authorization.
  - `includes/builder/class-boldgrid-editor-builder.php:431` writes `boldgrid_in_page_containers`, but the handler is attached only from admin post/editor pages for users passing `current_user_can( 'edit_posts' )` and with the BoldGrid editor active.
  - `includes/class-boldgrid-editor-option.php:52` is a generic option helper; the reviewed request-controlled caller writes only sanitized JSON custom color palette data from the post editor.
- Improvement idea:
  - Propagate core `save_post` editor context and plugin bootstrap guards such as `is_admin() && current_user_can( 'edit_posts' )` into post-meta and fixed-key option writes.
  - Downgrade fixed editor-state writes when values are constrained to integers or sanitized JSON and do not control arbitrary option names, capabilities, uploads, or executable content.

### stream network settings capability false positive

- Plugin: `stream`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `429`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/429-stream-network-settings-source-review.md`
- False-positive pattern:
  - `classes/class-network.php:384` writes `wp_stream_network` with `update_site_option()`, but `network_options_action()` first verifies the settings nonce, `current_user_can( $this->plugin->admin->settings_cap )`, the `wpmuadminedit` action slug, and the expected `option_page`.
  - `$this->plugin->admin->settings_cap` resolves to `WP_STREAM_SETTINGS_CAPABILITY`, which defaults to `manage_options` in `stream.php`.
- Improvement idea:
  - Propagate object-property capability constants into methods before ranking network settings writes.
  - Model multisite settings wrappers where `wpmuadminedit` handlers manually implement nonce, capability, action, and option-page checks before `update_site_option()`.

### woocommerce-square public checkout payment-helper below-bar findings

- Plugin: `woocommerce-square`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue IDs `525`, `526`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/525-woocommerce-square-source-review.md`
- False-positive pattern:
  - `includes/Framework/PaymentGateway/ApplePay/Payment_Gateway_Apple_Pay_Ajax.php:121` returns the Apple Pay merchant-session JSON from a public AJAX callback, but the public nonce is intentionally localized to Apple Pay frontend pages and the outbound URL is requested through `wp_safe_remote_request()` with redirects disabled.
  - The Apple Pay API sets a client certificate path on the cURL handle, but source review found no private-key disclosure or ability to use the endpoint for private-network SSRF, arbitrary file read, RCE, or privilege escalation.
  - `includes/Gateway/Digital_Wallet.php:937` returns a digital-wallet payment request after a public checkout nonce check; the response is cart/order totals only and no item, PII, payment-token, or state-changing order action was found.
- Improvement idea:
  - Recognize public checkout/payment helper nonces localized to frontend payment pages and rank them separately from sensitive record-read findings.
  - Downgrade Apple Pay merchant validation helpers when request execution uses `wp_safe_remote_request()` with no redirects and returns only merchant-session JSON.
  - Treat digital-wallet recalculation endpoints as low-value unless the response includes customer PII, payment secrets, order mutation, or bypasses WooCommerce order-key ownership checks for sensitive fields.

### wp-social admin menu capability false positives

- Plugin: `wp-social`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue IDs `490`, `491`, `492`, `493`, `494`, `495`, `528`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/490-wp-social-source-review.md`
- False-positive pattern:
  - `inc/admin-settings.php:369`, `445`, `474`, `553`, `621`, and `791` write fixed WP Social settings options from request data, but all affected callbacks are wired through `add_menu_page()` or `add_submenu_page()` with `manage_options`.
  - Adjacent REST routes use open `permission_callback` values, but state-changing callbacks check `X-WP-Nonce`, logged-in state, and `current_user_can( 'manage_options' )` before updates.
  - `helper/share-style-settings.php:78` writes only a `save_post` social-share display selector after a post-editor nonce and `current_user_can( 'edit_post', $post_id )`.
- Improvement idea:
  - Propagate `add_menu_page()` and `add_submenu_page()` capability gates into callback methods before ranking fixed plugin-option writes as nonce-only.
  - Model inline REST callback guards separately from route-level `permission_callback => __return_true`.
  - Downgrade `save_post` post-meta display setting writes when core editor authorization and plugin nonce checks are present.

### custom-typekit-fonts init settings save false positive

- Plugin: `custom-typekit-fonts`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `820`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/820-custom-typekit-fonts-source-review.md`
- False-positive pattern:
  - `classes/class-custom-typekit-fonts.php:95` writes the `custom-typekit-fonts` option from `$_POST` on `init`, but the required `custom-typekit-fonts` nonce is rendered only by `templates/custom-typekit-fonts-options.php` on a submenu page registered with `edit_theme_options`.
  - Saved embed method is constrained to `css` or `javascript`, and frontend output uses fixed Adobe hosts (`https://use.typekit.net/%s.css` or `.js`) after fetching kit details from Adobe's Typekit API.
- Improvement idea:
  - Link `init` POST handlers to nonce fields rendered only in admin submenu pages and propagate the submenu capability.
  - Downgrade fixed-vendor font/embed option updates when request control cannot change the host or arbitrary script URL.

### disable-json-api settings page capability false positive

- Plugin: `disable-json-api`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `140`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/140-disable-json-api-source-review.md`
- False-positive pattern:
  - `classes/disable-rest-api.php:255` writes the REST API allowlist/security-control option, but the callback is reached through `add_options_page()` with `CAPABILITY = 'manage_options'`.
  - The form processor also checks `check_admin_referer( 'DRA_admin_nonce' )` and `current_user_can( self::CAPABILITY )` before reading request data or calling `update_option()`.
- Improvement idea:
  - Propagate class constants used as `add_options_page()` capabilities into page callbacks.
  - Treat repeated inline `current_user_can( self::CAPABILITY )` checks as a strong sink guard even when request data is processed in a private helper method.

### remove-footer-credit activate_plugins settings false positive

- Plugin: `remove-footer-credit`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `425`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/425-remove-footer-credit-source-review.md`
- False-positive pattern:
  - `remove-footer-credit.php:163` writes the sitewide find/replace option, but the callback is registered through `add_submenu_page( 'tools.php', ..., 'activate_plugins', 'remove-footer-credit', ... )`.
  - The required nonce is rendered only inside the same Tools admin screen.
  - Output replacement is real but uses `jabrfc_kses()` and has no lower-privileged writer.
- Improvement idea:
  - Propagate `add_submenu_page()` capabilities into settings callbacks even when the callback method itself only checks a nonce.
  - Rank option writes used in output replacement by both writer capability and output sanitizer, not only by sink type.

### yikes custom product tabs product-capability AJAX false positives

- Plugin: `yikes-inc-easy-custom-woocommerce-product-tabs`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue IDs `210`, `211`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/210-yikes-woo-tabs-source-review.md`
- False-positive pattern:
  - `admin/class.yikes-woo-saved-tabs.php:141` writes the reusable-tab option from `wp_ajax_yikes_woo_save_tab_as_reusable`, but the required nonce is localized only on the plugin settings page registered by `add_menu_page()` with default capability `publish_products`.
  - `admin/class.yikes-woo-tabs.php:197` and related `update_post_meta()` calls write product-tab state from `wp_ajax_yikes_woo_save_product_tabs`, but the nonce is localized only on WooCommerce product add/edit pages.
  - The AJAX callbacks lack inline capability checks, but no subscriber/customer/unauthenticated nonce acquisition path was found; the reachable role is a product-publishing/product-editing role and the impact is product tab content/association manipulation.
- Improvement idea:
  - Propagate nonces localized by `admin_enqueue_scripts` only for specific admin hooks into AJAX reachability scoring.
  - Link `add_menu_page()` default capabilities such as `publish_products` to localized AJAX nonces before classifying missing-capability callbacks as low-privilege.
  - For post edit screen nonces, require a separate IDOR/high-impact signal before promoting request-controlled `post_id` writes above product-editor content management.

### maxbuttons license upgrade admin capability false positive

- Plugin: `maxbuttons`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `420`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/420-maxbuttons-source-review.md`
- False-positive pattern:
  - `classes/upgrader/license.php:98` writes `maxbuttons_pro_license_key`, but the value comes from `classes/controllers/upgradeController.php:29-40` after `check_admin_referer( 'upgrade', 'upgrade_nonce' )`.
  - The nonce is rendered only by `includes/maxbuttons-pro.php` on the Upgrade to Pro admin page.
  - The page is registered through `add_submenu_page()` using `MB()->get_user_level()`, which defaults to `manage_options`; an admin can lower this capability intentionally through plugin settings.
  - The adjacent `Plugin_Upgrader->install()` path uses a package URL returned by the MaxButtons license API, not a request-controlled URL.
- Improvement idea:
  - Propagate plugin-specific admin menu capabilities stored in options when defaulting to `manage_options`.
  - Link admin form nonces to their menu-page capability before ranking option writes.
  - Treat vendor-license upgrade installers separately from arbitrary plugin install/upload paths when the package URL is not request-controlled.

### popup-builder-block base REST permission false positive

- Plugin: `popup-builder-block`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1470`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1470-popup-builder-block-source-review.md`
- False-positive pattern:
  - `includes/Routes/Onboard.php:79` writes onboarding email metadata from the POST `/onboard` route.
  - The route definition omits a per-route permission callback, but `includes/Routes/Api.php` supplies the default `permission_callback`, which returns `current_user_can( 'manage_options' )`.
  - The affected options are onboarding status/email subscription markers, not security settings or executable content.
- Improvement idea:
  - Propagate inherited REST permission callbacks from base route classes into child route definitions.
  - Downgrade admin-only onboarding/telemetry option writes when the default route permission is `manage_options`.

### auto-post-thumbnail REST settings permission false positive

- Plugin: `auto-post-thumbnail`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1460`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1460-auto-post-thumbnail-source-review.md`
- False-positive pattern:
  - `src/Routes/Settings.php:239` writes a logger/telemetry option from the REST `settings/tracking` route.
  - The route declares `permission_callback => [ $this, 'manage_options_permissions_check' ]`, and `src/Routes/Base_Route.php` implements that callback as `current_user_can( 'manage_options' )`.
  - Adjacent thumbnail/log deletion routes also use `manage_options_permissions_check`, and attachment deletion is constrained to plugin-created attachments.
- Improvement idea:
  - Propagate route-level method-reference permission callbacks into REST callback sink scoring.
  - Downgrade admin-only telemetry option writes and plugin-owned attachment cleanup paths when the route callback requires `manage_options`.

### exclusive-addons-for-elementor admin installer deserialization false positive

- Plugin: `exclusive-addons-for-elementor`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `1123`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1123-exclusive-addons-source-review.md`
- False-positive pattern:
  - `admin/dashboard-notice.php:56` unserializes the WordPress.org plugin information API response in `get_remote_plugin_data()`.
  - The only queue-flagged caller is `wp_ajax_exad_install_plugin`, which checks `check_ajax_referer( 'exad-addons-elementor', 'security' )` and `current_user_can( 'install_plugins' )` before accepting the request slug.
  - Adjacent plugin upgrade, activation, and notice-dismiss AJAX callbacks are also capability-gated with `update_plugins`, `activate_plugins`, or `manage_options`.
- Improvement idea:
  - Propagate hard plugin-management capabilities into unsafe-deserialization findings before ranking them as bounty candidates.
  - Downgrade fixed WordPress.org Plugin Info API unserialize patterns when the request-controlled value is only a sanitized plugin slug and the caller requires `install_plugins`.

### internal-links admin statistics SQL and import file false positives

- Plugin: `internal-links`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue IDs `276`, `277`, `278`, `279`, `303`, `304`, `305`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/276-internal-links-source-review.md`
- False-positive pattern:
  - `statistics/link.php:229`, `237`, `355`, and `360` build dashboard statistics SQL from request filters, but the caller `helper/ajax.php:485` requires the `ilj-dashboard` nonce and `current_user_can( 'manage_options' )`.
  - Statistics request values are constrained before query execution: sort columns and directions are allowlisted, `limit`/`offset` are integer-cast, search is prepared with `$wpdb->esc_like()`, and main/sub type arrays use `esc_sql()` before entering `IN (...)` fragments.
  - `helper/ajax.php:371`, `372`, and `426` read or delete only paths produced by `wp_handle_upload()` or by a transient created from the same admin-only upload flow, with `ilj-tools` nonce plus `manage_options`.
- Improvement idea:
  - Propagate plugin-wide AJAX registration gates and callback-level `manage_options` checks before ranking SQL/import helpers.
  - Model allowlisted order-by and direction parameters plus `intval()` pagination as SQL sanitizers.
  - Treat file read/delete of `wp_handle_upload()` result paths and same-flow upload transients as import-cleanup behavior unless a separate arbitrary path source is present.

### wp-smtp admin REST logs SQL false positive

- Plugin: `wp-smtp`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `704`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/704-wp-smtp-source-review.md`
- False-positive pattern:
  - `src/Mail/Repository/LogsRepository.php:85` builds the log listing SQL with interpolated table and order fragments.
  - The REST controller `src/Mail/Admin/REST/Logs.php` applies `permission_callback => [ $this, 'get_items_permissions_check' ]`, and the callback requires `current_user_can( 'manage_options' )`.
  - REST args constrain `sortby` and `sort` with enum values, while the repository also allowlists `orderby` to `timestamp`, `to`, or `subject`, allowlists order to `ASC` or `DESC`, prepares the search fragment with `$wpdb->esc_like()`, and binds pagination placeholders.
- Improvement idea:
  - Propagate REST permission callbacks requiring `manage_options` into SQL ranking.
  - Recognize repository-level `ORDER BY` allowlists and prepared search fragments as SQL sanitizers, even when the final query string is assembled before `$wpdb->prepare()`.

### feeds-for-tiktok admin AJAX SQL/import false positives

- Plugin: `feeds-for-tiktok`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue IDs `1016`, `1017`, `1018`, `1019`, `1020`, `1046`, `1088`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1016-feeds-for-tiktok-source-review.md`
- False-positive pattern:
  - `inc/Common/Database/FeedCacheTable.php:145`, `FeedsTable.php:239`, `PostsTable.php:167`, and `SourcesTable.php:240` call `$wpdb->update()` with request-influenced arrays, but reviewed callers are `wp_ajax_sbtt_*` admin callbacks that require `check_ajax_referer( 'sbtt-admin', 'nonce' )` and `current_user_can( 'manage_options' )`.
  - The update helpers sanitize `where` values with `sanitize_text_field()` and pass structured arrays plus format arrays into `$wpdb->update()` instead of raw SQL fragments.
  - `inc/Common/Database/SourcesTable.php:155` has an `IN (...)` branch that interpolates `sanitize_text_field()` values, but the reachable reviewed actions are still admin-only.
  - `inc/Common/Services/AjaxHandlerService.php:274` reads only `$_FILES['feedFile']['tmp_name']` after `is_uploaded_file()` and a `.json` filename check in the same admin-only import callback.
  - `inc/Common/Feed.php:735` writes plugin resize cache metadata behind the same admin-only builder/preview flow.
- Improvement idea:
  - Recognize `$wpdb->update()` array arguments plus `$where_format` construction as lower-risk than raw SQL string execution.
  - Track AJAX callback-level `check_ajax_referer()` and `current_user_can( 'manage_options' )` gates through helper-table update methods.
  - Treat `is_uploaded_file()`-validated import temp-file reads as import handling rather than arbitrary path reads unless a separate path bypass is present.

### profile-builder generated metadata and admin settings false positives

- Plugin: `profile-builder`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue IDs `1177`, `1184`, `1198`, `1218`, `1219`, `1247`, `1248`, `1249`, `1260`, `1261`, `1262`, `1339`, `1340`, `1341`, `1456`, `1457`, `1458`, `1472`, `1491`, `1498`, `1499`, `1500`, `1501`, `1502`, `1503`, `1504`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/1198-profile-builder-source-review.md`
- False-positive pattern:
  - Multiple `unserialize()` and `maybe_unserialize()` sinks consume `signups.meta` records generated by the plugin through `serialize($userdata)` or `serialize($meta)`. Users can influence scalar field values, but not raw serialized object bytes.
  - Upload findings reach `wp_handle_upload()` for avatar or generic profile fields, but WordPress MIME checks still apply and the paths are media uploads, not executable file writes.
  - Role mutation findings either require `delete_users`, `promote_users`, `edit_user`, or `manage_options`, or are constrained to configured user-role fields where `administrator` is stripped for non-admin flows.
  - Admin import/settings findings read `$_FILES[*]['tmp_name']` or include fixed view files behind plugin settings pages.
- Improvement idea:
  - Track plugin-generated serialized database columns separately from request-controlled serialized blobs.
  - Downgrade `wp_handle_upload()` findings that retain default WordPress MIME validation and do not write into executable paths.
  - Propagate role-management capabilities and configured role allowlists into privilege-mutation ranking.
  - Treat settings-view includes built from fixed tab allowlists as non-traversal.

### hcaptcha public validation output and admin import false positives

- Plugin: `hcaptcha-for-forms-and-more`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue IDs `614`, `615`, `616`, `617`, `733`, `740`, `741`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/614-hcaptcha-for-forms-source-review.md`
- False-positive pattern:
  - Public AJAX handlers for Blocksy, Essential Blocks, Kadence, and Spectra return only hCaptcha verification error messages through `wp_send_json_error()`.
  - `Settings/Tools.php:151` reads the uploaded import temp file path after `PluginSettingsBase::run_checks()`, which requires both an AJAX nonce and `current_user_can( 'manage_options' )`.
  - License and onboarding option writes are derived from hCaptcha site-config responses or admin-only onboarding AJAX, not lower-privileged request input.
- Improvement idea:
  - Distinguish validation-error response helpers from record-read-to-output paths.
  - Treat admin-only settings import temp-file reads as import handling rather than arbitrary path reads.
  - Propagate shared settings-base AJAX guards into subclass callbacks.

### facebook-messenger-customer-chat settings capability false positive

- Plugin: `facebook-messenger-customer-chat`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `142`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/142-facebook-messenger-customer-chat-source-review.md`
- False-positive pattern:
  - `options.php:121` writes Facebook widget options inside `fbmcc_update_options()`, but the handler first checks `current_user_can( fbmcc_get_options_capability() )`, which defaults to `manage_options`.
  - The AJAX nonce is localized only on the plugin settings or plugins screen after the same capability check.
- Improvement idea:
  - Resolve default values of plugin capability wrapper functions when they are simple `apply_filters()` wrappers around `manage_options`.
  - Link nonce localization guards to AJAX callbacks when both use the same capability helper.

### change-wp-admin-login network settings hook false positive

- Plugin: `change-wp-admin-login`
- Candidate: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue ID `618`
- Evidence: `artifacts/phparser/phparser-20260406-145336/evidence/618-change-wp-admin-login-source-review.md`
- False-positive pattern:
  - `class-change-wp-admin-login.php:205` updates the multisite `rwl_page` setting from `update_wpmu_options`.
  - WordPress core fires `update_wpmu_options` only from `wp-admin/network/settings.php` after `current_user_can( 'manage_network_options' )` and `check_admin_referer( 'siteoptions' )`.
  - Adjacent REST settings routes use `Helper::get_api_permission()`, which requires `is_user_logged_in()` and `current_user_can( 'manage_options' )`.
- Improvement idea:
  - Model core admin-only hooks such as `update_wpmu_options` with their upstream capability and nonce gates.
  - Propagate simple REST permission helper methods into route sink reachability.

### final phparser pending batch admin-gated cleanup and login-template false positives

- Plugins: `wp-fail2ban`, `fluent-crm`, `imagemagick-engine`, `export-all-urls`, `ultimate-dashboard`
- Candidates: `artifacts/phparser/phparser-20260406-145336/candidate-queue.tsv` queue IDs `719`, `732`, `1082`, `1593`, `1094`, `1147`, `1148`, `1149`, `1150`, `1151`, `1152`, `1153`, `1154`
- Evidence:
  - `artifacts/phparser/phparser-20260406-145336/evidence/719-wp-fail2ban-source-review.md`
  - `artifacts/phparser/phparser-20260406-145336/evidence/732-fluent-crm-source-review.md`
  - `artifacts/phparser/phparser-20260406-145336/evidence/1082-imagemagick-engine-source-review.md`
  - `artifacts/phparser/phparser-20260406-145336/evidence/1593-export-all-urls-source-review.md`
  - `artifacts/phparser/phparser-20260406-145336/evidence/1094-ultimate-dashboard-source-review.md`
- False-positive pattern:
  - `wp-fail2ban/admin/widgets.php:53` updates a fixed site option with `update_site_option( $dismiss, intval( $_GET[ $dismiss ] ) );`, but the dashboard widget is only registered for `manage_options` or network `manage_network_options` users and is a low-value dismiss preference.
  - `fluent-crm/app/Http/Controllers/CompanyController.php:623` calls `wp_delete_file($filepath);`, but `$filepath` is generated under `uploads/fluentcrm/` from `md5($url . time()) . '-' . basename($logoUrl)` and the route group is behind `CompanyPolicy`.
  - `imagemagick-engine/imagemagick-engine.php:819` calls `@ unlink( $dir . $old_file );`, but the AJAX handler requires `manage_options`, a plugin nonce, and image-processing mode, while `$old_file` comes from WordPress attachment metadata during derivative regeneration.
  - `export-all-urls/extract-all-urls-settings.php:375` calls `unlink($file)`, but the settings page requires `manage_options`, a nonce generated by `wp_nonce_url()`, and path checks restricting deletion to `.CSV` files in the current uploads directory.
  - `ultimate-dashboard/modules/login-customizer/templates/udb-login-page.php:587` copies WordPress' `RELOCATE` `update_option( 'siteurl', $url );` branch, and lines `240`, `366`, `370`, `797`, `931`, `943`, `1167`, and `1183` are escaped login/register UI outputs inside a Customizer preview template loaded only for logged-in `manage_options` users.
- Improvement idea:
  - Downgrade fixed admin-widget dismiss toggles and generated notice/preference option writes when the option key is not request-controlled.
  - Track generated upload cleanup paths that combine a fixed upload base, generated prefixes, and `basename()` instead of raw request paths.
  - Recognize WordPress image derivative cleanup from attachment metadata as lower-risk than arbitrary unlink.
  - Model upload-directory plus extension allowlists before ranking decoded-path `unlink()` calls.
  - Treat Customizer-only preview templates loaded after `is_user_logged_in()` and `manage_options` gates as admin-only UI, and distinguish escaped login form reflections from record disclosure.
