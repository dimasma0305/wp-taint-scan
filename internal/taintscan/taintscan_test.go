package taintscan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/dimasma0305/php-parser-go/ast"
	"github.com/dimasma0305/php-parser-go/parsetree"
)

func edgeSetContains(edges map[string]struct{}, key string) bool {
	if edges == nil {
		return false
	}
	_, ok := edges[key]
	return ok
}

func TestAnalyzeRootFindsGeoStyleLoadTemplate(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "geo.php"), `<?php
class GeoDemo {
    public static function locate_template($name) {
        return '/tmp/' . $name;
    }

    public function render() {
        $template_base = isset($_GET['template']) ? $_GET['template'] : '';
        load_template(GeoDemo::locate_template($template_base));
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "path-transversal" {
		t.Fatalf("check_id = %q, want path-transversal", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 8 {
		t.Fatalf("source line = %d, want 8", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsWeakCapabilityAuthenticatedAjaxSQLSinkThroughWideNestedReceiverBuilder(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-wide-nested-receiver.php"), `<?php
function json_encode($value) { return $value; }
function add_action($hook, $callback) {}
function current_user_can($cap) { return true; }
function sanitize_text_field($value) { return $value; }

class WPDB {
    public $posts = 'wp_posts';
    public function prepare($query, ...$args) { return $query; }
    public function get_results($query) {}
}

$wpdb = new WPDB();

class Item {
    protected $title;
    protected $type;

    public function __construct($type = 'all', $title = "", $authorId = 0, $postStatus = "", $shareStatus = "", $publishDate = '', $schedDate = '', $showByDate = '', $showByNetwork = 0, $userAuthId = 0, $blogPostId = 0, $currentPage = 0, $postCat = 0, $postType = "", $userLang = "en", $results_per_page = 25, $searchPostSharedById = 0, $searchSharedToNetwork = 0, $searchSharedAtDateStart = 0, $searchSharedAtDateEnd = 0) {
        $this->title = $title;
        $this->type = $postType;
    }

    protected function getData() {
        global $wpdb;
        $cleanTitle = '';
        if (!empty($this->title)) {
            $cleanTitle = $wpdb->prepare(' AND posts.post_title LIKE %s', '%' . trim($this->title) . '%');
        }
        $postTypes = " ";
        if (!empty($this->type)) {
            $postTypes .= " posts.post_type LIKE '%" . $this->type . "%' ";
        }
        $sql = "SELECT $wpdb->posts.ID
        FROM $wpdb->posts
        WHERE 1=1 $cleanTitle
        AND $postTypes";
        $wpdb->get_results($sql);
    }

    public function getItemHtml() {
        $this->getData();
        return '';
    }
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_demo_sql', array($this, 'run'));
    }

    public function run() {
        if (!current_user_can('read')) {
            return;
        }
        $title = sanitize_text_field($_POST['title']);
        $type = sanitize_text_field($_POST['ptype']);
        $item = new Item("all", $title, 0, "", "", "", "", "", 0, 0, 0, 0, 0, $type, "en", 25, 0, 0, 0, 0);
        echo json_encode(array('result' => true, 'content' => $item->getItemHtml()));
    }
}

new DemoSQL();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1; results=%#v", len(result.Payload.Results), result.Payload.Results)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 38 {
		t.Fatalf("sink line = %d, want 38", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 57 {
		t.Fatalf("source line = %d, want 57", finding.Extra.Trace.Source.Line)
	}
}

func TestFileReadSummaryDropsNonPathReturnPathWritesAtGeneration(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "return-path-writes.php"), `<?php
function helper($input) {
    $payload = array();
    $payload['file_path'] = $input['file_path'];
    $payload['plan_name'] = $input['plan_name'];
    return $payload;
}

function run() {
    $payload = helper($_GET);
    file_get_contents($payload['file_path']);
}

run();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "read"
	_ = engine.run()

	helperKey := engine.lookupFunctionKey("", "helper")
	if helperKey == "" {
		t.Fatal("missing helper key")
	}
	item := engine.summaries[helperKey]
	if len(item.ReturnPathWrites) == 0 {
		t.Fatal("expected file-path return write to remain")
	}
	for path := range item.ReturnPathWrites {
		if !fileStructuralPathRelevant(path) {
			t.Fatalf("unexpected non-path return write retained: %q", path)
		}
	}
}

func TestAnalyzeRootFindsTemplateHelperFallbackChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "geo-fallback.php"), `<?php
function locate_template($x) { return $x; }
function path_join($a, $b) { return $a . '/' . $b; }

class GeoDemo {
    public static function locate_template($template_base) {
        $template = locate_template(array("geo-mashup-$template_base.php"));
        if (empty($template)) {
            $template = path_join('/plugin', "default-templates/$template_base.php");
        }
        if (empty($template)) {
            $template = path_join('/plugin', 'default-templates/info-window.php');
        }
        return $template;
    }

    public static function render() {
        load_template(GeoDemo::locate_template($_GET['template']));
    }
}

GeoDemo::render();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "path-transversal" {
		t.Fatalf("check_id = %q, want path-transversal", finding.CheckID)
	}
	if finding.Start.Line != 18 {
		t.Fatalf("sink line = %d, want 18", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsHelperChainToRequire(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
class FilesDemo {
    public function getCurrentURL() {
        return rawurldecode($_SERVER['REQUEST_URI']);
    }

    public function getOriginalPath($url) {
        return '/tmp/' . ltrim($url, '/');
    }

    public function showFile($url) {
        $new_path = $this->getOriginalPath($url);
        require_once $new_path;
    }

    public function maybeShow() {
        $this->showFile($this->getCurrentURL());
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "path-transversal" {
		t.Fatalf("check_id = %q, want path-transversal", finding.CheckID)
	}
	if finding.Start.Line != 13 {
		t.Fatalf("sink line = %d, want 13", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 4 {
		t.Fatalf("source line = %d, want 4", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsUnsafeEvalFromShortcodeClassConstTag(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-eval.php"), `<?php
function add_shortcode($tag, $callback) {}

class DemoShortcode {
    public const TAG = 'demo';

    public function __construct() {
        add_shortcode(self::TAG, array($this, 'render'));
    }

    public function render($atts) {
        $snippet = (object) array('code' => 'echo "safe";');
        extract($atts);
        eval("?>\n\n" . $snippet->code);
    }
}

new DemoShortcode();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "unsafe-use" {
			continue
		}
		for _, entry := range finding.Extra.Context.EntryPoints {
			if entry.Kind == "shortcode" && entry.Name == "demo" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("results = %#v, want unsafe-use with shortcode entrypoint", result.Payload.Results)
	}
}

func TestAnalyzeRootDoesNotFlagUnsafeEvalWhenExtractUsesEXTRSKIP(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-eval-safe.php"), `<?php
function add_shortcode($tag, $callback) {}

class DemoShortcode {
    public const TAG = 'demo';

    public function __construct() {
        add_shortcode(self::TAG, array($this, 'render'));
    }

    public function render($atts) {
        $snippet = (object) array('code' => 'echo "safe";');
        extract($atts, EXTR_SKIP);
        eval("?>\n\n" . $snippet->code);
    }
}

new DemoShortcode();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsParsedURLChainToFilesystemRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
function home_url() {
    return 'https://example.test';
}

function wp_parse_url($url, $component = -1) {
    return parse_url($url, $component);
}

class FilesystemDemo {
    public function get_contents($path) {
        return $path;
    }
}

class FilesDemo {
    public function getCurrentURL() {
        return rawurldecode($_SERVER['REQUEST_URI']);
    }

    public function getOriginalUrl($url) {
        $parts = wp_parse_url($url);
        if (!isset($parts['path'])) {
            return $url;
        }

        $path = parse_url(home_url(), PHP_URL_PATH);
        if ($path <> '') {
            $parts['path'] = preg_replace('/^' . preg_quote($path, '/') . '/', '', $parts['path']);
        }

        return $parts['scheme'] . '://' . $parts['host'] . $path . $parts['path'];
    }

    public function getOriginalPath($new_url) {
        $new_path = str_replace(home_url(), '', $new_url);
        if (strpos($new_path, '?') !== false) {
            $new_path = substr($new_path, 0, strpos($new_path, '?'));
        }
        return '/tmp/' . ltrim($new_path, '/');
    }

    public function showFile($url) {
        $wp_filesystem = new FilesystemDemo();
        $new_url = $this->getOriginalUrl($url);
        $new_path = $this->getOriginalPath($new_url);
        $wp_filesystem->get_contents($new_path);
    }

    public function maybeShowFile() {
        $this->showFile($this->getCurrentURL());
    }
}

(new FilesDemo())->maybeShowFile();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" {
			continue
		}
		if finding.Start.Line != 47 {
			continue
		}
		found = true
		if finding.Extra.Trace.Source.Line != 18 {
			t.Fatalf("source line = %d, want 18", finding.Extra.Trace.Source.Line)
		}
	}
	if !found {
		t.Fatalf("did not find request-path-read-delete at line 47; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsRealpathChainToRequire(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
class FilesDemo {
    public function getCurrentURL() {
        return rawurldecode($_SERVER['REQUEST_URI']);
    }

    public function getOriginalPath($url) {
        return '/tmp/' . ltrim($url, '/');
    }

    public function showFile($url) {
        $new_path = $this->getOriginalPath($url);
        $new_path = realpath($new_path);
        require_once $new_path;
    }

    public function maybeShowFile() {
        $this->showFile($this->getCurrentURL());
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "path-transversal" {
			continue
		}
		if finding.Start.Line != 14 {
			continue
		}
		found = true
		if finding.Extra.Trace.Source.Line != 4 {
			t.Fatalf("source line = %d, want 4", finding.Extra.Trace.Source.Line)
		}
	}
	if !found {
		t.Fatalf("did not find path-transversal at line 14; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSuppressesCanonicalRealpathGuardedDeleteSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "guarded-delete.php"), `<?php
define('ROOT_DIR', '/tmp/root');

class Demo {
    public function clean($items) {
        foreach ($items as $name) {
            $dir = ROOT_DIR . '/' . $name;
            if ($dir !== realpath($dir)) {
                continue;
            }
            unlink($dir);
            rmdir(ROOT_DIR . '/' . $name);
        }
    }

    public function handle() {
        $this->clean(array($_POST['key']));
    }
}

(new Demo())->handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0: %#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootFindsUnguardedDeleteSinkWithoutCanonicalRealpathGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "unguarded-delete.php"), `<?php
define('ROOT_DIR', '/tmp/root');

class Demo {
    public function clean($items) {
        foreach ($items as $name) {
            $dir = ROOT_DIR . '/' . $name;
            unlink($dir);
            rmdir(ROOT_DIR . '/' . $name);
        }
    }

    public function handle() {
        $this->clean(array($_POST['key']));
    }
}

(new Demo())->handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" && finding.CheckID != "wp-request-file-delete-without-cap-check" {
			continue
		}
		if finding.Start.Line != 8 && finding.Start.Line != 9 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find unguarded delete sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSuppressesRealpathTrustedPrefixGuardedDeleteSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "guarded-prefix-delete.php"), `<?php
class Demo {
    public function handle() {
        $file = realpath($_POST['path']);
        $uploads_dir = '/var/www/html/wp-content/uploads/wp_dndcf7_uploads';
        if ($file && file_exists($file) && strpos($file, $uploads_dir) === 0) {
            wp_delete_file($file);
        }
    }
}

(new Demo())->handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0: %#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootDoesNotSuppressRealpathDeleteSinkWithRequestDerivedPrefixGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "request-prefix-delete.php"), `<?php
class Demo {
    public function handle() {
        $file = realpath($_POST['path']);
        $uploads_dir = $_POST['prefix'];
        if ($file && file_exists($file) && strpos($file, $uploads_dir) === 0) {
            wp_delete_file($file);
        }
    }
}

(new Demo())->handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" && finding.CheckID != "wp-request-file-delete-without-cap-check" {
			continue
		}
		if finding.Start.Line != 7 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find request-derived prefix delete sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootDoesNotSuppressRealpathDeleteSinkWithBroadRootPrefixGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "broad-root-prefix-delete.php"), `<?php
class Demo {
    public function handle() {
        $file = realpath($_POST['path']);
        $root = '/';
        if ($file && file_exists($file) && strpos($file, $root) === 0) {
            wp_delete_file($file);
        }
    }
}

(new Demo())->handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" && finding.CheckID != "wp-request-file-delete-without-cap-check" {
			continue
		}
		if finding.Start.Line != 7 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find broad-root prefix delete sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsHideMyWPStyleShowFileRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
define('HMW_DYNAMIC_FILES', true);
define('PHP_URL_PATH', 5);

function home_url() {
    return 'https://example.test';
}

function is_ssl() {
    return true;
}

function wp_parse_url($url, $component = -1) {
    return parse_url($url, $component);
}

function trailingslashit($value) {
    return rtrim($value, '/') . '/';
}

class FilesystemDemo {
    public function exists($path) {
        return true;
    }
    public function get_contents($path) {
        return $path;
    }
}

class FilesDemo {
    public $_files = array('css');
    public $_safe_files = array('cssh');
    public $_rewrites = array();

    public function maybeShowFile() {
        if ($this->isFile($this->getCurrentURL())) {
            $this->showFile($this->getCurrentURL());
        }
    }

    public function isFile($url) {
        return 'css';
    }

    public function getCurrentURL() {
        $url = '';
        if (isset($_SERVER['HTTP_HOST'])) {
            $url = is_ssl() ? 'https://' : 'http://';
            $url .= $_SERVER['HTTP_HOST'];
            $url .= rawurldecode($_SERVER['REQUEST_URI']);
        }
        return $url;
    }

    public function buildRedirect() {
        $this->_rewrites['from'][] = '#^/hidden/(.*)#i';
        $this->_rewrites['to'][] = '/wp-content/$1';
    }

    public function getOriginalUrl($url) {
        if (empty($this->_rewrites)) {
            $this->buildRedirect();
        }
        $parse_url = wp_parse_url($url);
        if (!isset($parse_url['path'])) {
            return $url;
        }
        $path = wp_parse_url(home_url(), PHP_URL_PATH);
        if ($path <> '') {
            $parse_url['path'] = preg_replace('/^' . preg_quote($path, '/') . '/', '', $parse_url['path']);
        }
        if (isset($this->_rewrites['from']) && isset($this->_rewrites['to']) && !empty($this->_rewrites['from']) && !empty($this->_rewrites['to'])) {
            $parse_url['path'] = preg_replace($this->_rewrites['from'], $this->_rewrites['to'], $parse_url['path'], 1);
        }
        if (!isset($parse_url['scheme'])) {
            $parse_url['scheme'] = 'https';
        }
        if (isset($parse_url['port']) && $parse_url['port'] <> 80) {
            $new_url = $parse_url['scheme'] . '://' . $parse_url['host'] . ':' . $parse_url['port'] . $path . $parse_url['path'];
        } else {
            $new_url = $parse_url['scheme'] . '://' . $parse_url['host'] . $path . $parse_url['path'];
        }
        if (isset($parse_url['query']) && !empty($parse_url['query'])) {
            $query = $parse_url['query'];
            $query = str_replace(array('?', '%3F'), '&', $query);
            $new_url .= (!strpos($new_url, '?') ? '?' : '&') . $query;
        }
        return $new_url;
    }

    public function getOriginalPath($new_url) {
        $new_path = str_replace(home_url(), '', $new_url);
        if (strpos($new_path, '?') !== false) {
            $new_path = substr($new_path, 0, strpos($new_path, '?'));
        }
        return '/tmp/' . ltrim($new_path, '/');
    }

    public function showFile($url) {
        $wp_filesystem = new FilesystemDemo();
        if (HMW_DYNAMIC_FILES) {
            $url = str_replace($this->_safe_files, $this->_files, $url);
        }
        $this->buildRedirect();
        $url_no_query = ((strpos($url, '?') !== false) ? substr($url, 0, strpos($url, '?')) : $url);
        $new_url = $this->getOriginalUrl($url);
        $new_url_no_query = ((strpos($new_url, '?') !== false) ? substr($new_url, 0, strpos($new_url, '?')) : $new_url);
        $new_path = $this->getOriginalPath($new_url);
        if ($ext = $this->isFile($new_url)) {
            if ($wp_filesystem->exists($new_path)) {
                if (wp_parse_url($url) && $url <> $new_url) {
                    $new_url_no_query = trailingslashit($new_url_no_query);
                }
                $content = $wp_filesystem->get_contents($new_path);
                echo $content;
            }
        }
    }
}

$_SERVER['HTTP_HOST'] = 'example.test';
$_SERVER['REQUEST_URI'] = '/hidden/../../wp-activate.php';
(new FilesDemo())->maybeShowFile();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" {
			continue
		}
		if finding.Start.Line != 114 {
			continue
		}
		found = true
	}
	if !found {
		t.Fatalf("did not find hide-my-wp style read sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsHideMyWPStyleShowFileInclude(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
const HMW_DYNAMIC_FILES = false;
function home_url() { return 'https://example.test'; }
function wp_parse_url($url, $component = -1) { return parse_url($url); }
function trailingslashit($value) { return rtrim($value, '/') . '/'; }

class ToolsDemo {
    public static function isMultisites() { return true; }
    public static function getOption($key) { return 'activate'; }
}

class FilesystemDemo {
    public function exists($path) {
        return true;
    }
}

class FilesDemo {
    public $_rewrites = array();
    public $_files = array();
    public $_safe_files = array();

    public function getCurrentURL() {
        $url = 'https://example.test';
        $url .= rawurldecode($_SERVER['REQUEST_URI']);
        return $url;
    }

    public function buildRedirect() {}

    public function getOriginalUrl($url) {
        $parse_url = wp_parse_url($url);
        if (!isset($parse_url['path'])) {
            return $url;
        }
        return 'https://example.test/' . ltrim($parse_url['path'], '/');
    }

    public function getOriginalPath($new_url) {
        $new_path = str_replace(home_url(), '', $new_url);
        if (strpos($new_path, '?') !== false) {
            $new_path = substr($new_path, 0, strpos($new_path, '?'));
        }
        return '/tmp/' . ltrim($new_path, '/');
    }

    public function showFile($url) {
        $wp_filesystem = new FilesystemDemo();
        $this->buildRedirect();
        $url_no_query = ((strpos($url, '?') !== false) ? substr($url, 0, strpos($url, '?')) : $url);
        $new_url = $this->getOriginalUrl($url);
        $new_url_no_query = ((strpos($new_url, '?') !== false) ? substr($new_url, 0, strpos($new_url, '?')) : $new_url);
        $new_path = $this->getOriginalPath($new_url);
        if (false) {
        } elseif ($url <> $new_url) {
            if (false) {
            } elseif (ToolsDemo::isMultisites() && stripos(trailingslashit($url_no_query), '/' . ToolsDemo::getOption('hmwp_activate_url') . '/' ) !== false) {
                $new_path = realpath($new_path);
                if (strpos($new_path, 'wp-activate.php') && $wp_filesystem->exists($new_path)) {
                    require_once $new_path;
                }
            }
        }
    }
}

$_SERVER['REQUEST_URI'] = '/hidden/../../wp-activate.php';
(new FilesDemo())->showFile((new FilesDemo())->getCurrentURL());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "path-transversal" {
			continue
		}
		if finding.Start.Line != 60 {
			continue
		}
		found = true
	}
	if !found {
		t.Fatalf("did not find hide-my-wp style include sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsHeaderBackedConstructorDeleteChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "backup-heart.php"), `<?php
function getallheaders() {
    return $_SERVER;
}

class HeartDemo {
    public $manifest;

    public function __construct($remote_settings = []) {
        $this->manifest = $remote_settings['manifest'];
    }

    public function remove_commons() {
        if (file_exists($this->manifest)) {
            @unlink($this->manifest);
        }
    }

    public function send_success() {
        $this->remove_commons();
    }

    public function handle_batch() {
        $this->send_success();
    }
}

$fields = getallheaders();
foreach ($fields as $key => $value) {
    unset($fields[$key]);
    $fields[strtolower($key)] = $value;
}

$request = new HeartDemo([
    'manifest' => $fields['http_content_manifest'],
]);
$request->handle_batch();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" {
			continue
		}
		if finding.Start.Line != 15 {
			continue
		}
		found = true
	}
	if !found {
		t.Fatalf("did not find header-backed constructor delete sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsBuiltinHeaderBackedDeleteAcrossFiles(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "backup-heart.php"), `<?php
namespace BMI\Plugin\Heart;

try {
    require_once __DIR__ . '/bypasser.php';
    $fields = getallheaders();
    foreach ($fields as $key => $value) {
        unset($fields[$key]);
        $fields[strtolower($key)] = $value;
    }
    $request = new BMI_Backup_Heart(true, false, false, false, false, false, false, [
        'manifest' => $fields['http_content_manifest'],
    ]);
    $request->handle_batch();
} catch (\Throwable $e) {
}
`)
	writePHP(t, filepath.Join(root, "bypasser.php"), `<?php
namespace BMI\Plugin\Heart;

class BMI_Backup_Heart {
    public $manifest;

    public function __construct($curl = false, $config = false, $content = false, $backups = false, $abs = false, $dir = false, $url = false, $remote_settings = []) {
        $this->manifest = $remote_settings['manifest'];
    }

    public function remove_commons() {
        if (file_exists($this->manifest)) {
            @unlink($this->manifest);
        }
    }

    public function send_success() {
        $this->remove_commons();
    }

    public function handle_batch() {
        $this->send_success();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" {
			continue
		}
		if strings.HasSuffix(finding.Path, "bypasser.php") && finding.Start.Line == 13 {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find builtin header-backed delete sink across files; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsDefinedHeaderBackedDeleteAcrossFiles(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "backup-heart.php"), `<?php
namespace BMI\Plugin\Heart;

try {
    require_once __DIR__ . '/bypasser.php';
    $fields = getallheaders();
    foreach ($fields as $key => $value) {
        unset($fields[$key]);
        $fields[strtolower($key)] = $value;
    }
    define('BMI_TMP', $fields['http_content_tmp']);
    define('BMI_BACKUPS', $fields['http_content_backups']);
    $request = new BMI_Backup_Heart([
        'manifest' => $fields['http_content_manifest'],
    ]);
    $request->handle_batch();
} catch (\Throwable $e) {
}
`)
	writePHP(t, filepath.Join(root, "bypasser.php"), `<?php
namespace BMI\Plugin\Heart;

class BMI_Backup_Heart {
    public $manifest;
    public $fileList;
    public $lockCli;

    public function __construct($remote_settings = []) {
        $this->manifest = $remote_settings['manifest'];
        $this->fileList = BMI_TMP . '/files_latest.list';
        $this->lockCli = BMI_BACKUPS . '/.backup_cli_lock';
    }

    public function remove_commons() {
        if (file_exists($this->manifest)) {
            @unlink($this->manifest);
        }
        if (file_exists($this->fileList)) {
            @unlink($this->fileList);
        }
        if (file_exists($this->lockCli)) {
            @unlink($this->lockCli);
        }
    }

    public function handle_batch() {
        $this->remove_commons();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" {
			continue
		}
		if strings.HasSuffix(finding.Path, "bypasser.php") && finding.Start.Line == 17 {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find define-backed delete sink across files; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsConstructorDefinedDeleteAcrossDeepMethodChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "backup-heart.php"), `<?php
namespace BMI\Plugin\Heart;

require_once __DIR__ . '/bypasser.php';
$fields = getallheaders();
foreach ($fields as $key => $value) {
    unset($fields[$key]);
    $fields[strtolower($key)] = $value;
}
$request = new BMI_Backup_Heart(
    true,
    false,
    false,
    false,
    false,
    false,
    false,
    array(
        'manifest' => $fields['http_content_manifest'],
        'bmitmp' => $fields['http_content_bmitmp'],
    ),
    0,
    0,
    0
);
$request->handle_batch();
`)
	writePHP(t, filepath.Join(root, "bypasser.php"), `<?php
namespace BMI\Plugin\Heart;

class BMI_Backup_Heart {
    public $manifest;
    public $fileList;

    public function __construct($curl = false, $config = false, $content = false, $backups = false, $abs = false, $dir = false, $url = false, $remote_settings = [], $it = 0, $dbit = 0, $dblast = 0) {
        if (isset($remote_settings['bmitmp'])) {
            define('BMI_TMP', $remote_settings['bmitmp']);
        }
        $this->manifest = $remote_settings['manifest'];
        $this->fileList = BMI_TMP . '/files_latest.list';
    }

    public function remove_commons() {
        if (file_exists($this->manifest)) {
            @unlink($this->manifest);
        }
        if (file_exists($this->fileList)) {
            @unlink($this->fileList);
        }
    }

    public function send_error() {
        $this->remove_commons();
    }

    public function zip_batch() {
        $this->send_error();
    }

    public function handle_batch() {
        $this->zip_batch();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" {
			continue
		}
		if strings.HasSuffix(finding.Path, "bypasser.php") && finding.Start.Line == 18 {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find constructor-defined delete sink across deep chain; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsBackupMigrationRealisticHeartDeleteAcrossFiles(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "backup-heart.php"), `<?php
namespace BMI\Plugin\Heart;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    exit;
}

function __getallheaders() {
    $headers = [];
    foreach ($_SERVER as $name => $value) {
        if (substr($name, 0, 5) == 'HTTP_') {
            $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
        }
    }
    return $headers;
}

function filterChainFix($content) {
    return $content;
}

require_once filterChainFix(__DIR__) . '/bypasser.php';
$fields = getallheaders();
if (!isset($fields['Content-Content']) && !isset($fields['content-content'])) {
    $fields = __getallheaders();
}
foreach ($fields as $key => $value) {
    unset($fields[$key]);
    $fields[strtolower($key)] = $value;
}

define('BMI_CURL_REQUEST', true);
define('ABSPATH', filterChainFix($fields['content-abs']));
define('BMI_BACKUPS', $fields['content-backups']);
define('BMI_ROOT_DIR', filterChainFix($fields['content-dir']));
define('BMI_INCLUDES', BMI_ROOT_DIR . 'includes');

$request = new BMI_Backup_Heart(
    true,
    $fields['content-configdir'],
    $fields['content-content'],
    $fields['content-backups'],
    filterChainFix($fields['content-abs']),
    filterChainFix($fields['content-dir']),
    $fields['content-url'],
    [
        'identy' => $fields['content-identy'],
        'manifest' => $fields['content-manifest'],
        'backupname' => $fields['content-name'],
        'browser' => $fields['content-browser'],
        'bmitmp' => $fields['content-bmitmp'],
    ],
    $fields['content-it'],
    $fields['content-dbit'],
    $fields['content-dblast']
);
$request->handle_batch();
`)
	writePHP(t, filepath.Join(root, "bypasser.php"), `<?php
namespace BMI\Plugin\Heart;

if (!(defined('BMI_CURL_REQUEST') || defined('ABSPATH'))) exit;

class BMI_Backup_Heart {
    public $it;
    public $dbit;
    public $manifest;
    public $identy;
    public $backupname;
    public $browserSide;
    public $identyfile;
    public $fileList;
    public $lock_cli;

    function __construct($curl = false, $config = false, $content = false, $backups = false, $abs = false, $dir = false, $url = false, $remote_settings = [], $it = 0, $dbit = 0, $dblast = 0) {
        if (isset($remote_settings['bmitmp'])) {
            if (!defined('BMI_TMP')) define('BMI_TMP', $remote_settings['bmitmp']);
        }

        $this->it = intval($it);
        $this->dbit = intval($dbit);
        $this->identy = $remote_settings['identy'];
        $this->manifest = $remote_settings['manifest'];
        $this->backupname = $remote_settings['backupname'];
        $this->browserSide = ($remote_settings['browser'] === true || $remote_settings['browser'] === 'true') ? true : false;
        $this->identyfile = BMI_TMP . DIRECTORY_SEPARATOR . '.' . $this->identy;
        $this->fileList = BMI_TMP . DIRECTORY_SEPARATOR . 'files_latest.list';
        $this->lock_cli = BMI_BACKUPS . '/.backup_cli_lock';
    }

    public function remove_commons() {
        $identyfile = $this->identyfile;
        if (file_exists($this->fileList)) @unlink($this->fileList);
        if (file_exists($this->manifest)) @unlink($this->manifest);
        if (file_exists($identyfile)) @unlink($identyfile);
        if (file_exists($this->lock_cli)) @unlink($this->lock_cli);
    }

    public function send_error($reason = false, $abort = false) {
        $this->remove_commons();
        if (file_exists(BMI_BACKUPS . DIRECTORY_SEPARATOR . $this->backupname)) @unlink(BMI_BACKUPS . DIRECTORY_SEPARATOR . $this->backupname);
        exit;
    }

    public function make_file_groups() {
        return $this->send_error('missing list', true);
    }

    public function zip_batch() {
        $this->make_file_groups();
    }

    public function handle_batch() {
        $this->zip_batch();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" {
			continue
		}
		if strings.HasSuffix(finding.Path, "bypasser.php") && finding.Start.Line == 36 {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find realistic backup-heart delete sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSuppressesIncludeAfterPathSanitizerHelperAcrossConstructorSummary(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function filterChainFix($content) {
    if (!is_string($content)) exit;
    if (strpos($content, "php:")) exit;
    if (strpos($content, "|")) exit;
    if (!(is_dir($content) || file_exists($content))) exit;
    return $content;
}

function build_path($path) {
    return filterChainFix($path);
}

$safe = build_path($_POST['dir']);
require_once $safe;
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	for _, finding := range result.Payload.Results {
		if finding.CheckID == "path-transversal" {
			t.Fatalf("unexpected include finding after path sanitizer helper summary: %#v", result.Payload.Results)
		}
	}
}

func TestAnalyzeRootFindsIncludeWithoutPathSanitizerHelperAcrossConstructorSummary(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function filterChainFix($content) {
    return $content;
}

function build_path($path) {
    return filterChainFix($path);
}

$unsafe = build_path($_POST['dir']);
require_once $unsafe;
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "path-transversal" {
			continue
		}
		if strings.HasSuffix(finding.Path, "main.php") && finding.Start.Line == 11 {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find include sink without path sanitizer helper summary; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSuppressesIncludeAfterPathSanitizerAcrossReceiverSummary(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function filterChainFix($content) {
    if (!is_string($content)) exit;
    if (strpos($content, "php:")) exit;
    if (strpos($content, "|")) exit;
    if (!(is_dir($content) || file_exists($content))) exit;
    return $content;
}

class Loader {
    private $dir;

    function __construct($dir) {
        $this->dir = $dir;
    }

    function load() {
        $alternative = dirname($this->dir) . '/backup-backup-pro/includes/pcl.php';
        require_once $alternative;
    }
}

$loader = new Loader(filterChainFix($_POST['dir']));
$loader->load();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	for _, finding := range result.Payload.Results {
		if finding.CheckID == "path-transversal" {
			t.Fatalf("unexpected include finding after receiver-summary path sanitizer: %#v", result.Payload.Results)
		}
	}
}

func TestAnalyzeRootFindsHideMyWPNestedTemplateRedirectInclude(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
function add_action($hook, $callback, $priority = 10) {}
function is_404() { return true; }
function home_url() { return 'https://example.test'; }
function wp_parse_url($url, $component = -1) { return parse_url($url); }
function trailingslashit($value) { return rtrim($value, '/') . '/'; }

class ObjController {
    public static function getClass($class) {
        return null;
    }
}

class ToolsDemo {
    public static function isMultisites() { return true; }
    public static function getOption($key) { return 'activate'; }
}

class FilesystemDemo {
    public function exists($path) {
        return true;
    }
}

class FilesDemo {
    public function getCurrentURL() {
        return 'https://example.test' . rawurldecode($_SERVER['REQUEST_URI']);
    }

    public function getOriginalUrl($url) {
        $parts = wp_parse_url($url);
        return 'https://example.test/' . ltrim($parts['path'], '/');
    }

    public function getOriginalPath($new_url) {
        return '/tmp/' . ltrim(str_replace(home_url(), '', $new_url), '/');
    }

    public function showFile($url) {
        $wp_filesystem = new FilesystemDemo();
        $url_no_query = ((strpos($url, '?') !== false) ? substr($url, 0, strpos($url, '?')) : $url);
        $new_url = $this->getOriginalUrl($url);
        $new_path = $this->getOriginalPath($new_url);
        if ($url <> $new_url) {
            if (ToolsDemo::isMultisites() && stripos(trailingslashit($url_no_query), '/' . ToolsDemo::getOption('hmwp_activate_url') . '/' ) !== false) {
                $new_path = realpath($new_path);
                if (strpos($new_path, 'wp-activate.php') && $wp_filesystem->exists($new_path)) {
                    require_once $new_path;
                }
            }
        }
    }

    public function maybeShowNotFound() {
        if (is_404()) {
            $this->showFile($this->getCurrentURL());
        }
    }
}

class RewriteDemo {
    public function hookChangePaths() {
        add_action('template_redirect', array(ObjController::getClass('FilesDemo'), 'maybeShowNotFound'), 1);
    }
}

add_action('init', array(new RewriteDemo(), 'hookChangePaths'));
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "path-transversal" {
			continue
		}
		if finding.Start.Line != 48 {
			continue
		}
		found = true
	}
	if !found {
		t.Fatalf("did not find nested template_redirect include sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsHideMyWPStyleNestedTemplateRedirectInclude(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
const HMW_DYNAMIC_FILES = false;
function add_action($hook, $callback, $priority = 10) {}
function is_404() { return true; }
function is_ssl() { return false; }
function home_url() { return 'https://example.test'; }
function wp_parse_url($url, $component = -1) { return parse_url($url); }
function trailingslashit($value) { return rtrim($value, '/') . '/'; }

class ObjController {
    public static function getClass($class) {
        return null;
    }
}

class ToolsDemo {
    public static function getOption($key) {
        if ($key === 'hmwp_activate_url') {
            return 'activate';
        }
        return '';
    }
    public static function getRootPath() {
        return '/tmp/';
    }
    public static function isMultisites() {
        return true;
    }
    public static function getValue($key) {
        return false;
    }
}

class FilesystemDemo {
    public function exists($path) {
        return true;
    }
}

class FilesDemo {
    public $_rewrites = array();

    public function getCurrentURL() {
        $url = '';
        if (isset($_SERVER['HTTP_HOST'])) {
            $url = is_ssl() ? 'https://' : 'http://';
            $url .= $_SERVER['HTTP_HOST'];
            $url .= rawurldecode($_SERVER['REQUEST_URI']);
        }
        return $url;
    }

    public function buildRedirect() {}

    public function getOriginalUrl($url) {
        if (empty($this->_rewrites)) {
            $this->buildRedirect();
        }
        $parse_url = wp_parse_url($url);
        if (!isset($parse_url['path'])) {
            return $url;
        }
        $path = wp_parse_url(home_url(), PHP_URL_PATH);
        if ($path <> '') {
            $parse_url['path'] = preg_replace('/^' . preg_quote($path, '/') . '/', '', $parse_url['path']);
        }
        if (!isset($parse_url['scheme'])) {
            $parse_url['scheme'] = 'https';
        }
        if (isset($parse_url['port']) && $parse_url['port'] <> 80) {
            $new_url = $parse_url['scheme'] . '://' . $parse_url['host'] . ':' . $parse_url['port'] . $path . $parse_url['path'];
        } else {
            $new_url = $parse_url['scheme'] . '://' . $parse_url['host'] . $path . $parse_url['path'];
        }
        if (isset($parse_url['query']) && !empty($parse_url['query'])) {
            $query = $parse_url['query'];
            $query = str_replace(array('?', '%3F'), '&', $query);
            $new_url .= (!strpos($new_url, '?') ? '?' : '&') . $query;
        }
        return $new_url;
    }

    public function getOriginalPath($new_url) {
        $new_path = str_replace(home_url(), '', $new_url);
        if (strpos($new_path, '?') !== false) {
            $new_path = substr($new_path, 0, strpos($new_path, '?'));
        }
        return ToolsDemo::getRootPath() . ltrim($new_path, '/');
    }

    public function showFile($url) {
        $wp_filesystem = new FilesystemDemo();
        $this->buildRedirect();
        $url_no_query = ((strpos($url, '?') !== false) ? substr($url, 0, strpos($url, '?')) : $url);
        $new_url = $this->getOriginalUrl($url);
        $new_url_no_query = ((strpos($new_url, '?') !== false) ? substr($new_url, 0, strpos($new_url, '?')) : $new_url);
        $new_path = $this->getOriginalPath($new_url);
        if (false) {
        } elseif ($url <> $new_url) {
            if (false) {
            } elseif (ToolsDemo::isMultisites() && stripos(trailingslashit($url_no_query), '/' . ToolsDemo::getOption('hmwp_activate_url') . '/') !== false) {
                $new_path = realpath($new_path);
                if (strpos($new_path, 'wp-activate.php') && $wp_filesystem->exists($new_path)) {
                    require_once $new_path;
                }
            }
        }
    }

    public function maybeShowNotFound() {
        if (is_404()) {
            $this->showFile($this->getCurrentURL());
        }
    }
}

class RewriteDemo {
    public function hookChangePaths() {
        if (!ToolsDemo::getValue('hmwp_preview')) {
            add_action('template_redirect', array(ObjController::getClass('FilesDemo'), 'maybeShowNotFound'), 1);
        }
    }
}

$_SERVER['HTTP_HOST'] = 'example.test';
$_SERVER['REQUEST_URI'] = '/hidden/../../wp-activate.php';
add_action('init', array(new RewriteDemo(), 'hookChangePaths'));
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "path-transversal" {
			continue
		}
		if finding.Start.Line != 104 {
			continue
		}
		found = true
	}
	if !found {
		t.Fatalf("did not find hide-my-wp style nested include sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsHideMyWPActualShowFileInclude(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/hide-my-wp__5.4.01"
	result, err := AnalyzeRootWithOptions(root, []string{
		"vendor",
		"vendor-prefixed",
		"vendor_prefixed",
		"node_modules",
		"bower_components",
		"tests",
		"test",
		"spec",
	}, 0, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "path-transversal" {
			continue
		}
		if !strings.HasSuffix(finding.Path, "models/Files.php") {
			continue
		}
		if finding.Start.Line != 515 {
			continue
		}
		if !strings.Contains(finding.Extra.Trace.Callable, "\\HMWP_Models_Files::") {
			continue
		}
		if finding.Extra.Trace.Source.Path == "" || finding.Extra.Trace.Source.Line == 0 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find actual hide-my-wp include sink; findings=%#v", result.Payload.Results)
	}
}

func TestBuildEngineMarksCodeSnippetsShortcodeRegistrationViaClassConst(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/code-snippets__3.9.1"
	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	if len(manifest.Files) != 1 || len(manifest.Errors) != 0 {
		t.Fatalf("unexpected manifest state: files=%d errors=%#v", len(manifest.Files), manifest.Errors)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("unexpected loaded files count: %d", len(files))
	}
	if len(files[0].AST) == 0 {
		t.Fatalf("unexpected loaded file ast length: %d", len(files[0].AST))
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupMethodKey(`\Code_Snippets\Front_End`, "render_content_shortcode")
	if key == "" {
		t.Fatalf("missing render_content_shortcode method key")
	}
	if _, ok := engine.directPublicCallables[key]; !ok {
		t.Fatalf("shortcode callback %s not marked direct public", key)
	}
}

func TestAnalyzeRootFindsCodeSnippetsRealShortcodeFlatFileInclude(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/code-snippets__3.9.1"
	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "path-transversal" {
			continue
		}
		if strings.HasSuffix(finding.Path, "php/front-end/class-front-end.php") && finding.Start.Line == 296 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not find real code-snippets flat-file include sink; findings=%#v", result.Payload.Results)
	}
}

func TestBuildEngineKeepsNinjaFormsCalculationsMetaboxRelevant(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/ninja-forms__3.8.19"
	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"
	engine.currentBatchName = "output"
	engine.currentBatchName = "output"

	key := engine.lookupMethodKey(`\NF_Admin_Metaboxes_Calculations`, "render_metabox")
	if key == "" {
		t.Fatalf("missing calculations render_metabox method key")
	}
	if _, ok := engine.directPublicCallables[key]; !ok {
		t.Fatalf("calculations metabox callback %s not marked direct public", key)
	}
	templateKey := engine.lookupMethodKey(`\Ninja_Forms`, "template")
	if templateKey == "" {
		t.Fatalf("missing Ninja_Forms::template method key")
	}
	if _, ok := engine.relevantCallables[key]; !ok {
		_, renderRequestReachable := engine.requestReachableCallables[key]
		_, templateRequestReachable := engine.requestReachableCallables[templateKey]
		_, templateRelevant := engine.relevantCallables[templateKey]
		hasTemplateEdge := false
		for _, site := range engine.callSiteEdges[key] {
			if site.callee == templateKey {
				hasTemplateEdge = true
				break
			}
		}
		_, hasReverseTemplateEdge := engine.reverseCallEdges[templateKey][key]
		t.Fatalf("calculations metabox callback %s not kept relevant; render_request_reachable=%t template=%s request_reachable=%t relevant=%t edge=%t reverse_edge=%t", key, renderRequestReachable, templateKey, templateRequestReachable, templateRelevant, hasTemplateEdge, hasReverseTemplateEdge)
	}
}

func TestAnalyzeCallableInfersReturnClassFromAssignedNewObject(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "assigned-new-return-class.php"), `<?php
class Submission {}
class Factory {
    protected $_objects = array();
    public function get_sub($id) {
        return $this->_objects[$id] = new Submission();
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"
	engine.currentBatchName = "output"

	key := engine.lookupMethodKey(`\Factory`, "get_sub")
	if key == "" {
		t.Fatalf("missing Factory::get_sub")
	}
	summary := engine.analyzeCallable(engine.callables[key])
	if len(summary.ReturnClasses) != 1 || summary.ReturnClasses[0] != `\Submission` {
		t.Fatalf("ReturnClasses = %#v, want [\\\\Submission]", summary.ReturnClasses)
	}
	if got := engine.callableReturnClassHint(key); got != `\Submission` {
		t.Fatalf("callableReturnClassHint(Factory::get_sub) = %q, want \\Submission", got)
	}
}

func TestBuildEngineInfersReturnClassFromLocalCachedArrayFetch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "local-cached-array-return-class.php"), `<?php
class Submission {}
class Factory {
    public function get_sub($id) {
        $objects[$id] = new Submission();
        return $objects[$id];
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupMethodKey(`\Factory`, "get_sub")
	if key == "" {
		t.Fatalf("missing Factory::get_sub")
	}
	if got := engine.callableReturnClassHint(key); got != `\Submission` {
		t.Fatalf("callableReturnClassHint(Factory::get_sub) = %q, want \\Submission", got)
	}
}

func TestAnalyzeRootResolvesGetterReturnedReceiverPropertyClassAcrossChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "getter-returned-receiver-property-chain.php"), `<?php
class Submission {
    public function save() {
        eval($_POST['payload']);
    }
}

class Factory {
    protected $_object;

    public function sub() {
        $this->_object = new Submission();
        return $this;
    }

    public function get() {
        $object = $this->_object;
        $this->_object = null;
        return $object;
    }
}

class Demo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_chain_save', array($this, 'run'));
    }

    public function run() {
        $sub = (new Factory())->sub()->get();
        $sub->save();
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	subKey := engine.lookupMethodKey(`\Factory`, "sub")
	if subKey == "" {
		t.Fatalf("missing Factory::sub")
	}
	if got := engine.callableReceiverPropertyClassHint(subKey, "this._object"); got != `\Submission` {
		t.Fatalf("callableReceiverPropertyClassHint(Factory::sub, this._object) = %q, want \\Submission", got)
	}

	getKey := engine.lookupMethodKey(`\Factory`, "get")
	if getKey == "" {
		t.Fatalf("missing Factory::get")
	}
	if got := engine.directReturnPropertyHints[getKey]; got != "this._object" {
		t.Fatalf("directReturnPropertyHints[Factory::get] = %q, want this._object", got)
	}
	runKey := engine.lookupMethodKey(`\Demo`, "run")
	if runKey == "" {
		t.Fatalf("missing Demo::run")
	}
	saveKey := engine.lookupMethodKey(`\Submission`, "save")
	if saveKey == "" {
		t.Fatalf("missing Submission::save")
	}
	if _, ok := engine.directPublicCallables[runKey]; !ok {
		t.Fatalf("Demo::run should be marked direct public: %#v", engine.directPublicCallables)
	}
	if _, ok := engine.relevantCallables[saveKey]; !ok {
		t.Fatalf("Submission::save should stay relevant: %#v", engine.relevantCallables)
	}
	hasSaveEdge := false
	for _, site := range engine.callSiteEdges[runKey] {
		if site.callee == saveKey {
			hasSaveEdge = true
			break
		}
	}
	if !hasSaveEdge {
		t.Fatalf("Demo::run call edges = %#v, want edge to %s", engine.callSiteEdges[runKey], saveKey)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID == "unsafe-use" && finding.Start.Line == 4 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("getter-returned receiver property chain finding missing: %#v", result.Payload.Results)
	}
}

func TestBuildEngineSpecializesNinjaFormsTemplateForCalculationsMetabox(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/ninja-forms__3.8.19"
	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	templateKey := engine.lookupMethodKey(`\Ninja_Forms`, "template")
	if templateKey == "" {
		t.Fatalf("missing Ninja_Forms::template method key")
	}
	engine.currentBatchName = "output"
	specializedKey := engine.maybeSpecializeCallableForLiteralArgs(templateKey, map[int]string{0: "admin-metaboxes-calcs.html.php"})
	if specializedKey == "" || specializedKey == templateKey {
		t.Fatalf("expected specialized Ninja_Forms::template callable, got %q", specializedKey)
	}
	current := engine.callables[specializedKey]
	var includeExpr ast.Node
	walkNodes(current.Stmts, func(node ast.Node) {
		if includeExpr != nil {
			return
		}
		includeNode, ok := node.(*ast.ExprInclude)
		if !ok {
			return
		}
		includeExpr = includeNode.Expr
	})
	if includeExpr == nil {
		t.Fatalf("missing include expression in %s", specializedKey)
	}
	keys := engine.staticIncludedFileCallableKeys(includeExpr, current)
	found := false
	for _, key := range keys {
		if strings.HasSuffix(key, "includes/Templates/admin-metaboxes-calcs.html.php") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("specialized template include keys = %#v, want admin-metaboxes-calcs template", keys)
	}
	getKey := engine.lookupMethodKey(`\NF_Abstracts_ModelFactory`, "get")
	if getKey == "" {
		t.Fatalf("missing NF_Abstracts_ModelFactory::get")
	}
	if got := engine.directReturnPropertyHints[getKey]; got != "this._object" {
		t.Fatalf("directReturnPropertyHints[ModelFactory::get] = %q, want this._object", got)
	}
	subKey := engine.lookupMethodKey(`\NF_Abstracts_ModelFactory`, "sub")
	if subKey == "" {
		t.Fatalf("missing NF_Abstracts_ModelFactory::sub")
	}
	if got := engine.callableReceiverPropertyClassHint(subKey, "this._object"); got != `\NF_Database_Models_Submission` {
		t.Fatalf("callableReceiverPropertyClassHint(ModelFactory::sub, this._object) = %q, want \\NF_Database_Models_Submission", got)
	}
	if got := engine.receiverPropertyReturnClassHint(`\NF_Admin_Metaboxes_Calculations`, "this.sub"); got != `\NF_Database_Models_Submission` {
		t.Fatalf("receiverPropertyReturnClassHint(\\\\NF_Admin_Metaboxes_Calculations, this.sub) = %q, want \\\\NF_Database_Models_Submission; hints=%#v", got, engine.receiverPropertyClassHints)
	}
	getExtraValuesKey := engine.lookupMethodKey(`\NF_Database_Models_Submission`, "get_extra_values")
	if getExtraValuesKey == "" {
		t.Fatalf("missing NF_Database_Models_Submission::get_extra_values")
	}
	renderKey := engine.lookupMethodKey(`\NF_Admin_Metaboxes_Calculations`, "render_metabox")
	if renderKey == "" {
		t.Fatalf("missing NF_Admin_Metaboxes_Calculations::render_metabox")
	}
	getExtraValueKey := engine.lookupMethodKey(`\NF_Database_Models_Submission`, "get_extra_value")
	if getExtraValueKey == "" {
		t.Fatalf("missing NF_Database_Models_Submission::get_extra_value")
	}
	if _, ok := engine.relevantCallables[getExtraValueKey]; !ok {
		t.Fatalf("get_extra_value should stay relevant: relevant=%#v render_sites=%#v extra_values_sites=%#v read_buckets=%#v read_families=%#v", engine.relevantCallables, engine.callSiteEdges[renderKey], engine.callSiteEdges[getExtraValuesKey], engine.storageReadBucketsByCallable[getExtraValueKey], engine.storageReadFamiliesByCallable[getExtraValueKey])
	}
	if _, ok := engine.relevantCallables[getExtraValuesKey]; !ok {
		t.Fatalf("get_extra_values should stay relevant: relevant=%#v render_sites=%#v read_buckets=%#v read_families=%#v", engine.relevantCallables, engine.callSiteEdges[renderKey], engine.storageReadBucketsByCallable[getExtraValuesKey], engine.storageReadFamiliesByCallable[getExtraValuesKey])
	}
	saveKey := engine.lookupMethodKey(`\NF_Database_Models_Submission`, "save")
	if saveKey == "" {
		t.Fatalf("missing NF_Database_Models_Submission::save")
	}
	if _, ok := engine.relevantCallables[saveKey]; !ok {
		t.Fatalf("save should stay relevant: %#v", engine.relevantCallables)
	}
	summary := engine.analyzeCallable(current)
	if len(summary.SourceFindings) == 0 && len(summary.ParamFindings) == 0 && len(summary.ReceiverFindings) == 0 {
		t.Fatalf("specialized template summary missing findings for %s", specializedKey)
	}
	engine.currentBatchName = batchNameForAllowedOps(engine.allowedSinkOps)
	payload := engine.run()
	foundTemplateFinding := false
	for _, finding := range payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("includes", "Templates", "admin-metaboxes-calcs.html.php")) {
			continue
		}
		if finding.Extra.Trace.Callable != `\NF_Admin_Metaboxes_Calculations::render_metabox` {
			continue
		}
		foundTemplateFinding = true
		break
	}
	if !foundTemplateFinding {
		getExtraValueSummary := engine.analyzeCallable(engine.callables[getExtraValueKey])
		getExtraValuesSummary := engine.analyzeCallable(engine.callables[getExtraValuesKey])
		renderSummary := engine.summaries[renderKey]
		t.Fatalf("render_metabox settled findings missing admin-metaboxes-calcs sink: payload=%#v render=%+v get_extra_value=%+v get_extra_values=%+v template=%+v", payload.Results, renderSummary, getExtraValueSummary, getExtraValuesSummary, summary)
	}
}

func TestBuildEngineSkipsABSPATHGuardedFileEntrypointForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "guarded-template.php"), `<?php
defined('ABSPATH') || exit;

$tab = $_GET['tab'] ?? '';
helper($tab);

function helper($value) {
    return unserialize($value);
}
`)
	writePHP(t, filepath.Join(root, "unguarded-endpoint.php"), `<?php
$tab = $_GET['tab'] ?? '';
helper2($tab);

function helper2($value) {
    return unserialize($value);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("unexpected loaded files count: %d", len(files))
	}
	for _, file := range files {
		if len(file.AST) == 0 {
			t.Fatalf("unexpected empty ast for %s", file.Relative)
		}
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	guardedKey := "file::guarded-template.php"
	if _, ok := engine.directPublicCallables[guardedKey]; ok {
		t.Fatalf("ABSPATH-guarded file should not be marked direct public: %#v", engine.directPublicCallables)
	}
	if _, ok := engine.relevantCallables[guardedKey]; ok {
		t.Fatalf("ABSPATH-guarded file should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}

	unguardedKey := "file::unguarded-endpoint.php"
	if _, ok := engine.directPublicCallables[unguardedKey]; !ok {
		t.Fatalf("unguarded request file should stay direct public: %#v", engine.directPublicCallables)
	}
	if _, ok := engine.relevantCallables[unguardedKey]; !ok {
		t.Fatalf("unguarded request file should stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsOrphanFileDirectSinkForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "guarded-template.php"), `<?php
defined('ABSPATH') || exit;

$callback = 'trim';
call_user_func($callback, 'safe');
`)
	writePHP(t, filepath.Join(root, "unguarded-endpoint.php"), `<?php
$callback = $_GET['callback'] ?? 'trim';
call_user_func($callback, 'safe');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	guardedKey := "file::guarded-template.php"
	if _, ok := engine.relevantCallables[guardedKey]; ok {
		t.Fatalf("guarded orphan file sink should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}

	unguardedKey := "file::unguarded-endpoint.php"
	if _, ok := engine.relevantCallables[unguardedKey]; !ok {
		t.Fatalf("unguarded direct sink file should stay relevant: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsRegistrationOnlyFileWrapperForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "bootstrap.php"), `<?php
defined('ABSPATH') || exit;

add_action('init', 'demo_bootstrap');

function demo_bootstrap() {
    return;
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	fileKey := "file::bootstrap.php"
	if _, ok := engine.relevantCallables[fileKey]; ok {
		t.Fatalf("registration-only file wrapper should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineKeepsRequestReachableDirectSinkHelperForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "entry.php"), `<?php
function entry() {
    $value = $_GET['payload'] ?? '';
    helper($value);
}

function helper($value) {
    return unserialize($value);
}

entry();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := "function::\\helper"
	if _, ok := engine.relevantCallables[helperKey]; !ok {
		t.Fatalf("request-reachable direct sink helper should stay relevant: %#v", engine.relevantCallables)
	}
}

func TestAnalyzeCallableStoresWarmDependencySummaryInPassCache(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "demo.php"), `<?php
function first($value) {
    return shared_helper($value);
}

function second($value) {
    return shared_helper($value);
}

function shared_helper($value) {
    return leaf_helper($value);
}

function leaf_helper($value) {
    return unserialize($value);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	engine.resetPassWarmSummaryCache()
	defer engine.clearPassWarmSummaryCache()

	firstKey := `function::\first`
	secondKey := `function::\second`
	sharedKey := `function::\shared_helper`
	leafKey := `function::\leaf_helper`

	engine.analyzeCallable(engine.callables[firstKey])
	if _, ok := engine.getPassWarmSummary(sharedKey); !ok {
		t.Fatalf("shared helper summary should be cached for current pass")
	}
	if _, ok := engine.getPassWarmSummary(leafKey); !ok {
		t.Fatalf("leaf helper summary should be cached for current pass")
	}
	engine.analyzeCallable(engine.callables[secondKey])
	if _, ok := engine.getPassWarmSummary(sharedKey); !ok {
		t.Fatalf("shared helper summary should remain cached across top-level callable analyses in the same pass")
	}
}

func TestAnalyzeRootFindsFactoryResolvedHookCallbackRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
function add_action($hook, $callback) {}

class ObjController {
    public static function getClass($class) {
        return null;
    }
}

class FilesystemDemo {
    public function get_contents($path) {
        return $path;
    }
}

class FilesDemo {
    public function getCurrentURL() {
        return rawurldecode($_SERVER['REQUEST_URI']);
    }

    public function getOriginalPath($url) {
        return '/tmp/' . ltrim($url, '/');
    }

    public function showFile($url) {
        $wp_filesystem = new FilesystemDemo();
        $new_path = $this->getOriginalPath($url);
        $wp_filesystem->get_contents($new_path);
    }

    public function maybeShowFile() {
        $this->showFile($this->getCurrentURL());
    }
}

add_action('init', array(ObjController::getClass('FilesDemo'), 'maybeShowFile'));
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "request-path-read-delete" {
			continue
		}
		if finding.Start.Line != 28 {
			continue
		}
		found = true
		if finding.Extra.Trace.Source.Line != 18 {
			t.Fatalf("source line = %d, want 18", finding.Extra.Trace.Source.Line)
		}
	}
	if !found {
		t.Fatalf("did not find factory-resolved hook callback read sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsFactoryResolvedHookCallbackInclude(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "files.php"), `<?php
function add_action($hook, $callback) {}

class ObjController {
    public static function getClass($class) {
        return null;
    }
}

class FilesDemo {
    public function getCurrentURL() {
        return rawurldecode($_SERVER['REQUEST_URI']);
    }

    public function getOriginalPath($url) {
        return '/tmp/' . ltrim($url, '/');
    }

    public function showFile($url) {
        $new_path = $this->getOriginalPath($url);
        $new_path = realpath($new_path);
        require_once $new_path;
    }

    public function maybeShowFile() {
        $this->showFile($this->getCurrentURL());
    }
}

add_action('init', array(ObjController::getClass('FilesDemo'), 'maybeShowFile'));
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "path-transversal" {
			continue
		}
		if finding.Start.Line != 22 {
			continue
		}
		found = true
		if finding.Extra.Trace.Source.Line != 12 {
			t.Fatalf("source line = %d, want 12", finding.Extra.Trace.Source.Line)
		}
	}
	if !found {
		t.Fatalf("did not find factory-resolved hook callback include sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootWithOptionsFiltersSinkOps(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ops.php"), `<?php
class OpsDemo {
    public function run() {
        $path = $_GET['template'];
        require_once $path;
        unlink($path);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		manifest, manifestErr := parsetree.BuildManifestForRoot(root, nil, 1)
		if manifestErr != nil {
			t.Fatalf("findings = %d, want 1 (manifest err=%v)", len(result.Payload.Results), manifestErr)
		}
		files, loadErr := loadFiles(manifest, 1)
		if loadErr != nil {
			t.Fatalf("findings = %d, want 1 (load err=%v)", len(result.Payload.Results), loadErr)
		}
		engine, buildErr := buildEngine(root, files, Options{
			AllowedSinkOps: map[string]struct{}{"call": {}},
		})
		if buildErr != nil {
			t.Fatalf("findings = %d, want 1 (build err=%v)", len(result.Payload.Results), buildErr)
		}
		handleKey := engine.lookupFunctionKey("", "handle")
		ctorKey := engine.lookupMethodKey(`\Importer`, "__construct")
		enableKey := engine.lookupMethodKey(`\Importer`, "enablePlugins")
		t.Fatalf(
			"findings = %d, want 1 handle=%+v handle_now=%+v ctor_now=%+v enable_now=%+v relevant=%t ctor_relevant=%t enable_relevant=%t",
			len(result.Payload.Results),
			engine.callables[handleKey],
			engine.analyzeCallable(engine.callables[handleKey]),
			engine.analyzeCallable(engine.callables[ctorKey]),
			engine.analyzeCallable(engine.callables[enableKey]),
			func() bool { _, ok := engine.relevantCallables[handleKey]; return ok }(),
			func() bool { _, ok := engine.relevantCallables[ctorKey]; return ok }(),
			func() bool { _, ok := engine.relevantCallables[enableKey]; return ok }(),
		)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 6 {
		t.Fatalf("sink line = %d, want 6", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 4 {
		t.Fatalf("source line = %d, want 4", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootDefaultScanBatchesSinkFamilies(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "batched.php"), `<?php
class BatchedDemo {
    public function run() {
        $path = $_GET['path'];
        unlink($path);
        update_option('demo_value', $_POST['value']);
    }
}
`)

	allResult, err := AnalyzeRootWithOptions(root, nil, 1, Options{})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(all): %v", err)
	}
	deleteResult, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(delete): %v", err)
	}
	actionResult, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(action): %v", err)
	}

	if len(deleteResult.Payload.Results) != 1 {
		t.Fatalf("delete findings = %d, want 1", len(deleteResult.Payload.Results))
	}
	if len(actionResult.Payload.Results) != 1 {
		t.Fatalf("action findings = %d, want 1", len(actionResult.Payload.Results))
	}
	if len(allResult.Payload.Results) != 2 {
		t.Fatalf("all findings = %d, want 2", len(allResult.Payload.Results))
	}

	keys := map[string]struct{}{}
	for _, finding := range allResult.Payload.Results {
		keys[findingKey(finding)] = struct{}{}
	}
	for _, finding := range deleteResult.Payload.Results {
		if _, ok := keys[findingKey(finding)]; !ok {
			t.Fatalf("default batched results missing delete finding %#v", finding)
		}
	}
	for _, finding := range actionResult.Payload.Results {
		if _, ok := keys[findingKey(finding)]; !ok {
			t.Fatalf("default batched results missing action finding %#v", finding)
		}
	}
}

func TestAnalyzeRootTracksUpdateOptionToGetOption(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "option.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']), 'text' => 'safe');
    update_option('demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $value = maybe_unserialize(get_option('demo_upload'));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		manifest, manifestErr := parsetree.BuildManifestForRoot(root, nil, 1)
		if manifestErr != nil {
			t.Fatalf("findings = %d, want 1 (manifest err: %v)", len(result.Payload.Results), manifestErr)
		}
		files, loadErr := loadFiles(manifest, 1)
		if loadErr != nil {
			t.Fatalf("findings = %d, want 1 (load err: %v)", len(result.Payload.Results), loadErr)
		}
		engine, buildErr := buildEngine(root, files, Options{
			AllowedSinkOps: map[string]struct{}{"action": {}},
		})
		if buildErr != nil {
			t.Fatalf("findings = %d, want 1 (build err: %v)", len(result.Payload.Results), buildErr)
		}
		controllerKey := engine.lookupMethodKey(`\Demo\App\Http\Controllers\ManagersController`, "addmanager")
		serviceKey := engine.lookupMethodKey(`\Demo\App\Services\Manager\ManagerService`, "addmanager")
		var controllerParams map[string]string
		var controllerEdges map[string]struct{}
		var serviceEntry []EntryPoint
		resolvedClass := ""
		resolvedCandidates := []string(nil)
		specializedKey := ""
		if controller, ok := engine.callables[controllerKey]; ok {
			controllerParams = controller.ParamTypes
			controllerEdges = engine.callEdges[controllerKey]
			walkNodes(controller.Stmts, func(node ast.Node) {
				if resolvedClass != "" {
					return
				}
				call, ok := node.(*ast.ExprMethodCall)
				if !ok || strings.ToLower(identifierText(call.Name)) != "addmanager" {
					return
				}
				resolvedClass = resolveCallGraphClassExpr(engine, controller, call.Var, nil)
				resolvedCandidates = resolveCallGraphClassExprCandidates(engine, controller, call.Var, nil)
				specializedKey = engine.maybeSpecializeRuntimeMethodKeyForLiteralArgs(resolvedClass, strings.ToLower(identifierText(call.Name)), literalArgHintsForArgs(call.Args, controller, engine))
			})
		}
		if serviceKey != "" {
			serviceEntry = engine.contexts[serviceKey].EntryPoints
		}
		t.Fatalf("findings = %d, want 1; controllerKey=%q serviceKey=%q controllerParams=%#v controllerEdges=%#v resolvedClass=%q resolvedCandidates=%#v specializedKey=%q serviceEntry=%#v results=%#v", len(result.Payload.Results), controllerKey, serviceKey, controllerParams, controllerEdges, resolvedClass, resolvedCandidates, specializedKey, serviceEntry, result.Payload.Results)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksDynamicGetOptionFromExactOptionWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "dynamic-option.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    update_option('demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $key = 'demo_upload';
    $value = maybe_unserialize(get_option($key));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 10 {
		t.Fatalf("sink line = %d, want 10", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestBuildEngineIndexesExactStoragePathReaders(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "storage-readers.php"), `<?php
function read_demo_file() {
    $value = get_option('demo_upload');
    return $value['file']['tmp_name'];
}

function read_demo_text() {
    return get_option('demo_text');
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	filePathKey := `option_value[demo_upload]`
	textPathKey := `option_value[demo_text]`
	if readers := engine.storagePathReadersByExact[filePathKey]; len(readers) != 1 {
		t.Fatalf("exact readers for %s = %d, want 1", filePathKey, len(readers))
	}
	if readers := engine.storagePathReadersByExact[textPathKey]; len(readers) != 1 {
		t.Fatalf("exact readers for %s = %d, want 1", textPathKey, len(readers))
	}
	bucket := staticPathInvalidationBucket(filePathKey)
	if readers := engine.storagePathReadersByBucket[bucket]; len(readers) != 0 {
		t.Fatalf("bucket readers for %s = %d, want 0 exact-reader spillover", bucket, len(readers))
	}
}

func TestBuildEngineIndexesWildcardStoragePathReadersForDynamicMetaIDs(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "meta-readers.php"), `<?php
function read_demo_file($post_id) {
    return get_post_meta($post_id, 'demo_upload', true);
}

function read_demo_text($post_id) {
    return get_post_meta($post_id, 'demo_text', true);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	filePathKey := `post_meta_value[*][demo_upload]`
	textPathKey := `post_meta_value[*][demo_text]`
	if readers := engine.storagePathReadersByExact[filePathKey]; len(readers) != 1 {
		t.Fatalf("exact readers for %s = %d, want 1", filePathKey, len(readers))
	}
	if readers := engine.storagePathReadersByExact[textPathKey]; len(readers) != 1 {
		t.Fatalf("exact readers for %s = %d, want 1", textPathKey, len(readers))
	}
	fileBucket := storageStablePathBucket(filePathKey)
	if readers := engine.storagePathReadersByBucket[fileBucket]; len(readers) != 1 {
		t.Fatalf("bucket readers for %s = %d, want 1", fileBucket, len(readers))
	}
	textBucket := storageStablePathBucket(textPathKey)
	if readers := engine.storagePathReadersByBucket[textBucket]; len(readers) != 1 {
		t.Fatalf("bucket readers for %s = %d, want 1", textBucket, len(readers))
	}
}

func TestAnalyzeRootTracksUpdateSiteOptionToGetSiteOption(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "site-option.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    update_site_option('demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $value = maybe_unserialize(get_site_option('demo_upload'));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksSetTransientToGetTransient(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "transient.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    set_transient('demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $value = maybe_unserialize(get_transient('demo_upload'));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksSetSiteTransientToGetSiteTransient(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "site-transient.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    set_site_transient('demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $value = maybe_unserialize(get_site_transient('demo_upload'));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksUpdateMetadataToGetMetadata(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "metadata.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    update_metadata('post', 77, 'demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $value = maybe_unserialize(get_metadata('post', 77, 'demo_upload', true));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksUpdatePostMetaToGetPostMeta(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "post-meta.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    update_post_meta(77, 'demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $value = maybe_unserialize(get_post_meta(77, 'demo_upload', true));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksUpdateUserMetaToGetUserMeta(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "user-meta.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    update_user_meta(7, 'demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $value = maybe_unserialize(get_user_meta(7, 'demo_upload', true));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksUpdateTermMetaToGetTermMeta(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "term-meta.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    update_term_meta(11, 'demo_upload', maybe_serialize($payload));
}

function delete_demo() {
    $value = maybe_unserialize(get_term_meta(11, 'demo_upload', true));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksJSONWrappedOptionStorage(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "json-option.php"), `<?php
function save_demo() {
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    update_option('demo_upload', json_encode($payload));
}

function delete_demo() {
    $value = json_decode(get_option('demo_upload'), true);
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksUpdatePostToGetPostContent(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "post-content.php"), `<?php
function save_demo() {
    $payload = array('file' => array('file_path' => $_POST['path']));
    wp_update_post(array(
        'ID' => 77,
        'post_content' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $post = get_post(77);
    $value = maybe_unserialize($post->post_content);
    unlink($value['file']['file_path']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 13 {
		t.Fatalf("sink line = %d, want 13", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksInsertPostToGetPostExcerpt(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "post-excerpt.php"), `<?php
function save_demo() {
    $payload = array('file' => array('file_path' => $_POST['path']));
    wp_insert_post(array(
        'ID' => 77,
        'post_excerpt' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $post = get_post(77);
    $value = maybe_unserialize($post->post_excerpt);
    unlink($value['file']['file_path']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 13 {
		t.Fatalf("sink line = %d, want 13", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksDBUpdateStorageWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-update.php"), `<?php
class DB {
    public function update($table, $row) {}
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->update('entry_meta', array(
        'meta_value' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $result = (object) array('meta_value' => 'placeholder');
    $value = maybe_unserialize($result->meta_value);
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 17 {
		t.Fatalf("sink line = %d, want 17", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 8 {
		t.Fatalf("source line = %d, want 8", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksDBReplaceStorageWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-replace.php"), `<?php
class DB {
    public function replace($table, $row) {}
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->replace('entry_meta', array(
        'meta_value' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $result = (object) array('meta_value' => 'placeholder');
    $value = maybe_unserialize($result->meta_value);
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 17 {
		t.Fatalf("sink line = %d, want 17", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 8 {
		t.Fatalf("source line = %d, want 8", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksDBGetVarSelectRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-get-var.php"), `<?php
class DB {
    public function insert($table, $row) {}
    public function get_var($query) {}
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->insert('entry_meta', array(
        'meta_value' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $db = new DB();
    $value = maybe_unserialize($db->get_var("SELECT meta_value FROM entry_meta"));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 18 {
		t.Fatalf("sink line = %d, want 18", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 9 {
		t.Fatalf("source line = %d, want 9", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksDBGetRowSelectReadWithAlias(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-get-row.php"), `<?php
class DB {
    public function insert($table, $row) {}
    public function get_row($query) {}
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->insert('entry_meta', array(
        'meta_value' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $db = new DB();
    $row = $db->get_row("SELECT meta_value AS value FROM entry_meta");
    $value = maybe_unserialize($row->value);
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 19 {
		t.Fatalf("sink line = %d, want 19", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 9 {
		t.Fatalf("source line = %d, want 9", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksDBGetResultsSelectRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-get-results.php"), `<?php
class DB {
    public function insert($table, $row) {}
    public function get_results($query) {}
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->insert('entry_meta', array(
        'meta_value' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $db = new DB();
    $rows = $db->get_results("SELECT meta_value FROM entry_meta");
    foreach ($rows as $row) {
        $value = maybe_unserialize($row->meta_value);
        unlink($value['file']['tmp_name']);
    }
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 20 {
		t.Fatalf("sink line = %d, want 20", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 9 {
		t.Fatalf("source line = %d, want 9", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksPreparedDBSelectDeleteBySelector(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-prepared-selector-delete.php"), `<?php
class DB {
    public function prepare($query, ...$args) { return $query; }
    public function get_results($query) {}
}

class Repo {
    private $db;

    public function __construct() {
        $this->db = new DB();
    }

    public function delete_by_entry($entry_id) {
        $sql = "SELECT meta_value FROM entry_meta WHERE entry_id = %d";
        $rows = $this->db->get_results($this->db->prepare($sql, $entry_id));
        foreach ($rows as $row) {
            $value = maybe_unserialize($row->meta_value);
            unlink($value['file']['tmp_name']);
        }
    }
}

function run_demo() {
    $entry_id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);
    if ($entry_id) {
        (new Repo())->delete_by_entry($entry_id);
    }
}

run_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 19 {
		t.Fatalf("sink line = %d, want 19", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 25 {
		t.Fatalf("source line = %d, want 25", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksWrapperReturningDBRow(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-wrapper-row.php"), `<?php
class DB {
    public function insert($table, $row) {}
    public function get_row($query) {}
}

class Repo {
    private $db;

    public function __construct() {
        $this->db = new DB();
    }

    public function load_value() {
        return $this->db->get_row("SELECT meta_value AS value FROM entry_meta");
    }
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->insert('entry_meta', array(
        'meta_value' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $repo = new Repo();
    $row = $repo->load_value();
    $value = maybe_unserialize($row->value);
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Trace.Source.Line != 21 {
		t.Fatalf("source line = %d, want 21", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksWrapperReturningDBResults(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-wrapper-results.php"), `<?php
class DB {
    public function insert($table, $row) {}
    public function get_results($query) {}
}

class Repo {
    private $db;

    public function __construct() {
        $this->db = new DB();
    }

    public function load_values() {
        return $this->db->get_results("SELECT meta_value FROM entry_meta");
    }
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->insert('entry_meta', array(
        'meta_value' => maybe_serialize($payload),
    ));
}

function delete_demo() {
    $repo = new Repo();
    $rows = $repo->load_values();
    foreach ($rows as $row) {
        $value = maybe_unserialize($row->meta_value);
        unlink($value['file']['tmp_name']);
    }
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Trace.Source.Line != 21 {
		t.Fatalf("source line = %d, want 21", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksDBQueryInsertWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-query-insert.php"), `<?php
class DB {
    public function query($query) {}
    public function get_var($query) {}
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->query("INSERT INTO entry_meta (meta_value) VALUES ('" . maybe_serialize($payload) . "')");
}

function delete_demo() {
    $db = new DB();
    $value = maybe_unserialize($db->get_var("SELECT meta_value FROM entry_meta"));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
}

func TestAnalyzeRootTracksDBQueryUpdateWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-query-update.php"), `<?php
class DB {
    public function query($query) {}
    public function get_var($query) {}
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->query("UPDATE entry_meta SET meta_value = '" . maybe_serialize($payload) . "' WHERE entry_id = 1");
}

function delete_demo() {
    $db = new DB();
    $value = maybe_unserialize($db->get_var("SELECT meta_value FROM entry_meta"));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
}

func TestAnalyzeRootTracksDBQueryReplaceWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-query-replace.php"), `<?php
class DB {
    public function query($query) {}
    public function get_var($query) {}
}

function save_demo() {
    $db = new DB();
    $payload = array('file' => array('tmp_name' => $_POST['path']));
    $db->query("REPLACE INTO entry_meta (meta_value) VALUES ('" . maybe_serialize($payload) . "')");
}

function delete_demo() {
    $db = new DB();
    $value = maybe_unserialize($db->get_var("SELECT meta_value FROM entry_meta"));
    unlink($value['file']['tmp_name']);
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
}

func TestAnalyzeRootFindsGetterReadToEchoWithoutCapCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "disclosure.php"), `<?php
class LogStore {
    public function get_log($id, $columns = array()) {
        return array('original_message' => $id);
    }
}

class Demo {
    public function run() {
        $id = sanitize_text_field($_GET['log_id']);
        $store = new LogStore();
        $log = $store->get_log($id, '');
        $msg = $log['original_message'];
        echo $msg;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-record-read-to-output-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-record-read-to-output-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 14 {
		t.Fatalf("sink line = %d, want 14", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 10 {
		t.Fatalf("source line = %d, want 10", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsAdminPageDynamicControllerDispatchThroughSingletonApplicationGetter(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "admin-page-singleton-app-dispatch.php")
	writePHP(t, path, `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}

class ControllerBase {
    final public function doAction($actionName, $args = array()) {
        if (method_exists($this, 'action' . $actionName)) {
            call_user_func_array(array($this, 'action' . $actionName), $args);
        }
    }
}

class SlidersController extends ControllerBase {
    protected function actionExportAll() {
        activate_plugin($_GET['plugin']);
    }
}

class ApplicationTypeAdmin {
    public function processRequest($defaultControllerName, $defaultActionName, $ajax = false, $args = array()) {
        $controllerName = trim($_GET['nextendcontroller']);
        if (empty($controllerName)) {
            $controllerName = $defaultControllerName;
        }
        $actionName = trim($_GET['nextendaction']);
        if (empty($actionName)) {
            $actionName = $defaultActionName;
        }
        $this->process($controllerName, $actionName, $ajax, $args);
    }

    public function process($controllerName, $actionName, $ajax = false, $args = array()) {
        $controller = $this->getController($controllerName, $ajax);
        $controller->doAction($actionName, $args);
    }

    protected function getController($controllerName, $ajax = false) {
        $methodName = 'getController' . ($ajax ? 'Ajax' : '') . $controllerName;
        if (method_exists($this, $methodName)) {
            return call_user_func(array($this, $methodName));
        }
    }

    protected function getControllerSliders() {
        return new SlidersController();
    }
}

class Application {
    private static $instance;
    protected $applicationTypeAdmin;

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function __construct() {
        $this->applicationTypeAdmin = new ApplicationTypeAdmin();
    }

    public function getApplicationTypeAdmin() {
        return $this->applicationTypeAdmin;
    }
}

class AdminHelper {
    public function __construct() {
        add_action('admin_menu', array($this, 'register_menu'));
    }

    public function register_menu() {
        add_menu_page('Smart Slider', 'Smart Slider', 'read', 'smart-slider', array($this, 'display_admin'));
    }

    public function display_admin() {
        $application = Application::getInstance();
        $applicationType = $application->getApplicationTypeAdmin();
        $applicationType->processRequest('sliders', 'index');
    }
}

new AdminHelper();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	actionKey := engine.lookupMethodKey(`\SlidersController`, "actionexportall")
	if actionKey == "" {
		t.Fatalf("missing SlidersController::actionExportAll")
	}
	foundActionEntrypoint := false
	for _, entry := range engine.contexts[actionKey].EntryPoints {
		if entry.Kind == "admin_page" && entry.Name == "smart-slider" {
			foundActionEntrypoint = true
			break
		}
	}
	if !foundActionEntrypoint {
		t.Fatalf("actionExportAll entrypoints = %#v, want inherited admin_page smart-slider", engine.contexts[actionKey].EntryPoints)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Base(path)) || finding.Start.Line != 15 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find singleton application getter admin-page action sink; findings=%#v", result.Payload.Results)
	}
}

func TestBuildEngineTracksAdminPageRegisteredThroughConcatenatedCallbackClassString(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-page-concat-callback-class.php"), `<?php
namespace Demo;

function add_action($hook, $callback) {}
function add_submenu_page($parent_slug, $page_title, $menu_title, $capability, $menu_slug, $callback = '') {}

class Menus {
    public function __construct() {
        add_action('admin_menu', array($this, 'register_menu'));
    }

    public function register_menu() {
        $method = 'refer';
        add_submenu_page('wps_overview_page', 'Referrers', 'Referrers', 'manage_options', 'wps_referrers_page', array('\\Demo\\' . $method . '_page', 'view'));
    }
}

class refer_page {
    public static function view() {
        echo $_GET['referrer'];
    }
}

new Menus();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	viewKey := engine.lookupMethodKey(`\Demo\refer_page`, "view")
	if viewKey == "" {
		t.Fatalf("missing Demo\\refer_page::view")
	}
	foundEntrypoint := false
	for _, entry := range engine.contexts[viewKey].EntryPoints {
		if entry.Kind == "admin_page" {
			foundEntrypoint = true
			break
		}
	}
	if !foundEntrypoint {
		t.Fatalf("view entrypoints = %#v, want admin_page entrypoint", engine.contexts[viewKey].EntryPoints)
	}
}

func TestBuildEngineTracksAdminPageRegisteredThroughPatternCallbackClassString(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-page-pattern-callback-class.php"), `<?php
namespace Demo;

function add_action($hook, $callback) {}
function add_submenu_page($parent_slug, $page_title, $menu_title, $capability, $menu_slug, $callback = '') {}

class Menus {
    public static function get_menu_list() {
        return array(
            array(
                'sub' => 'wps_overview_page',
                'title' => 'Referrers',
                'page_url' => 'wps_referrers_page',
                'method' => 'refer',
            ),
        );
    }

    public function __construct() {
        add_action('admin_menu', array($this, 'register_menu'));
    }

    public function register_menu() {
        foreach (self::get_menu_list() as $menu) {
            $method = 'log';
            if (array_key_exists('method', $menu)) {
                $method = $menu['method'];
            }
            add_submenu_page($menu['sub'], $menu['title'], $menu['title'], 'manage_options', $menu['page_url'], array('\\Demo\\' . $method . '_page', 'view'));
        }
    }
}

class refer_page {
    public static function view() {
        echo $_GET['referrer'];
    }
}

new Menus();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	viewKey := engine.lookupMethodKey(`\Demo\refer_page`, "view")
	if viewKey == "" {
		t.Fatalf("missing Demo\\refer_page::view")
	}
	foundEntrypoint := false
	for _, entry := range engine.contexts[viewKey].EntryPoints {
		if entry.Kind == "admin_page" {
			foundEntrypoint = true
			break
		}
	}
	if !foundEntrypoint {
		t.Fatalf("view entrypoints = %#v, want admin_page entrypoint", engine.contexts[viewKey].EntryPoints)
	}
}

func TestBuildEngineTracksRealSmartSliderAdminExportContext(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/smart-slider-3"

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	displayAdminKey := engine.lookupMethodKey(`\Nextend\SmartSlider3\Platform\WordPress\Admin\AdminHelper`, "display_admin")
	if displayAdminKey == "" {
		t.Fatalf("missing AdminHelper::display_admin")
	}
	displayControllerKey := engine.lookupMethodKey(`\Nextend\SmartSlider3\Platform\WordPress\Admin\AdminHelper`, "display_controller")
	if displayControllerKey == "" {
		t.Fatalf("missing AdminHelper::display_controller")
	}
	getTypeKey := engine.lookupMethodKey(`\Nextend\SmartSlider3\Application\ApplicationSmartSlider3`, "getapplicationtypeadmin")
	if getTypeKey == "" {
		t.Fatalf("missing ApplicationSmartSlider3::getApplicationTypeAdmin")
	}
	processRequestKey := engine.lookupMethodKey(`\Nextend\Framework\Application\AbstractApplicationType`, "processrequest")
	if processRequestKey == "" {
		t.Fatalf("missing AbstractApplicationType::processRequest")
	}
	processKey := engine.lookupMethodKey(`\Nextend\Framework\Application\AbstractApplicationType`, "process")
	if processKey == "" {
		t.Fatalf("missing AbstractApplicationType::process")
	}
	getControllerKey := engine.lookupMethodKey(`\Nextend\Framework\Application\AbstractApplicationType`, "getcontroller")
	if getControllerKey == "" {
		t.Fatalf("missing AbstractApplicationType::getController")
	}
	doActionKey := engine.lookupMethodKey(`\Nextend\Framework\Controller\AbstractController`, "doaction")
	if doActionKey == "" {
		t.Fatalf("missing AbstractController::doAction")
	}
	exportKey := engine.lookupMethodKey(`\Nextend\SmartSlider3\Application\Admin\Sliders\ControllerSliders`, "actionexportall")
	if exportKey == "" {
		t.Fatalf("missing ControllerSliders::actionExportAll")
	}

	hasDisplayEntrypoint := false
	for _, entry := range engine.contexts[displayAdminKey].EntryPoints {
		if entry.Kind == "admin_page" {
			hasDisplayEntrypoint = true
			break
		}
	}
	if !hasDisplayEntrypoint {
		t.Fatalf("display_admin entrypoints = %#v, want admin_page", engine.contexts[displayAdminKey].EntryPoints)
	}

	hasExportEntrypoint := false
	for _, entry := range engine.contexts[exportKey].EntryPoints {
		if entry.Kind == "admin_page" {
			hasExportEntrypoint = true
			break
		}
	}
	if !hasExportEntrypoint {
		t.Fatalf(
			"actionExportAll entrypoints = %#v; display_admin=%#v display_controller=%#v getApplicationTypeAdmin=%#v processRequest=%#v process=%#v getController=%#v doAction=%#v display_controller_edges=%#v getType_edges=%#v processRequest_edges=%#v process_edges=%#v getController_edges=%#v doAction_edges=%#v display_controller_aliases=%#v",
			engine.contexts[exportKey].EntryPoints,
			engine.contexts[displayAdminKey].EntryPoints,
			engine.contexts[displayControllerKey].EntryPoints,
			engine.contexts[getTypeKey].EntryPoints,
			engine.contexts[processRequestKey].EntryPoints,
			engine.contexts[processKey].EntryPoints,
			engine.contexts[getControllerKey].EntryPoints,
			engine.contexts[doActionKey].EntryPoints,
			engine.callEdges[displayControllerKey],
			engine.callEdges[getTypeKey],
			engine.callEdges[processRequestKey],
			engine.callEdges[processKey],
			engine.callEdges[getControllerKey],
			engine.callEdges[doActionKey],
			engine.callables[displayControllerKey].UseAliases,
		)
	}
	if engine.contexts[exportKey].Access == "" || engine.contexts[exportKey].Access == "unknown" {
		t.Fatalf("actionExportAll access = %q, want meaningful inherited access", engine.contexts[exportKey].Access)
	}
}

func TestBuildEngineMarksRealSmartSliderExportAllAsDirectActionSink(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/smart-slider-3"

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	exportKey := engine.lookupMethodKey(`\Nextend\SmartSlider3\Application\Admin\Sliders\ControllerSliders`, "actionexportall")
	if exportKey == "" {
		t.Fatalf("missing ControllerSliders::actionExportAll")
	}
	if !engine.callableHasDirectSink(engine.callables[exportKey]) {
		t.Fatalf("actionExportAll should stay a direct action sink")
	}
	if _, ok := engine.relevantCallables[exportKey]; !ok {
		t.Fatalf("actionExportAll should stay relevant in action-only analysis: %#v", engine.relevantCallables)
	}
}

func TestAnalyzeRootDeleteOnlySkipsDisclosureFindings(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "disclosure.php"), `<?php
class LogStore {
    public function get_log($id, $columns = array()) {
        return array('original_message' => 'secret');
    }
}

class Demo {
    public function run() {
        $id = sanitize_text_field($_GET['log_id']);
        $store = new LogStore();
        $log = $store->get_log($id, '');
        $msg = $log['original_message'];
        echo $msg;
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("delete-only scan should not emit disclosure findings: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootModelsSelectorDrivenGetterReadToEcho(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "disclosure.php"), `<?php
class LogStore {
    public function get_log($id, $columns = array()) {
        return array('original_message' => 'secret');
    }
}

class Demo {
    public function run() {
        $id = sanitize_text_field($_GET['log_id']);
        $store = new LogStore();
        $log = $store->get_log($id, '');
        $msg = $log['original_message'];
        echo $msg;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-record-read-to-output-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-record-read-to-output-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 14 {
		t.Fatalf("sink line = %d, want 14", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 10 {
		t.Fatalf("source line = %d, want 10", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsGetterReadToEchoInsideIfBranch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "disclosure.php"), `<?php
class LogStore {
    public function get_log($id, $columns = array()) {
        return array('original_message' => 'secret');
    }
}

class Demo {
    public function run() {
        if (isset($_GET['log_id']) && !empty($_GET['log_id'])) {
            $id = sanitize_text_field($_GET['log_id']);
            $store = new LogStore();
            $log = $store->get_log($id, '');
            $msg = $log['original_message'];
            echo $msg;
        }
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-record-read-to-output-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-record-read-to-output-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 15 {
		t.Fatalf("sink line = %d, want 15", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 11 {
		t.Fatalf("source line = %d, want 11", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsAdminPageZipExportDisclosureWithoutCapabilityCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-zip-export.php"), `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}

class Creator {
    public $datasec = array();

    public function addFile($data, $name) {
        $this->datasec[] = $data;
    }

    public function file() {
        return implode('', $this->datasec);
    }
}

class LogStore {
    public function get_log($id) {
        return array('path' => sanitize_text_field($_GET['path']));
    }
}

class Demo {
    public function __construct() {
        add_action('admin_menu', array($this, 'register'));
    }

    public function register() {
        add_menu_page('Demo', 'Demo', 'read', 'demo-export', array($this, 'handle'));
    }

    public function handle() {
        $store = new LogStore();
        $log = $store->get_log($_GET['id']);
        $zip = new Creator();
        $zip->addFile(file_get_contents($log['path']), basename($log['path']));
        echo $zip->file();
    }
}

new Demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-record-read-to-output-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-record-read-to-output-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 37 {
		t.Fatalf("sink line = %d, want 37", finding.Start.Line)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsAdminPageDirectFileReadDisclosureWithoutCapabilityCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-file-read.php"), `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}

class LogStore {
    public function get_log($id) {
        return array('path' => sanitize_text_field($_GET['path']));
    }
}

class Demo {
    public function __construct() {
        add_action('admin_menu', array($this, 'register'));
    }

    public function register() {
        add_menu_page('Demo', 'Demo', 'read', 'demo-export', array($this, 'handle'));
    }

    public function handle() {
        $store = new LogStore();
        $log = $store->get_log($_GET['id']);
        echo file_get_contents($log['path']);
    }
}

new Demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-record-read-to-output-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-record-read-to-output-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 23 {
		t.Fatalf("sink line = %d, want 23", finding.Start.Line)
	}
}

func TestAnalyzeRootSuppressesAdminPageZipExportDisclosureAfterCapabilityAndNonceChecks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-zip-export-safe.php"), `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}
function check_admin_referer($action) { return true; }

class Creator {
    public $datasec = array();

    public function addFile($data, $name) {
        $this->datasec[] = $data;
    }

    public function file() {
        return implode('', $this->datasec);
    }
}

class LogStore {
    public function get_log($id) {
        return array('path' => sanitize_text_field($_GET['path']));
    }
}

class Demo {
    public function __construct() {
        add_action('admin_menu', array($this, 'register'));
    }

    public function register() {
        add_menu_page('Demo', 'Demo', 'read', 'demo-export', array($this, 'handle'));
    }

    public function handle() {
        if (check_admin_referer('demo-export') && current_user_can('manage_options')) {
            $store = new LogStore();
            $log = $store->get_log($_GET['id']);
            $zip = new Creator();
            $zip->addFile(file_get_contents($log['path']), basename($log['path']));
            echo $zip->file();
        }
    }
}

new Demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %#v, want 0", result.Payload.Results)
	}
}

func TestAnalyzeRootSuppressesGetterReadToEchoWithCapCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "disclosure.php"), `<?php
class LogStore {
    public function get_log($id, $columns = array()) {
        return array('original_message' => $id);
    }
}

class Demo {
    public function run() {
        if ( current_user_can('manage_options') ) {
            $id = sanitize_text_field($_GET['log_id']);
            $store = new LogStore();
            $log = $store->get_log($id, '');
            $msg = $log['original_message'];
            echo $msg;
        }
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsAdminPageAttachmentDownloadActionWithoutCapabilityCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-download-action.php"), `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}

class LogStore {
    public function get_log($id) {
        return array('path' => sanitize_text_field($_GET['path']));
    }
}

class Demo {
    public function __construct() {
        add_action('admin_menu', array($this, 'register'));
    }

    public function register() {
        add_menu_page('Demo', 'Demo', 'read', 'demo-export', array($this, 'handle'));
    }

    public function handle() {
        $store = new LogStore();
        $log = $store->get_log($_GET['id']);
        header('Content-disposition: attachment; filename=demo.txt');
        header('Content-type: application/octet-stream');
        echo file_get_contents($log['path']);
    }
}

new Demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 25 {
		t.Fatalf("sink line = %d, want 25", finding.Start.Line)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootSuppressesAdminPageAttachmentDownloadActionAfterCapabilityAndNonceChecks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-download-action-safe.php"), `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}
function check_admin_referer($action) { return true; }
function current_user_can($cap) { return true; }

class LogStore {
    public function get_log($id) {
        return array('path' => sanitize_text_field($_GET['path']));
    }
}

class Demo {
    public function __construct() {
        add_action('admin_menu', array($this, 'register'));
    }

    public function register() {
        add_menu_page('Demo', 'Demo', 'read', 'demo-export', array($this, 'handle'));
    }

    public function handle() {
        if ( ! current_user_can('manage_options') ) {
            return;
        }
        check_admin_referer('demo-export');
        $store = new LogStore();
        $log = $store->get_log($_GET['id']);
        header('Content-disposition: attachment; filename=demo.txt');
        header('Content-type: application/octet-stream');
        echo file_get_contents($log['path']);
    }
}

new Demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestBuildEngineMarksFalseEqualsCurrentUserCanGuardAsCapabilityChecked(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "false-equals-capability-guard.php"), `<?php
function add_action($hook, $callback) {}
function current_user_can($cap) { return true; }
function update_option($key, $value, $autoload = false) {}

class Demo {
    public function __construct() {
        add_action('wp_ajax_demo_save', array($this, 'save'));
    }

    public function save() {
        if ( false === current_user_can('administrator') ) {
            return;
        }
        update_option('demo_value', $_GET['value'], false);
    }
}

new Demo();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\Demo`, "save")
	if methodKey == "" {
		t.Fatal("missing Demo::save")
	}
	if ctx := engine.contexts[methodKey]; ctx.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", ctx.Access)
	}
}

func TestAnalyzeRootSuppressesReplayedActionSinkForCapabilityCheckedCallerWithSharedPublicHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shared-action-helper.php"), `<?php
function add_action($hook, $callback) {}
function register_rest_route($namespace, $route, $args) {}
function current_user_can($cap) { return true; }
function update_option($key, $value, $autoload = false) {}

class OptionStore {
    public static function set_option($value) {
        update_option('demo_option', $value, false);
    }
}

class RestController {
    public function create_public_connection($request) {
        $value = $_POST['sure-triggers-access-key'];
        OptionStore::set_option($value);
    }
}

class RoutesController {
    public function __construct() {
        add_action('rest_api_init', array($this, 'register'));
    }

    public function register() {
        $controller = new RestController();
        register_rest_route('demo/v1', '/connection/create', array(
            'methods' => 'POST',
            'callback' => array($controller, 'create_public_connection'),
            'permission_callback' => '__return_true',
        ));
    }
}

class AuthController {
    public function __construct() {
        add_action('admin_init', array($this, 'save_connection'));
    }

    public function save_connection() {
        if ( false === current_user_can('administrator') ) {
            return;
        }
        $value = sanitize_text_field($_GET['sure-triggers-access-key']);
        OptionStore::set_option($value);
    }
}

class Loader {
    public function __construct() {
        add_action('plugins_loaded', array($this, 'initialize'));
    }

    public function initialize() {
        new RoutesController();
        new AuthController();
    }
}

new Loader();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Trace.Callable != `\RestController::create_public_connection` {
		t.Fatalf("callable = %q, want \\RestController::create_public_connection", finding.Extra.Trace.Callable)
	}
	if finding.Extra.Trace.Source.Line != 15 {
		t.Fatalf("source line = %d, want 15", finding.Extra.Trace.Source.Line)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Kind == "front_hook" || entry.Kind == "ajax" {
			t.Fatalf("unexpected helper entrypoint in replayed action context: %#v", finding.Extra.Context.EntryPoints)
		}
	}
}

func TestCurrentContextPrefersDirectEntrypointsForCurrentCallable(t *testing.T) {
	state := analysisState{
		engine: &engine{
			contexts: map[string]FlowContext{
				"method::\\AuthController::save_connection": {
					EntryPoints: []EntryPoint{
						{Kind: "front_hook", Name: "plugins_loaded", Access: "unknown"},
						{Kind: "rest", Route: "connection/create-wp-connection", Access: "unauthenticated"},
						{Kind: "ajax", Name: "wp_ajax_st_save_settings", Access: "authenticated"},
					},
					CapabilityChecks: []Location{{Path: "AuthController.php", Line: 144, Snippet: "if ( false === current_user_can( 'administrator' ) ) {"}},
					NonceChecks:      []Location{{Path: "AuthController.php", Line: 140, Snippet: "if ( false === wp_verify_nonce( $nonce, 'sure-trigger-connect' ) ) {"}},
				},
			},
			directEntryPointsByCallable: map[string][]EntryPoint{
				"method::\\AuthController::save_connection": {
					{Kind: "front_hook", Name: "admin_init", Access: "authenticated", Location: Location{Path: "AuthController.php", Line: 73}},
				},
			},
		},
		current: callable{Key: "method::\\AuthController::save_connection"},
	}

	ctx := state.currentContext()
	if len(ctx.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %#v, want only direct admin_init", ctx.EntryPoints)
	}
	if ctx.EntryPoints[0].Name != "admin_init" {
		t.Fatalf("entrypoint name = %q, want admin_init", ctx.EntryPoints[0].Name)
	}
	if !definitelyCapabilityGuardedForAction(ctx) {
		t.Fatalf("context should be definitely capability guarded for action: %#v", ctx)
	}
}

func TestAnalyzeRootSuppressesSourceFindingReplayForDirectCapabilityCheckedHandler(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "direct-handler-replay.php"), `<?php
function add_action($hook, $callback) {}
function register_rest_route($namespace, $route, $args) {}
function current_user_can($cap) { return true; }
function wp_verify_nonce($value, $action) { return true; }
function sanitize_text_field($value) { return $value; }
function wp_unslash($value) { return $value; }
function update_option($key, $value, $autoload = false) {}

class OptionStore {
    public static function set_option($value) {
        update_option('demo_option', $value, false);
    }
}

class RoutesController {
    public function __construct() {
        add_action('rest_api_init', array($this, 'register'));
    }

    public function register() {
        register_rest_route('demo/v1', '/connection/create', array(
            'methods' => 'POST',
            'callback' => array($this, 'create_public_connection'),
            'permission_callback' => '__return_true',
        ));
    }

    public function create_public_connection($request) {
        return true;
    }
}

class AuthController {
    public function __construct() {
        add_action('admin_init', array($this, 'save_connection'));
    }

    public function save_connection() {
        if ( false === wp_verify_nonce($_GET['nonce'], 'demo') ) {
            return;
        }
        if ( false === current_user_can('administrator') ) {
            return;
        }
        $value = sanitize_text_field( wp_unslash( $_GET['sure-triggers-access-key'] ) );
        OptionStore::set_option($value);
    }
}

class Loader {
    public function __construct() {
        add_action('plugins_loaded', array($this, 'initialize'));
    }

    public function initialize() {
        new RoutesController();
        new AuthController();
    }
}

new Loader();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestBuildEngineMarksAdminInitHookAsAuthenticatedEntrypoint(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-init-hook.php"), `<?php
function add_action($hook, $callback) {}

class AuthController {
    public function __construct() {
        add_action('admin_init', array($this, 'save_connection'));
    }

    public function save_connection() {}
}

new AuthController();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	key := engine.lookupMethodKey(`\AuthController`, "save_connection")
	if key == "" {
		t.Fatal("missing save_connection key")
	}
	if len(engine.directEntryPointsByCallable[key]) != 1 {
		t.Fatalf("direct entrypoints = %#v, want 1 admin_init entrypoint", engine.directEntryPointsByCallable[key])
	}
	entry := engine.directEntryPointsByCallable[key][0]
	if entry.Kind != "front_hook" || entry.Name != "admin_init" || entry.Access != "authenticated" {
		t.Fatalf("entrypoint = %#v, want authenticated front_hook admin_init", entry)
	}
}

func TestBuildEngineMarksAttachmentDownloadActionAsDirectSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "attachment-download-sink.php"), `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}

class Demo {
    public function __construct() {
        add_action('admin_menu', array($this, 'register'));
    }

    public function register() {
        add_menu_page('Demo', 'Demo', 'read', 'demo-export', array($this, 'handle'));
    }

    public function handle() {
        $path = sanitize_text_field($_GET['path']);
        header('Content-disposition: attachment; filename=demo.txt');
        echo file_get_contents($path);
    }
}

new Demo();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	handleKey := engine.lookupMethodKey(`\Demo`, "handle")
	if handleKey == "" {
		t.Fatal("missing Demo::handle")
	}
	if !engine.callableHasDirectSink(engine.callables[handleKey]) {
		t.Fatalf("attachment download handler should stay a direct action sink")
	}
}

func TestAnalyzeRootKeepsAttachmentDownloadActionWhenGuardedAdminPageSharesUnguardedAjaxHandler(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "mixed-download-context.php"), `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}
function current_user_can($cap) { return true; }

class Demo {
    public function __construct() {
        add_action('wp_ajax_demo_export', array($this, 'ajax'));
        add_action('admin_menu', array($this, 'register'));
    }

    public function register() {
        add_menu_page('Demo', 'Demo', 'read', 'demo-export', array($this, 'page'));
    }

    public function page() {
        if ( ! current_user_can('manage_options') ) {
            return;
        }
        $this->handle();
    }

    public function ajax() {
        $this->handle();
    }

    public function handle() {
        $path = sanitize_text_field($_GET['path']);
        header('Content-disposition: attachment; filename=demo.txt');
        echo file_get_contents($path);
    }
}

new Demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	hasAdminPage := false
	hasAjax := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		switch entry.Kind {
		case "admin_page":
			hasAdminPage = true
		case "ajax":
			hasAjax = true
		}
	}
	if !hasAdminPage || !hasAjax {
		t.Fatalf("entrypoints = %#v, want mixed admin_page and ajax", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootSuppressesAttachmentDownloadActionWhenMixedAdminPageAndAjaxShareLocalCapabilityAndNonceGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "mixed-download-local-guard.php"), `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}
function current_user_can($cap) { return true; }

class Demo {
    public function __construct() {
        add_action('wp_ajax_demo_export', array($this, 'ajax'));
        add_action('admin_menu', array($this, 'register'));
    }

    public function register() {
        add_menu_page('Demo', 'Demo', 'read', 'demo-export', array($this, 'page'));
    }

    public function page() {
        if ( ! current_user_can('manage_options') ) {
            return;
        }
        $this->handle();
    }

    public function ajax() {
        $this->handle();
    }

    protected function validateToken() {
        return true;
    }

    protected function validatePermission($cap) {
        return current_user_can($cap);
    }

    public function handle() {
        if ($this->validateToken() && $this->validatePermission('manage_options')) {
            $path = sanitize_text_field($_GET['path']);
            header('Content-disposition: attachment; filename=demo.txt');
            echo file_get_contents($path);
        }
    }
}

new Demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsStoredXSSFromDBSelectInShortcodeReturn(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-stored-xss.php"), `<?php
function add_shortcode($tag, $callback) {}
function wp_kses($value, $allow = array()) { return $value; }
class DB {
    public function get_results($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    private function parse_text($text) {
        return html_entity_decode($text, ENT_QUOTES);
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $text = $this->parse_text($rows[0]->text);
        return wp_kses($text, array('div' => array('class' => true)));
    }
}
(new Demo())->boot();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	renderKey := engine.lookupMethodKey(`\Demo`, "render")
	if renderKey == "" {
		t.Fatalf("missing render method key")
	}
	if !engineCallableReturnsPublicMarkup(engine, renderKey) {
		t.Fatalf("render callable %s should be marked as a public markup return sink", renderKey)
	}

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
		t.Fatalf("check_id = %q, want wp-stored-xss-persistent-read-to-output", finding.CheckID)
	}
	if finding.Start.Line != 17 {
		t.Fatalf("sink line = %d, want 17", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 15 {
		t.Fatalf("source line = %d, want 15", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsStoredXSSFromVariableShortcodeTagMethodReturn(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-variable-tag.php"), `<?php
function add_action($tag, $callback) {}
function add_shortcode($tag, $callback) {}
function wp_kses($value, $allow = array()) { return $value; }
class DB {
    public function get_results($query) {}
}
class Demo {
    public function boot() {
        add_action('init', array($this, 'init_shortcode'));
    }
    public function get_shortcode_name() {
        return 'demo';
    }
    public function init_shortcode() {
        $tag = $this->get_shortcode_name();
        add_shortcode($tag, array($this, 'render'));
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        return wp_kses($rows[0]->text, array('div' => array('class' => true)));
    }
}
$demo = new Demo();
$demo->boot();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	renderKey := engine.lookupMethodKey(`\Demo`, "render")
	if renderKey == "" {
		t.Fatalf("missing render method key")
	}
	if _, ok := engine.directPublicCallables[renderKey]; !ok {
		t.Fatalf("render callable %s should be marked direct public from variable shortcode tag registration", renderKey)
	}

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
		t.Fatalf("check_id = %q, want wp-stored-xss-persistent-read-to-output", finding.CheckID)
	}
	if finding.Start.Line != 21 {
		t.Fatalf("sink line = %d, want 21", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 20 {
		t.Fatalf("source line = %d, want 20", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsStoredXSSFromAdminMetaboxRender(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-metabox-stored-xss.php"), `<?php
function add_action($tag, $callback) {}
function add_meta_box($id, $title, $callback, $screen = null) {}
class Loader {
    public static $dir = '';
    public static function boot() { self::$dir = __DIR__ . '/'; }
    public static function template($file, $args = array()) {
        extract($args);
        $path = self::$dir . 'templates/' . $file;
        include $path;
    }
}
class Writer {
    public function submit() {
        update_post_meta(1, 'calculations', array(
            'total' => array(
                'raw' => $_POST['raw'],
                'parsed' => $_POST['parsed'],
                'value' => $_POST['value'],
            ),
        ));
    }
}
class Sub {
    public function get_extra_value($key) {
        return get_post_meta(1, $key, true);
    }
    public function get_extra_values($keys) {
        $values = array();
        foreach ($keys as $key) {
            $values[$key] = $this->get_extra_value($key);
        }
        return $values;
    }
}
abstract class NF_Abstracts_Metabox {
    protected $_callback = 'render_metabox';
    protected $sub;
    public function __construct() {
        $this->sub = new Sub();
        add_action('add_meta_boxes', array($this, 'add_meta_boxes'));
    }
    public function add_meta_boxes() {
        add_meta_box($this->id(), 'Demo', array($this, $this->_callback), array('nf_sub'));
    }
    protected function id() { return strtolower(get_class($this)); }
    abstract public function render_metabox($post, $metabox);
}
class Demo extends NF_Abstracts_Metabox {
    public function __construct() {
        parent::__construct();
    }
    public function render_metabox($post, $metabox) {
        $data = $this->sub->get_extra_values(array('calculations'));
        Loader::boot();
        Loader::template('calcs.php', $data['calculations']);
    }
}
add_action('wp_ajax_nopriv_demo_submit', array(new Writer(), 'submit'));
new Demo();
`)
	writePHP(t, filepath.Join(root, "templates", "calcs.php"), `<?php
foreach ($data as $name => $contents) {
    echo $contents['value'];
    if (isset($_GET['calcs_debug'])) {
        echo $contents['raw'];
        echo $contents['parsed'];
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	extraValuesKey := engine.lookupMethodKey(`\Sub`, "get_extra_values")
	if extraValuesKey == "" {
		t.Fatalf("missing get_extra_values method key")
	}
	extraValueKey := engine.lookupMethodKey(`\Sub`, "get_extra_value")
	if extraValueKey == "" {
		t.Fatalf("missing get_extra_value method key")
	}
	renderKey := engine.lookupMethodKey(`\Demo`, "render_metabox")
	if renderKey == "" {
		t.Fatalf("missing render method key")
	}
	writerKey := engine.lookupMethodKey(`\Writer`, "submit")
	if writerKey == "" {
		t.Fatalf("missing writer method key")
	}
	if got := engine.receiverPropertyReturnClassHint(`\Demo`, "this.sub"); got != `\Sub` {
		t.Fatalf("receiverPropertyReturnClassHint(\\Demo, this.sub) = %q, want \\Sub; hints=%#v", got, engine.receiverPropertyClassHints)
	}
	if _, ok := engine.directPublicCallables[renderKey]; !ok {
		t.Fatalf("render callable %s should be marked direct public from add_meta_box registration", renderKey)
	}
	if _, ok := engine.relevantCallables[renderKey]; !ok {
		t.Fatalf("render callable %s should stay relevant", renderKey)
	}
	if _, ok := engine.relevantCallables[writerKey]; !ok {
		t.Fatalf("writer callable %s should stay relevant", writerKey)
	}
	if _, ok := engine.relevantCallables[extraValuesKey]; !ok {
		t.Fatalf("get_extra_values callable %s should stay relevant", extraValuesKey)
	}
	if _, ok := engine.relevantCallables[extraValueKey]; !ok {
		t.Fatalf("get_extra_value callable %s should stay relevant", extraValueKey)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "calcs.php")) || finding.Start.Line != 3 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("metabox calculations output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSkipsDeadLocalReceiverMutationsButKeepsLaterLocalReceiverRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "dead-local-receiver.php"), `<?php
class Mailer {
    public function process_mail($data) {
        $this->path = $data['path'];
    }
}

class Demo {
    public function dead() {
        $forminator_mail_sender = new Mailer();
        $forminator_mail_sender->process_mail($_GET);
        return 'ok';
    }

    public function live() {
        $forminator_mail_sender = new Mailer();
        $forminator_mail_sender->process_mail($_GET);
        return $forminator_mail_sender->path;
    }
}

function run_live() {
    $demo = new Demo();
    $path = $demo->live();
    unlink($path);
}

run_live();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	deadKey := engine.lookupMethodKey(`\Demo`, "dead")
	if deadKey == "" {
		t.Fatal("missing Demo::dead")
	}
	if got := engine.summaries[deadKey]; !summaryHasNoEffects(got) {
		t.Fatalf("Demo::dead summary leaked dead local receiver effects: %+v", got)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 25 {
		t.Fatalf("sink line = %d, want 25", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 17 {
		t.Fatalf("source line = %d, want 17", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootKeepsReceiverMutatingHelperOnDeleteDataChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "receiver-delete-chain.php"), `<?php
class Entry {
    public $entry_id = 0;
    public $meta_data = array();

    public function __construct($entry_id) {
        $this->get($entry_id);
    }

    public function get($entry_id) {
        $this->entry_id = $entry_id;
        $this->load_meta();
    }

    public function load_meta() {
        if ($this->entry_id > 0) {
            $this->meta_data['upload'] = array(
                'value' => array(
                    'file' => array(
                        'file_path' => array($_GET['path']),
                    ),
                ),
            );
        }
    }

    public static function delete_by_entrys($entry_id) {
        $entry = new Entry($entry_id);
        self::entry_delete_upload_files($entry);
    }

    public static function entry_delete_upload_files($entry) {
        foreach ($entry->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            if (is_array($meta_value) && isset($meta_value['file'])) {
                $file_path = is_array($meta_value['file']['file_path']) ? $meta_value['file']['file_path'] : array($meta_value['file']['file_path']);
                foreach ($file_path as $path) {
                    unlink($path);
                }
            }
        }
    }
}

class Page {
    public function process_request() {
        $id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);
        if ($id) {
            Entry::delete_by_entrys($id);
        }
    }
}

(new Page())->process_request();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	loadMetaKey := engine.lookupMethodKey(`\Entry`, "load_meta")
	if loadMetaKey == "" {
		t.Fatal("missing Entry::load_meta")
	}
	if _, ok := engine.relevantCallables[loadMetaKey]; !ok {
		getKey := engine.lookupMethodKey(`\Entry`, "get")
		t.Fatalf("Entry::load_meta should stay relevant in delete data chain: relevant=%#v get_sites=%#v receiver_mutating=%#v", engine.relevantCallables, engine.callSiteEdges[getKey], engine.receiverMutatingCallables)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line == 38 && (finding.CheckID == "wp-request-file-delete-without-cap-check" || finding.CheckID == "request-path-read-delete") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("receiver-mutating delete chain finding missing: %#v", result.Payload.Results)
	}
}

func TestReceiverPropertyReturnClassHintCachesFallbackResolution(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "receiver-property-fallback-cache.php"), `<?php
class Sub {}
class Demo {
    private $sub;
    public function __construct() {
        $this->sub = new Sub();
    }
    public function get() {
        return $this->sub;
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	engine.receiverPropertyClassHints = map[string][]string{}
	engine.receiverPropertyFallbackHints = map[string]classHintCandidatesCacheEntry{}

	if got := engine.receiverPropertyReturnClassHint(`\Demo`, "this.sub"); got != `\Sub` {
		t.Fatalf("first receiverPropertyReturnClassHint(\\Demo, this.sub) = %q, want \\Sub", got)
	}
	cacheKey := receiverPropertyClassHintKey(`\Demo`, "this.sub")
	entry, ok := engine.receiverPropertyFallbackHints[cacheKey]
	if !ok || !entry.Computed {
		t.Fatalf("missing computed fallback cache entry for %s: %#v", cacheKey, engine.receiverPropertyFallbackHints)
	}
	if len(entry.Candidates) != 1 || entry.Candidates[0] != `\Sub` {
		t.Fatalf("fallback cache entry = %#v, want [\\\\Sub]", entry)
	}

	engine.callOrder = nil
	if got := engine.receiverPropertyReturnClassHint(`\Demo`, "this.sub"); got != `\Sub` {
		t.Fatalf("cached receiverPropertyReturnClassHint(\\Demo, this.sub) = %q, want \\Sub", got)
	}
	if candidates := engine.receiverPropertyReturnClassCandidates(`\Demo`, "this.missing"); len(candidates) != 0 {
		t.Fatalf("receiverPropertyReturnClassCandidates(\\Demo, this.missing) = %#v, want nil", candidates)
	}
	missEntry, ok := engine.receiverPropertyFallbackHints[receiverPropertyClassHintKey(`\Demo`, "this.missing")]
	if !ok || !missEntry.Computed || len(missEntry.Candidates) != 0 {
		t.Fatalf("missing negative fallback cache entry: %#v", missEntry)
	}
}

func TestReceiverPropertyReturnClassHintStopsRecursiveFallbackCycles(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "receiver-property-fallback-cycle.php"), `<?php
class Demo {
    private $sub;
    public function warm() {
        $this->sub = $this->get();
    }
    public function get() {
        return $this->sub;
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	engine.receiverPropertyClassHints = map[string][]string{}
	engine.receiverPropertyFallbackHints = map[string]classHintCandidatesCacheEntry{}

	if got := engine.receiverPropertyReturnClassHint(`\Demo`, "this.sub"); got != "" {
		t.Fatalf("receiverPropertyReturnClassHint(\\Demo, this.sub) = %q, want empty on recursive cycle", got)
	}
	entry, ok := engine.receiverPropertyFallbackHints[receiverPropertyClassHintKey(`\Demo`, "this.sub")]
	if !ok || !entry.Computed || len(entry.Candidates) != 0 {
		t.Fatalf("missing computed empty fallback cache entry for recursive cycle: %#v", entry)
	}
}

func TestAnalyzeRootFindsStoredXSSFromParameterizedExtraValueSaveLoop(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "submission-extra-stored-xss.php"), `<?php
function add_action($tag, $callback) {}
function add_shortcode($tag, $callback) {}
class Loader {
    public static $dir = '';
    public static function boot() { self::$dir = __DIR__ . '/'; }
    public static function template($file, $data) {
        $path = self::$dir . 'templates/' . $file;
        include $path;
    }
}
class Submission {
    protected $_extra_values = array();
    public function update_extra_value($key, $value) {
        if (property_exists($this, $key)) return false;
        return $this->_extra_values[$key] = $value;
    }
    public function save() {
        foreach ($this->_extra_values as $key => $value) {
            update_post_meta(1, $key, $value);
        }
    }
    public function get_extra_value($key) {
        return get_post_meta(1, $key, true);
    }
    public function get_extra_values($keys) {
        $values = array();
        foreach ($keys as $key) {
            $values[$key] = $this->get_extra_value($key);
        }
        return $values;
    }
}
class Writer {
    public function submit() {
        $sub = new Submission();
        $sub->update_extra_value('calculations', array(
            'total' => array(
                'raw' => $_POST['raw'],
                'parsed' => $_POST['parsed'],
                'value' => $_POST['value'],
            ),
        ));
        $sub->save();
    }
}
class Reader {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render() {
        $sub = new Submission();
        $data = $sub->get_extra_values(array('calculations'));
        Loader::boot();
        Loader::template('calcs.php', $data['calculations']);
    }
}
add_action('wp_ajax_nopriv_demo_submit', array(new Writer(), 'submit'));
(new Reader())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "calcs.php"), `<?php
foreach ($data as $name => $contents) {
    echo $contents['value'];
    if (isset($_GET['calcs_debug'])) {
        echo $contents['raw'];
        echo $contents['parsed'];
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "calcs.php")) || finding.Start.Line != 3 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("stored extra values output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSFromNestedExtraParamSaveLoop(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "submission-nested-extra-param-stored-xss.php"), `<?php
function add_action($tag, $callback) {}
function add_shortcode($tag, $callback) {}
class Loader {
    public static $dir = '';
    public static function boot() { self::$dir = __DIR__ . '/'; }
    public static function template($file, $data) {
        $path = self::$dir . 'templates/' . $file;
        include $path;
    }
}
class Submission {
    protected $_extra_values = array();
    public function update_extra_value($key, $value) {
        return $this->_extra_values[$key] = $value;
    }
    public function update_extra_values($values) {
        foreach ($values as $key => $value) {
            $this->update_extra_value($key, $value);
        }
    }
    public function save() {
        foreach ($this->_extra_values as $key => $value) {
            update_post_meta(1, $key, $value);
        }
    }
    public function get_extra_value($key) {
        if (!isset($this->_extra_values[$key]) || !$this->_extra_values[$key]) {
            $this->_extra_values[$key] = get_post_meta(1, $key, true);
        }
        return $this->_extra_values[$key];
    }
    public function get_extra_values($keys) {
        $values = array();
        foreach ($keys as $key) {
            $values[$key] = $this->get_extra_value($key);
        }
        return $values;
    }
}
class SaveFlow {
    public function process($data) {
        $sub = new Submission();
        if (isset($data['extra'])) {
            $sub->update_extra_values($data['extra']);
        }
        $sub->save();
    }
}
class Writer {
    public function submit() {
        (new SaveFlow())->process(array(
            'extra' => array(
                'calculations' => array(
                    'total' => array(
                        'raw' => $_POST['raw'],
                        'parsed' => $_POST['parsed'],
                        'value' => $_POST['value'],
                    ),
                ),
            ),
        ));
    }
}
class Reader {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render() {
        $sub = new Submission();
        $data = $sub->get_extra_values(array('calculations'));
        Loader::boot();
        Loader::template('calcs.php', $data['calculations']);
    }
}
add_action('wp_ajax_nopriv_demo_submit', array(new Writer(), 'submit'));
(new Reader())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "calcs.php"), `<?php
foreach ($data as $name => $contents) {
    echo $contents['value'];
    if (isset($_GET['calcs_debug'])) {
        echo $contents['raw'];
        echo $contents['parsed'];
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "calcs.php")) || finding.Start.Line != 3 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("stored nested extra param output finding missing: results=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSWriteSideSourceForNestedExtraParamSaveLoop(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "submission-nested-extra-write-source.php"), `<?php
function add_action($tag, $callback) {}
function add_shortcode($tag, $callback) {}
class Loader {
    public static $dir = '';
    public static function boot() { self::$dir = __DIR__ . '/'; }
    public static function template($file, $data) {
        $path = self::$dir . 'templates/' . $file;
        include $path;
    }
}
class Submission {
    protected $_extra_values = array();
    public function update_extra_value($key, $value) {
        return $this->_extra_values[$key] = $value;
    }
    public function update_extra_values($values) {
        foreach ($values as $key => $value) {
            $this->update_extra_value($key, $value);
        }
    }
    public function save() {
        foreach ($this->_extra_values as $key => $value) {
            update_post_meta(1, $key, $value);
        }
    }
    public function get_extra_value($key) {
        if (!isset($this->_extra_values[$key]) || !$this->_extra_values[$key]) {
            $this->_extra_values[$key] = get_post_meta(1, $key, true);
        }
        return $this->_extra_values[$key];
    }
    public function get_extra_values($keys) {
        $values = array();
        foreach ($keys as $key) {
            $values[$key] = $this->get_extra_value($key);
        }
        return $values;
    }
}
class SaveFlow {
    public function process($data) {
        $sub = new Submission();
        if (isset($data['extra'])) {
            $sub->update_extra_values($data['extra']);
        }
        $sub->save();
    }
}
class Writer {
    public function submit() {
        (new SaveFlow())->process(array(
            'extra' => array(
                'calculations' => array(
                    'total' => array(
                        'value' => $_POST['value'],
                    ),
                ),
            ),
        ));
    }
}
class Reader {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render() {
        $sub = new Submission();
        $data = $sub->get_extra_values(array('calculations'));
        Loader::boot();
        Loader::template('calcs.php', $data['calculations']);
    }
}
add_action('wp_ajax_nopriv_demo_submit', array(new Writer(), 'submit'));
(new Reader())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "calcs.php"), `<?php
foreach ($data as $name => $contents) {
    echo $contents['value'];
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "calcs.php")) || finding.Start.Line != 3 {
			continue
		}
		if strings.Contains(finding.Extra.Trace.Source.Snippet, "$_POST['value']") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("stored extra values write-side source finding missing: results=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSWriteSideSourceForReceiverBackedExtraSaveLoopWithDynamicRecordID(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "submission-receiver-extra-dynamic-id.php"), `<?php
function add_action($tag, $callback) {}
function add_shortcode($tag, $callback) {}
function absint($value) { return $value; }
class Loader {
    public static $dir = '';
    public static function boot() { self::$dir = __DIR__ . '/'; }
    public static function template($file, $data) {
        $path = self::$dir . 'templates/' . $file;
        include $path;
    }
}
class Submission {
    protected $_id = 0;
    protected $_extra_values = array();
    public function __construct($id = 0) {
        $this->_id = $id;
    }
    public function update_extra_values($values) {
        foreach ($values as $key => $value) {
            $this->_extra_values[$key] = $value;
        }
    }
    public function save() {
        foreach ($this->_extra_values as $key => $value) {
            update_post_meta($this->_id, $key, $value);
        }
    }
    public function get_extra_value($key) {
        $id = $this->_id ? $this->_id : 0;
        if (!isset($this->_extra_values[$key]) || !$this->_extra_values[$key]) {
            $this->_extra_values[$key] = get_post_meta($id, $key, true);
        }
        return $this->_extra_values[$key];
    }
    public function get_extra_values($keys) {
        $values = array();
        foreach ($keys as $key) {
            $values[$key] = $this->get_extra_value($key);
        }
        return $values;
    }
}
class Writer {
    private function resolve_submission_id() {
        return isset($_POST['sub_id']) ? absint($_POST['sub_id']) : 0;
    }
    public function submit() {
        $sub = new Submission($this->resolve_submission_id());
        $sub->update_extra_values(array(
            'calculations' => array(
                'total' => array(
                    'value' => $_POST['value'],
                ),
            ),
        ));
        $sub->save();
    }
}
class Reader {
    private function resolve_submission_id() {
        return isset($_GET['post']) ? absint($_GET['post']) : 0;
    }
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render() {
        $sub = new Submission($this->resolve_submission_id());
        $data = $sub->get_extra_values(array('calculations'));
        Loader::boot();
        Loader::template('calcs.php', $data['calculations']);
    }
}
add_action('wp_ajax_nopriv_demo_submit', array(new Writer(), 'submit'));
(new Reader())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "calcs.php"), `<?php
foreach ($data as $name => $contents) {
    echo $contents['value'];
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "calcs.php")) || finding.Start.Line != 3 {
			continue
		}
		if strings.Contains(finding.Extra.Trace.Source.Snippet, "$_POST['value']") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("receiver-backed dynamic-id write-side source finding missing: results=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSkipsStoredXSSFromAggregateScalarReadToOutput(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-aggregate-count.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_var($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $count = (new DB())->get_var("SELECT COUNT(id) FROM reviews");
        return '<div>' . $count . '</div>';
    }
}
(new Demo())->boot();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %#v, want none", result.Payload.Results)
	}
}

func TestAnalyzeRootSkipsStoredXSSFromNonContentScalarReadToOutput(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-scalar-view-count.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_var($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $views = (new DB())->get_var("SELECT viewed FROM reviews");
        return '<div>' . $views . '</div>';
    }
}
(new Demo())->boot();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %#v, want none", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSFromContentLikeScalarReadToOutput(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-scalar-review-text.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_var($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $text = (new DB())->get_var("SELECT review_text FROM reviews");
        return '<div>' . $text . '</div>';
    }
}
(new Demo())->boot();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if finding.Start.Line != 12 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("stored xss finding missing from content-like scalar db read: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSAfterHTMLDecodeFromSanitizedDBWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-db-write-safe-read-unsafe.php"), `<?php
function add_shortcode($tag, $callback) {}
function wp_kses($value, $allow = array()) { return $value; }
function wp_kses_post($value) { return $value; }
function sanitize_text_field($value) { return $value; }
class DB {
    public function insert($table, $row) {}
    public function prepare($query, ...$args) { return $query; }
    public function get_results($query) {}
}
class Demo {
    public function get_table($name) {
        return 'prefix_' . $name;
    }
    public function save_reviews($rows) {
        $db = new DB();
        foreach ($rows as $row) {
            $db->insert($this->get_table('reviews'), array(
                'text' => wp_kses_post($row['text']),
                'user' => sanitize_text_field($row['user']),
            ));
        }
    }
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $db = new DB();
        $rows = $db->get_results($db->prepare('SELECT * FROM %i', $this->get_table('reviews')));
        return wp_kses(html_entity_decode($rows[0]->text, ENT_QUOTES), array('div' => array('class' => true)));
    }
}
$demo = new Demo();
$demo->save_reviews(array(array('text' => $_POST['text'], 'user' => $_POST['user'])));
$demo->boot();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if finding.Start.Line != 30 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("stored xss finding missing from sanitized db write + html decode flow: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSAfterURLSanitizersOnPersistentWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-db-write-url-sanitized-read-unsafe.php"), `<?php
function add_shortcode($tag, $callback) {}
function sanitize_url($value) { return $value; }
function esc_url_raw($value) { return $value; }
class DB {
    public function insert($table, $row) {}
    public function prepare($query, ...$args) { return $query; }
    public function get_results($query) {}
}
class Demo {
    public function get_table($name) {
        return 'prefix_' . $name;
    }
    public function save_referrer() {
        $db = new DB();
        $db->insert($this->get_table('visitor'), array(
            'refer' => esc_url_raw(sanitize_url($_REQUEST['referred'])),
        ));
    }
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $db = new DB();
        $rows = $db->get_results($db->prepare('SELECT * FROM %i', $this->get_table('visitor')));
        return '<a>' . preg_replace("(^https?://)", "", trim($rows[0]->refer)) . '</a>';
    }
}
$demo = new Demo();
$demo->save_referrer();
$demo->boot();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if finding.Start.Line != 26 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("stored xss finding missing after url sanitizers on persistent write: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSFromVariablePreparedVisitorQuery(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-db-write-variable-query-read-unsafe.php"), `<?php
function add_shortcode($tag, $callback) {}
function sanitize_url($value) { return $value; }
function esc_url_raw($value) { return $value; }
class DB {
    public static function table($name) { return $name; }
    public function insert($table, $row) {}
    public function prepare($query, ...$args) { return $query; }
    public function get_results($query) {}
}
class Visitor {
    public static function save_referrer() {
        $db = new DB();
        $db->insert(DB::table('visitor'), array(
            'referred' => esc_url_raw(sanitize_url($_REQUEST['referred'])),
        ));
    }
    public static function get_referrers() {
        $db = new DB();
        $sql = $db->prepare("SELECT * FROM " . DB::table('visitor') . " WHERE referred <> ''");
        return $db->get_results($sql);
    }
    public static function render($atts) {
        $rows = self::get_referrers();
        $item = array('refer' => $rows[0]->referred);
        return '<a>' . preg_replace("(^https?://)", "", trim($item['refer'])) . '</a>';
    }
}
add_shortcode('demo', array('Visitor', 'render'));
Visitor::save_referrer();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if finding.Start.Line != 26 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("stored xss finding missing for variable prepared visitor query: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSInIncludedTemplateUsingCallerLocal(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_results($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $data = array('refer' => $rows[0]->refer);
        include __DIR__ . '/template.php';
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "template.php"), `<?php
echo preg_replace("(^https?://)", "", trim($data['refer']));
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, "template.php") || finding.Start.Line != 2 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("included template local output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSInIncludedTemplateAfterExtract(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_results($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $args = array('title' => $rows[0]->text);
        extract($args);
        include __DIR__ . '/template.php';
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "template.php"), `<?php
echo $title;
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, "template.php") || finding.Start.Line != 2 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("included template extract output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSInIncludedTemplateForeachAfterExtract(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_results($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $args = array(
            'list' => array(
                array('refer' => $rows[0]->text),
            ),
        );
        extract($args);
        include __DIR__ . '/template.php';
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "template.php"), `<?php
foreach ($list as $item) {
    echo preg_replace("(^https?://)", "", trim($item['refer']));
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, "template.php") || finding.Start.Line != 3 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("included template foreach extract output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSInIncludedTemplateAfterHelperReturnsForeachBuiltList(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_results($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public static function prepareRows($rows) {
        $list = array();
        foreach ($rows as $row) {
            $list[] = array('refer' => $row->text);
        }
        return $list;
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $args = array(
            'list' => self::prepareRows($rows),
        );
        extract($args);
        include __DIR__ . '/template.php';
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "template.php"), `<?php
foreach ($list as $item) {
    echo preg_replace("(^https?://)", "", trim($item['refer']));
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, "template.php") || finding.Start.Line != 3 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("included template helper foreach output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSThroughForeachTemplateLoader(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_results($query) {}
}
class AdminTemplate {
    public static function get_template($template, $args = array()) {
        if (is_array($args) && isset($args)) {
            extract($args);
        }
        if (is_string($template)) {
            $template = explode(" ", $template);
        }
        foreach ($template as $file) {
            $template_file = __DIR__ . "/templates/{$file}.php";
            include $template_file;
        }
    }
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public static function prepareRows($rows) {
        $list = array();
        foreach ($rows as $row) {
            $list[] = array('refer' => $row->text);
        }
        return $list;
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $args = array('list' => self::prepareRows($rows));
        AdminTemplate::get_template(array('refer'), $args);
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "refer.php"), `<?php
foreach ($list as $item) {
    echo preg_replace("(^https?://)", "", trim($item['refer']));
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "refer.php")) || finding.Start.Line != 3 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("foreach template loader output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSThroughForeachTemplateLoaderUsingPluginDirPathConstant(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
function plugin_dir_path($path) { return dirname($path) . '/'; }
define('PLUGIN_ROOT', plugin_dir_path(__FILE__));
class DB {
    public function get_results($query) {}
}
class AdminTemplate {
    public static function get_template($template, $args = array()) {
        if (is_array($args) && isset($args)) {
            extract($args);
        }
        if (is_string($template)) {
            $template = explode(" ", $template);
        }
        foreach ($template as $file) {
            $template_file = PLUGIN_ROOT . "templates/{$file}.php";
            include $template_file;
        }
    }
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public static function prepareRows($rows) {
        $list = array();
        foreach ($rows as $row) {
            $list[] = array('refer' => $row->text);
        }
        return $list;
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $args = array('list' => self::prepareRows($rows));
        AdminTemplate::get_template(array('refer'), $args);
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "refer.php"), `<?php
foreach ($list as $item) {
    echo preg_replace("(^https?://)", "", trim($item['refer']));
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "refer.php")) || finding.Start.Line != 3 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("plugin_dir_path template loader output finding missing: %#v", result.Payload.Results)
	}
}

func TestBuildEngineSpecializesForeachTemplateLoaderForListLiteralArgs(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
class AdminTemplate {
    public static function get_template($template, $args = array()) {
        if (is_array($args) && isset($args)) {
            extract($args);
        }
        if (is_string($template)) {
            $template = explode(" ", $template);
        }
        foreach ($template as $file) {
            $template_file = __DIR__ . "/templates/{$file}.php";
            include $template_file;
        }
    }
}
class Demo {
    public function render_country() {
        AdminTemplate::get_template(array('country'), array('title' => 'safe'));
    }
    public function render_addons() {
        AdminTemplate::get_template(array('addons'), array('title' => 'safe'));
    }
}
`)
	writePHP(t, filepath.Join(root, "templates", "country.php"), `<?php echo esc_html($title);`)
	writePHP(t, filepath.Join(root, "templates", "addons.php"), `<?php echo $title;`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	templateKey := engine.ensureRuntimeMethodCallable(`\AdminTemplate`, "get_template")
	if templateKey == "" {
		t.Fatalf("missing AdminTemplate::get_template")
	}

	countryHints := map[int]map[string]string{
		0: {
			literalArgPathHintKey([]string{"0"}): "country",
		},
		1: {
			literalArgPathHintKey([]string{"title"}): "safe",
		},
	}
	addonsHints := map[int]map[string]string{
		0: {
			literalArgPathHintKey([]string{"0"}): "addons",
		},
		1: {
			literalArgPathHintKey([]string{"title"}): "safe",
		},
	}

	engine.currentBatchName = "output"
	countryKey := engine.existingSpecializedCallableForLiteralArgsAndPaths(templateKey, nil, countryHints)
	addonsKey := engine.existingSpecializedCallableForLiteralArgsAndPaths(templateKey, nil, addonsHints)
	if countryKey == "" || countryKey == templateKey {
		t.Fatalf("expected specialized country template callable, got %q", countryKey)
	}
	if addonsKey == "" || addonsKey == templateKey {
		t.Fatalf("expected specialized addons template callable, got %q", addonsKey)
	}

	findIncludeExpr := func(key string) ast.Node {
		current := engine.callables[key]
		var includeExpr ast.Node
		walkNodes(current.Stmts, func(node ast.Node) {
			if includeExpr != nil {
				return
			}
			includeNode, ok := node.(*ast.ExprInclude)
			if !ok {
				return
			}
			includeExpr = includeNode.Expr
		})
		return includeExpr
	}

	countryExpr := findIncludeExpr(countryKey)
	if countryExpr == nil {
		t.Fatalf("missing include expr in %s", countryKey)
	}
	countryIncludes := engine.staticIncludedFileCallableKeys(countryExpr, engine.callables[countryKey])
	if len(countryIncludes) != 1 || !strings.HasSuffix(countryIncludes[0], "templates/country.php") {
		t.Fatalf("country include keys = %#v, want only templates/country.php", countryIncludes)
	}

	addonsExpr := findIncludeExpr(addonsKey)
	if addonsExpr == nil {
		t.Fatalf("missing include expr in %s", addonsKey)
	}
	addonsIncludes := engine.staticIncludedFileCallableKeys(addonsExpr, engine.callables[addonsKey])
	if len(addonsIncludes) != 1 || !strings.HasSuffix(addonsIncludes[0], "templates/addons.php") {
		t.Fatalf("addons include keys = %#v, want only templates/addons.php", addonsIncludes)
	}
}

func TestAnalyzeRootSpecializesForeachTemplateLoaderAcrossListLiteralCallsites(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
function esc_html($value) { return $value; }
class DB {
    public function get_results($query) {}
}
class AdminTemplate {
    public static function get_template($template, $args = array()) {
        if (is_array($args) && isset($args)) {
            extract($args);
        }
        if (is_string($template)) {
            $template = explode(" ", $template);
        }
        foreach ($template as $file) {
            $template_file = __DIR__ . "/templates/{$file}.php";
            include $template_file;
        }
    }
}
class Demo {
    public function boot() {
        add_shortcode('country', array($this, 'render_country'));
        add_shortcode('addons', array($this, 'render_addons'));
    }
    public function render_country($atts) {
        AdminTemplate::get_template(array('country'), array('title' => 'safe'));
    }
    public function render_addons($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        AdminTemplate::get_template(array('addons'), array('title' => $rows[0]->text));
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "country.php"), `<?php
echo esc_html($title);
`)
	writePHP(t, filepath.Join(root, "templates", "addons.php"), `<?php
echo $title;
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}

	var addonsFindings int
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if strings.HasSuffix(finding.Path, filepath.Join("templates", "country.php")) {
			t.Fatalf("country template should not receive cross-template stored XSS finding: %#v", result.Payload.Results)
		}
		if strings.HasSuffix(finding.Path, filepath.Join("templates", "addons.php")) && finding.Start.Line == 2 {
			addonsFindings++
		}
	}
	if addonsFindings != 1 {
		t.Fatalf("addons template findings = %d, want 1: %#v", addonsFindings, result.Payload.Results)
	}
}

func TestAnalyzeRootKeepsBoundedTernaryTemplateChoicesInForeachLoader(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
function esc_html($value) { return $value; }
class DB {
    public function get_results($query) {}
}
class AdminTemplate {
    public static function get_template($template, $args = array()) {
        if (is_array($args) && isset($args)) {
            extract($args);
        }
        if (is_string($template)) {
            $template = explode(" ", $template);
        }
        foreach ($template as $file) {
            $template_file = __DIR__ . "/templates/{$file}.php";
            include $template_file;
        }
    }
}
class Demo {
    public function boot() {
        add_shortcode('country', array($this, 'render_country'));
        add_shortcode('refer', array($this, 'render_refer'));
    }
    public function render_country($atts) {
        AdminTemplate::get_template(array('country'), array('title' => 'safe'));
    }
    public function render_refer($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $args = array('list' => array(array('refer' => $rows[0]->text)));
        if (isset($_GET['referrer'])) {
            $referrer = $_GET['referrer'];
        }
        AdminTemplate::get_template(array('layout/header', isset($referrer) ? 'pages/refer.url' : 'pages/top.refer', 'layout/footer'), $args);
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "country.php"), `<?php
echo esc_html($title);
`)
	writePHP(t, filepath.Join(root, "templates", "layout", "header.php"), `<?php
echo "header";
`)
	writePHP(t, filepath.Join(root, "templates", "layout", "footer.php"), `<?php
echo "footer";
`)
	writePHP(t, filepath.Join(root, "templates", "pages", "top.refer.php"), `<?php
echo "top";
`)
	writePHP(t, filepath.Join(root, "templates", "pages", "refer.url.php"), `<?php
foreach ($list as $item) {
    echo preg_replace("(^https?://)", "", trim($item['refer']));
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}

	var referFindings int
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if strings.HasSuffix(finding.Path, filepath.Join("templates", "country.php")) {
			t.Fatalf("country template should not receive cross-template stored XSS finding: %#v", result.Payload.Results)
		}
		if strings.HasSuffix(finding.Path, filepath.Join("templates", "pages", "refer.url.php")) && finding.Start.Line == 3 {
			referFindings++
		}
	}
	if referFindings != 1 {
		t.Fatalf("refer template findings = %d, want 1: %#v", referFindings, result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSThroughDirectTemplateLoaderHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
class DB {
    public function get_results($query) {}
}
class AdminTemplate {
    public static function get_template($args = array()) {
        if (is_array($args) && isset($args)) {
            extract($args);
        }
        include __DIR__ . "/templates/refer.php";
    }
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public static function prepareRows($rows) {
        $list = array();
        foreach ($rows as $row) {
            $list[] = array('refer' => $row->text);
        }
        return $list;
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $args = array('list' => self::prepareRows($rows));
        AdminTemplate::get_template($args);
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "refer.php"), `<?php
foreach ($list as $item) {
    echo preg_replace("(^https?://)", "", trim($item['refer']));
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "refer.php")) || finding.Start.Line != 3 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("direct template loader helper output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsStoredXSSThroughStaticPropertyTemplateLoader(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "main.php"), `<?php
function add_shortcode($tag, $callback) {}
function plugin_dir_path($path) { return dirname($path) . '/'; }
class DB {
    public function get_results($query) {}
}
class AdminTemplate {
    public static $dir = '';

    public static function init() {
        self::$dir = plugin_dir_path(__FILE__);
    }

    public static function get_template($args = array()) {
        if (is_array($args) && isset($args)) {
            extract($args);
        }
        include self::$dir . "templates/refer.php";
    }
}
class Demo {
    public function boot() {
        AdminTemplate::init();
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        AdminTemplate::get_template(array('title' => $rows[0]->text));
    }
}
(new Demo())->boot();
`)
	writePHP(t, filepath.Join(root, "templates", "refer.php"), `<?php
echo $title;
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-stored-xss-persistent-read-to-output" {
			continue
		}
		if !strings.HasSuffix(finding.Path, filepath.Join("templates", "refer.php")) || finding.Start.Line != 2 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("static property template loader output finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSkipsStoredXSSAfterWPKsesPostBoundary(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-stored-xss-kses-post.php"), `<?php
function add_shortcode($tag, $callback) {}
function wp_kses($value, $allow = array()) { return $value; }
function wp_kses_post($value) { return $value; }
class DB {
    public function get_results($query) {}
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    private function parse_text($text) {
        return wp_kses_post(html_entity_decode($text, ENT_QUOTES));
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $text = $this->parse_text($rows[0]->text);
        return wp_kses($text, array('div' => array('class' => true)));
    }
}
(new Demo())->boot();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %#v, want none", result.Payload.Results)
	}
}

func TestAnalyzeRootSkipsStoredXSSPlaceholderAfterEscHTMLBoundaryInHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "helper-esc-html.php"), `<?php
function add_shortcode($tag, $callback) {}
function esc_html($value) { return $value; }
class DB {
    public function get_results($query) {}
}
class Helper {
    public static function render_item($value) {
        echo esc_html($value);
    }
}
class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }
    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        Helper::render_item($rows[0]->text);
    }
}
(new Demo())->boot();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %#v, want none", result.Payload.Results)
	}
}

func TestAnalyzeRootSkipsStoredXSSReturnForNonPublicHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "helper-return.php"), `<?php
function wp_kses($value, $allow = array()) { return $value; }
class DB {
    public function get_results($query) {}
}
class Demo {
    private function parse_text($text) {
        return html_entity_decode($text, ENT_QUOTES);
    }
    public function render() {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $text = $this->parse_text($rows[0]->text);
        return wp_kses($text, array('div' => array('class' => true)));
    }
}
(new Demo())->render();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %#v, want none", result.Payload.Results)
	}
}

func TestBuildEngineMarksPostSMTPDisclosureConstructorRelevant(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/post-smtp__3.6.0"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("post-smtp test target unavailable: %v", err)
	}

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := `method::\PostmanEmailLogs::__construct`
	if _, ok := engine.callables[key]; !ok {
		t.Fatalf("missing callable %s", key)
	}
	if _, ok := engine.recordReadCallables[key]; !ok {
		t.Fatalf("callable %s should be marked as a record-read callable", key)
	}
	if !engine.callableHasDirectSink(engine.callables[key]) {
		t.Fatalf("callable %s should be treated as a direct disclosure sink", key)
	}
	if _, ok := engine.relevantCallables[key]; !ok {
		t.Fatalf("callable %s should stay relevant for output scans", key)
	}
}

func TestBuildEngineMarksUltimateMemberMetaAjaxGetMembersReachableAndRelevant(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/ultimate-member__2.9.1"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("ultimate-member test target unavailable: %v", err)
	}

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := `method::\um\core\Member_Directory_Meta::ajax_get_members`
	if _, ok := engine.callables[key]; !ok {
		nearby := make([]string, 0)
		fileKeys := make([]string, 0)
		for candidate := range engine.callables {
			lower := strings.ToLower(candidate)
			if strings.Contains(lower, "member_directory") && strings.Contains(lower, "ajax_get_members") {
				nearby = append(nearby, candidate)
			}
			if strings.Contains(engine.callables[candidate].SourcePath, "class-member-directory-meta.php") ||
				strings.Contains(engine.callables[candidate].SourcePath, "class-member-directory.php") {
				fileKeys = append(fileKeys, candidate+"@"+engine.callables[candidate].SourcePath)
			}
		}
		sort.Strings(nearby)
		sort.Strings(fileKeys)
		t.Fatalf("missing callable %s; nearby=%v filekeys=%v", key, nearby, fileKeys)
	}
	if !engine.callableHasDirectSink(engine.callables[key]) {
		t.Fatalf("callable %s should be treated as a direct sql sink", key)
	}
	if _, ok := engine.requestReachableCallables[key]; !ok {
		t.Fatalf("callable %s should be request-reachable for sql scans", key)
	}
	if _, ok := engine.relevantCallables[key]; !ok {
		t.Fatalf("callable %s should stay relevant for sql scans", key)
	}
}

func TestBuildEngineSkipsUnreachableDirectSQLSinkSeeds(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "reachable-sql-sinks.php"), `<?php
class DB {
    public function query($sql) {}
}

class LiveSQL {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_sql', array($this, 'run'));
    }

    public function helper($sql) {
        $db = new DB();
        $db->query($sql);
    }

    public function run() {
        $this->helper($_GET['sql']);
    }
}

class DeadSQL {
    public function run() {
        $db = new DB();
        $db->query("DELETE FROM demo");
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	liveHelperRelevant := false
	deadRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "LiveSQL::helper") {
			liveHelperRelevant = true
		}
		if strings.HasSuffix(key, "DeadSQL::run") {
			deadRelevant = true
		}
	}
	if !liveHelperRelevant {
		t.Fatalf("LiveSQL::helper should stay relevant for request-reachable sql scans")
	}
	if deadRelevant {
		t.Fatalf("DeadSQL::run should not be seeded when the direct sql sink is unreachable from request flow")
	}
}

func TestBuildEngineSkipsUnreachableReverseCallersForRequestGatedSQLSinks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "reverse-sql-callers.php"), `<?php
class DB {
    public function query($sql) {}
}

class SQLHelper {
    public function run_query($sql) {
        $db = new DB();
        $db->query($sql);
    }
}

class LiveController {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_controller_sql', array($this, 'handle_request'));
    }

    public function handle_request() {
        $helper = new SQLHelper();
        $helper->run_query($_GET['sql']);
    }
}

class ImportController {
    public function replay($payload) {
        $helper = new SQLHelper();
        $helper->run_query($payload);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperRelevant := false
	liveRelevant := false
	importRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "SQLHelper::run_query") {
			helperRelevant = true
		}
		if strings.HasSuffix(key, "LiveController::handle_request") {
			liveRelevant = true
		}
		if strings.HasSuffix(key, "ImportController::replay") {
			importRelevant = true
		}
	}
	if !helperRelevant {
		t.Fatalf("SQLHelper::run_query should stay relevant")
	}
	if !liveRelevant {
		t.Fatalf("LiveController::handle_request should stay relevant")
	}
	if importRelevant {
		t.Fatalf("ImportController::replay should not be pulled in through reverse expansion when it is not request-reachable")
	}
}

func TestBuildEngineSkipsCrossRequestOptionWriterFallbackForSQLSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-cross-request-option-noise.php"), `<?php
class DB {
    public function get_col($sql) {}
}

class LiveSQL {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_sql', array($this, 'run'));
    }

    public function run() {
        $stored = get_option('demo_sort');
        if ($stored) {
            $noop = $stored;
        }
        $order = sanitize_sql_orderby($_GET['order']);
        $db = new DB();
        $db->get_col("SELECT ID FROM wp_users ORDER BY " . $order);
    }
}

class WriterNoise {
    public function __construct() {
        add_action('wp_ajax_nopriv_save_sort', array($this, 'save'));
    }

    public function save() {
        update_option('demo_sort', $_POST['value']);
    }
}

new LiveSQL();
new WriterNoise();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`method::\LiveSQL::run`]; !ok {
		t.Fatalf("LiveSQL::run should stay relevant for sql scans: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[`method::\WriterNoise::save`]; ok {
		t.Fatalf("cross-request option writer should not stay relevant for direct sql scans: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsUnreachableDirectFileBatchSinkSeeds(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "reachable-file-batch.php"), `<?php
class LiveFile {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_file', array($this, 'run'));
    }

    public function helper($path) {
        unlink($path);
    }

    public function run() {
        $this->helper($_GET['path']);
    }
}

class DeadFile {
    public function run() {
        unlink('/tmp/stale');
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{
			"delete":  {},
			"read":    {},
			"open":    {},
			"include": {},
		},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	liveHelperRelevant := false
	deadRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "LiveFile::helper") {
			liveHelperRelevant = true
		}
		if strings.HasSuffix(key, "DeadFile::run") {
			deadRelevant = true
		}
	}
	if !liveHelperRelevant {
		t.Fatalf("LiveFile::helper should stay relevant for request-reachable file batches")
	}
	if deadRelevant {
		t.Fatalf("DeadFile::run should not be seeded in the default multi-op file batch")
	}
}

func TestBuildEngineSkipsLiteralAndUnreachableIncludeSinkSeeds(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "reachable-include.php"), `<?php
class LiveInclude {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_include', array($this, 'run'));
    }

    public function helper($path) {
        require_once $path;
    }

    public function run() {
        $this->helper($_GET['path']);
    }
}

class StaticInclude {
    public function __construct() {
        add_action('wp_ajax_nopriv_static_include', array($this, 'run'));
    }

    public function run() {
        require_once SRFM_DIR . 'modules/gutenberg/classes/class-spec-block-config.php';
    }
}

class DeadInclude {
    public function run() {
        require_once $this->get_default_path();
    }

    private function get_default_path() {
        return '/tmp/stale.php';
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	liveHelperRelevant := false
	staticRelevant := false
	deadRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "LiveInclude::helper") {
			liveHelperRelevant = true
		}
		if strings.HasSuffix(key, "StaticInclude::run") {
			staticRelevant = true
		}
		if strings.HasSuffix(key, "DeadInclude::run") {
			deadRelevant = true
		}
	}
	if !liveHelperRelevant {
		t.Fatalf("LiveInclude::helper should stay relevant for request-reachable include scans")
	}
	if staticRelevant {
		t.Fatalf("StaticInclude::run should not be seeded by a definitely static include path")
	}
	if deadRelevant {
		t.Fatalf("DeadInclude::run should not be seeded when the include sink is unreachable from request flow")
	}
}

func TestBuildEngineRequestGatesDeleteSinkSeeds(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "reachable-delete.php"), `<?php
class LiveDelete {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_delete', array($this, 'run'));
    }

    public function helper($path) {
        unlink($path);
    }

    public function run() {
        $this->helper($_GET['path']);
    }
}

class DeadDelete {
    public function run() {
        unlink('/tmp/stale');
    }
}

class PublicDelete {
    public function __construct() {
        add_action('wp_ajax_nopriv_public_delete', array($this, 'run'));
    }

    public function run() {
        unlink('/tmp/stale');
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	liveHelperRelevant := false
	deadRelevant := false
	publicRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "LiveDelete::helper") {
			liveHelperRelevant = true
		}
		if strings.HasSuffix(key, "DeadDelete::run") {
			deadRelevant = true
		}
		if strings.HasSuffix(key, "PublicDelete::run") {
			publicRelevant = true
		}
	}
	if !liveHelperRelevant {
		t.Fatalf("LiveDelete::helper should stay relevant for request-reachable delete scans")
	}
	if deadRelevant {
		t.Fatalf("DeadDelete::run should not be seeded in request-gated delete scans")
	}
	if publicRelevant {
		t.Fatalf("PublicDelete::run should not be seeded by a public hook alone in delete scans")
	}
}

func TestBuildEngineSkipsDeleteOnlyReturnHelperUnusedByFileSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-return-helper.php"), `<?php
class LiveDeleteReturnHelper {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_delete_return_helper', array($this, 'run'));
    }

    private function normalize($path) {
        return $path;
    }

    public function run() {
        $path = $this->normalize($_GET['path']);
        unlink($path);
    }
}

class DeadDeleteReturnHelper {
    public function __construct() {
        add_action('wp_ajax_nopriv_dead_delete_return_helper', array($this, 'run'));
    }

    private function rewrite($value) {
        if (is_array($value)) {
            $out = array();
            foreach ($value as $key => $item) {
                $out[$key] = $this->rewrite($item);
            }
            return $out;
        }
        return $value;
    }

    public function run() {
        $edited = $this->rewrite($_GET['value']);
        $sql = "UPDATE demo SET payload = '" . $edited . "'";
        unlink($_GET['path']);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	liveRelevant := false
	deadRelevant := false
	deadChurnHelper := false
	deadDirectSink := false
	deadStorageWriter := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "LiveDeleteReturnHelper::normalize") {
			liveRelevant = true
		}
		if strings.HasSuffix(key, "DeadDeleteReturnHelper::rewrite") {
			deadRelevant = true
			deadChurnHelper = engine.callableLooksLikeDeleteReturnChurnHelper(key)
			deadDirectSink = engine.callableHasDirectSink(engine.callables[key])
			deadStorageWriter = engine.callableIsStorageWriter(key)
		}
	}
	if !liveRelevant {
		t.Fatalf("LiveDeleteReturnHelper::normalize should stay relevant for delete sink return flow")
	}
	if deadRelevant {
		t.Fatalf("DeadDeleteReturnHelper::rewrite should not stay relevant when its return is unused by file sinks (churn_helper=%v direct_sink=%v storage_writer=%v)", deadChurnHelper, deadDirectSink, deadStorageWriter)
	}
}

func TestBuildEngineSkipsUnreachableDirectWriteSinkSeeds(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "reachable-write.php"), `<?php
class LiveWrite {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_write', array($this, 'run'));
    }

    public function helper($tmp) {
        file_put_contents('/tmp/live.bin', $tmp);
    }

    public function run() {
        $this->helper($_FILES['file']['tmp_name']);
    }
}

class DeadWrite {
    public function run() {
        file_put_contents('/tmp/dead.bin', 'static');
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	liveHelperRelevant := false
	deadRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "LiveWrite::helper") {
			liveHelperRelevant = true
		}
		if strings.HasSuffix(key, "DeadWrite::run") {
			deadRelevant = true
		}
	}
	if !liveHelperRelevant {
		t.Fatalf("LiveWrite::helper should stay relevant for request-reachable write scans")
	}
	if deadRelevant {
		t.Fatalf("DeadWrite::run should not be seeded when the direct write sink is unreachable from request flow")
	}
}

func TestBuildEngineSkipsStorageWriterHelperForDirectWriteScans(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "write-storage-noise.php"), `<?php
class LiveWrite {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_write', array($this, 'run'));
    }

    public function save_meta($value) {
        update_option('demo_value', $value);
    }

    public function helper($tmp) {
        file_put_contents('/tmp/live.bin', $tmp);
    }

    public function run() {
        $this->save_meta($_GET['noise']);
        $this->helper($_FILES['file']['tmp_name']);
    }
}

new LiveWrite();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`method::\LiveWrite::helper`]; !ok {
		t.Fatalf("LiveWrite::helper should stay relevant for direct write scans: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[`method::\LiveWrite::save_meta`]; ok {
		t.Fatalf("storage-writer side helper should not stay relevant for direct write scans: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsPublicStaticWriteSinkSeedWithoutRequestData(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-static-write.php"), `<?php
class DemoWrite {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_write', array($this, 'run'));
    }

    public function run() {
        file_put_contents('/tmp/demo-static.bin', 'static');
    }
}

new DemoWrite();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\DemoWrite`, "run")
	if methodKey == "" {
		t.Fatal("missing DemoWrite::run")
	}
	if _, ok := engine.directPublicCallables[methodKey]; !ok {
		t.Fatalf("DemoWrite::run should still be marked direct public: %#v", engine.directPublicCallables)
	}
	if _, ok := engine.relevantCallables[methodKey]; ok {
		t.Fatalf("public static write sink without request data should not stay relevant in write-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsCapabilityCheckedWriteSinkSeed(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "cap-checked-write.php"), `<?php
class DemoWrite {
    public function __construct() {
        add_action('wp_ajax_demo_write', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('manage_options') ) {
            return;
        }
        file_put_contents('/tmp/demo-static.bin', $_POST['payload']);
    }
}

new DemoWrite();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\DemoWrite`, "run")
	if methodKey == "" {
		t.Fatal("missing DemoWrite::run")
	}
	if ctx := engine.contexts[methodKey]; ctx.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", ctx.Access)
	}
	if _, ok := engine.relevantCallables[methodKey]; ok {
		t.Fatalf("capability-checked write sink should not stay relevant in write-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineKeepsCapabilityCheckedWriteSinkSeedWhenEntrypointIsNoprivAjax(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "cap-checked-write-nopriv.php"), `<?php
class DemoWrite {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_write', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('manage_options') ) {
            return;
        }
        file_put_contents('/tmp/demo-static.bin', $_POST['payload']);
    }
}

new DemoWrite();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\DemoWrite`, "run")
	if methodKey == "" {
		t.Fatal("missing DemoWrite::run")
	}
	if ctx := engine.contexts[methodKey]; ctx.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", ctx.Access)
	}
	if _, ok := engine.relevantCallables[methodKey]; !ok {
		t.Fatalf("nopriv ajax write sink should stay relevant despite merged capability_checked context: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineReturnsEmptyRelevantOrderWhenSinkFamilyHasNoDirectSeeds(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "no-call-sinks.php"), `<?php
class PlainDemo {
    public function run() {
        $value = $_GET['x'];
        strlen($value);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if order := engine.relevantCallOrder(); len(order) != 0 {
		t.Fatalf("relevantCallOrder() = %d entries, want 0 when the sink family has no direct seeds", len(order))
	}
}

func TestAnalyzeRootPropagatesW3StyleDynamicAjaxContext(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "w3-style.php"), `<?php
namespace W3TC;

class Config {
    public function get_string($key) {
        return 'bunnycdn';
    }
}

class Dispatcher {
    public static function config() {
        return new Config();
    }
}

class Util_Request {
    public static function get_string($key) {}
}

class Generic_Plugin_Admin {
    public function __construct() {
        $this->_config = Dispatcher::config();
    }

    public function run() {
        add_action('wp_ajax_w3tc_ajax', array($this, 'wp_ajax_w3tc_ajax'));
    }

    public function wp_ajax_w3tc_ajax() {
        if (!wp_verify_nonce(Util_Request::get_string('_wpnonce'), 'w3tc')) {
            wp_nonce_ays('w3tc');
        }

        $base_capability = apply_filters('w3tc_ajax_base_capability_', 'manage_options');
        $capability = apply_filters('w3tc_ajax_capability_' . Util_Request::get_string('w3tc_action'), $base_capability);
        if (!empty($capability) && !current_user_can($capability)) {
            return;
        }

        do_action('w3tc_ajax');
        do_action('w3tc_ajax_' . Util_Request::get_string('w3tc_action'));
    }
}

class Cdn_Plugin_Admin {
    public function run() {
        $c = Dispatcher::config();
        $cdn_engine = $c->get_string('cdn.engine');
        switch ($cdn_engine) {
            case 'bunnycdn':
                add_action('w3tc_ajax', array('\W3TC\Cdn_BunnyCdn_Popup', 'w3tc_ajax'));
                break;
        }
    }
}

class Cdn_BunnyCdn_Popup {
    public static function w3tc_ajax() {
        $o = new Cdn_BunnyCdn_Popup();
        add_action('w3tc_ajax_cdn_bunnycdn_configure_pull_zone', array($o, 'w3tc_ajax_cdn_bunnycdn_configure_pull_zone'));
    }

    public function w3tc_ajax_cdn_bunnycdn_configure_pull_zone() {
        $origin_url = Util_Request::get_string('origin_url');
        update_option('demo_origin', $origin_url);
        wp_die();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
		if err != nil {
			t.Fatalf("BuildManifestForRoot(): %v", err)
		}
		files, err := loadFiles(manifest, 1)
		if err != nil {
			t.Fatalf("loadFiles(): %v", err)
		}
		engine, err := buildEngine(root, files, Options{
			AllowedSinkOps: map[string]struct{}{"action": {}},
		})
		if err != nil {
			t.Fatalf("buildEngine(): %v", err)
		}
		_ = engine
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsUltimateMemberMetaSQLSink2025(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/ultimate-member__2.9.1"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("ultimate-member 2.9.1 test target unavailable: %v", err)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}

	for _, finding := range result.Payload.Results {
		if finding.CheckID != "tainted-sql-string" {
			continue
		}
		if filepath.Base(finding.Path) != "class-member-directory-meta.php" {
			continue
		}
		if finding.Start.Line != 1072 {
			continue
		}
		if finding.Extra.Trace.Callable != `\um\core\Member_Directory_Meta::ajax_get_members` {
			t.Fatalf("callable = %q, want member-directory meta ajax_get_members", finding.Extra.Trace.Callable)
		}
		return
	}

	t.Fatalf("did not find ultimate-member 2.9.1 member-directory meta sql sink at class-member-directory-meta.php:1072; findings=%#v", result.Payload.Results)
}

func TestAnalyzeRootFindsUltimateMemberMetaSQLSink2024(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/ultimate-member__2.8.2"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("ultimate-member 2.8.2 test target unavailable: %v", err)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}

	for _, finding := range result.Payload.Results {
		if finding.CheckID != "tainted-sql-string" {
			continue
		}
		if filepath.Base(finding.Path) != "class-member-directory-meta.php" {
			continue
		}
		if finding.Start.Line != 859 {
			continue
		}
		if finding.Extra.Trace.Callable != `\um\core\Member_Directory_Meta::ajax_get_members` {
			t.Fatalf("callable = %q, want member-directory meta ajax_get_members", finding.Extra.Trace.Callable)
		}
		return
	}

	t.Fatalf("did not find ultimate-member 2.8.2 member-directory meta sql sink at class-member-directory-meta.php:859; findings=%#v", result.Payload.Results)
}

func TestAnalyzeRootFindsSureFormsStoredDeleteSink(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/sureforms__1.7.3"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("sureforms 1.7.3 test target unavailable: %v", err)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}

	validSources := map[int]struct{}{
		213: {},
		226: {},
	}
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-request-file-delete-without-cap-check" {
			continue
		}
		if filepath.Base(finding.Path) != "entries-list-table.php" {
			continue
		}
		if finding.Start.Line != 684 {
			continue
		}
		if finding.Extra.Trace.Callable != `\SRFM\Admin\Views\Entries_List_Table::delete_entry_files` {
			t.Fatalf("callable = %q, want delete_entry_files", finding.Extra.Trace.Callable)
		}
		if filepath.Base(finding.Extra.Trace.Source.Path) != "form-submit.php" {
			continue
		}
		if _, ok := validSources[finding.Extra.Trace.Source.Line]; !ok {
			t.Fatalf("unexpected sureforms source line %d; want one of 213 or 226", finding.Extra.Trace.Source.Line)
		}
		if len(finding.Extra.StoredWriteContext.EntryPoints) == 0 {
			t.Fatalf("sureforms stored write context entrypoints = 0, want at least 1")
		}
		foundSubmitRoute := false
		for _, entry := range finding.Extra.StoredWriteContext.EntryPoints {
			if strings.HasSuffix(entry.Route, "/submit-form") {
				foundSubmitRoute = true
				break
			}
		}
		if !foundSubmitRoute {
			t.Fatalf("sureforms stored write context missing submit-form route: %#v", finding.Extra.StoredWriteContext.EntryPoints)
		}
		if len(finding.Extra.StoredWriteContext.NonceChecks) == 0 {
			t.Fatalf("sureforms stored write nonce checks = 0, want at least 1")
		}
		return
	}

	t.Fatalf("did not find sureforms stored delete sink at entries-list-table.php:684 from form-submit.php; findings=%#v", result.Payload.Results)
}

func TestAnalyzeRootFindsTaintedSQLStringToQuery(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-query.php"), `<?php
class DB {
    public function query($query) {}
}

function demo($db) {
    $db->query("SELECT * FROM wp_users WHERE ID = " . $_GET['id']);
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootDoesNotFlagPreparedSQLString(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-prepare.php"), `<?php
class DB {
    public function prepare($query, ...$args) { return $query; }
    public function query($query) {}
}

function demo($db) {
    $query = $db->prepare("SELECT * FROM wp_users WHERE ID = %d", $_GET['id']);
    $db->query($query);
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsTaintedPreparedSQLTemplate(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-prepare-template.php"), `<?php
class DB {
    public function prepare($query, ...$args) { return $query; }
    public function query($query) {}
}

function demo($db) {
    $query = $db->prepare($_GET['sql'], 7);
    $db->query($query);
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 8 {
		t.Fatalf("sink line = %d, want 8", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsTaintedStaticPreparedSQLTemplate(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-static-prepare-template.php"), `<?php
class DB {
    public static function prepare($query, ...$args) { return $query; }
}

function demo() {
    DB::prepare($_GET['sql'], 7);
}

demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 7 {
		t.Fatalf("sink line = %d, want 7", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsTaintedWhereRawSQLTemplate(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-where-raw-template.php"), `<?php
class Builder {
    public function whereRaw($sql, ...$args) {}
}

function demo($builder) {
    $builder->whereRaw($_GET['clause']);
}

demo(new Builder());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 7 {
		t.Fatalf("sink line = %d, want 7", finding.Start.Line)
	}
}

func TestAnalyzeRootDoesNotFlagConstantWhereRawSQLTemplate(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-where-raw-safe.php"), `<?php
class Builder {
    public function whereRaw($sql, ...$args) {}
}

function demo($builder) {
    $builder->whereRaw("user_id = %d", $_GET['id']);
}

demo(new Builder());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsTaintedRawSQLConstructorTemplate(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-rawsql-constructor.php"), `<?php
class RawSQL {
    public function __construct($sql, ...$args) {}
}

function demo() {
    new RawSQL($_GET['clause']);
}

demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 7 {
		t.Fatalf("sink line = %d, want 7", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsTaintedDBInsertIdentifierKey(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-insert-identifier-key.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

function demo($db) {
    $postArr = $_POST;
    foreach ($postArr as $key => $val) {
        if ($key !== 'action') {
            $params[$key] = sanitize_text_field($val);
        }
    }
    $db->insert('entry_meta', $params);
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 13 {
		t.Fatalf("sink line = %d, want 13", finding.Start.Line)
	}
}

func TestAnalyzeRootDoesNotFlagWhitelistedDBInsertIdentifierKeys(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-insert-identifier-safe.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

function demo($db) {
    $allowed_keys = array('contact_name', 'contact_email', 'contact_phone', 'page_link');
    foreach ($allowed_keys as $key) {
        if (isset($_POST[$key])) {
            $params[$key] = sanitize_text_field($_POST[$key]);
        }
    }
    $db->insert('entry_meta', $params);
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootDoesNotFlagIntCastSQLString(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-int-cast.php"), `<?php
class DB {
    public function query($query) {}
}

function demo($db) {
    $db->query("SELECT * FROM wp_users WHERE ID = " . (int) $_GET['id']);
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsTaintedSQLStringToGetVar(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-get-var.php"), `<?php
class DB {
    public function get_var($query) {}
}

function demo($db) {
    return $db->get_var("SELECT meta_value FROM entry_meta WHERE entry_id = " . $_GET['id']);
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootFindsEscSQLOrderFragmentInPropertyBackedQuery(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-order-fragment.php"), `<?php
class WPDBLike {
    public function get_col($query) {}
}

class Directory {
    public $sql_order = '';

    public function run($db) {
        $sortby = esc_sql($_POST['sorting']);
        $this->sql_order = " ORDER BY u." . $sortby;
        $db->get_col("SELECT u.ID FROM wp_users AS u {$this->sql_order}");
    }
}

(new Directory())->run(new WPDBLike());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootFindsSanitizeSQLOrderbyFragmentInQuery(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-orderby-sanitize.php"), `<?php
class DB {
    public function get_results($query) {}
}

function demo($db) {
    $order = sanitize_sql_orderby($_GET['order']);
    $db->get_results("SELECT * FROM wp_users ORDER BY " . $order);
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootFindsImplodedSQLFragmentsInQuery(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-implode-fragments.php"), `<?php
class DB {
    public function get_col($query) {}
}

class Directory {
    public $where_clauses = array();

    public function build($db) {
        $this->where_clauses[] = "u.user_login LIKE '%" . esc_sql($_GET['search']) . "%'";
        $sql_where = implode(' AND ', $this->where_clauses);
        $db->get_col("SELECT u.ID FROM wp_users AS u WHERE 1=1 AND " . $sql_where);
    }
}

(new Directory())->build(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootFindsJoinAliasSQLFragmentsInQuery(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-join-fragments.php"), `<?php
class DB {
    public function get_results($query) {}
}

function demo($db) {
    $parts = array("ORDER BY " . sanitize_sql_orderby($_GET['order']));
    $db->get_results("SELECT * FROM wp_users " . join(' ', $parts));
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootFindsTaintedPostsOrderbyFilterFallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-posts-orderby-filter-fallback.php"), `<?php
class DemoQuery {
    public function boot() {
        add_filter('posts_orderby', array($this, 'redirect_posts_orderby'), 200, 2);
    }

    protected function parse_orderby($orderby) {
        return false;
    }

    public function redirect_posts_orderby($posts_orderby, $query) {
        $redirected_orderbys = '';
        $orderbys = explode(',', $posts_orderby);
        foreach ($orderbys as $orderby_frag) {
            $orderby = $orderby_frag;
            $parsed_orderby = $this->parse_orderby((string) $orderby) ?: $orderby;
            $redirected_orderbys .= $parsed_orderby;
        }
        return $redirected_orderbys;
    }
}

(new DemoQuery())->boot();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Extra.Context.EntryPoints[0].Name != "posts_orderby" {
		t.Fatalf("entrypoint hook = %q, want posts_orderby", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootFindsTaintedPostsOrderbyRandPassThrough(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-posts-orderby-filter-rand.php"), `<?php
class DemoQuery {
    public function boot() {
        add_filter('posts_orderby', array($this, 'redirect_posts_orderby'), 200, 2);
    }

    public function redirect_posts_orderby($posts_orderby, $query) {
        $redirected_orderbys = '';
        $orderbys = explode(',', $posts_orderby);
        foreach ($orderbys as $orderby_frag) {
            if (stripos($orderby_frag, 'rand') === 0) {
                $redirected_orderbys .= $orderby_frag;
                continue;
            }
        }
        return $redirected_orderbys;
    }
}

(new DemoQuery())->boot();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootDoesNotFlagConstantPostsOrderbyFilterReturn(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-posts-orderby-filter-safe.php"), `<?php
class DemoQuery {
    public function boot() {
        add_filter('posts_orderby', array($this, 'redirect_posts_orderby'), 200, 2);
    }

    public function redirect_posts_orderby($posts_orderby, $query) {
        return 'RAND() DESC';
    }
}

(new DemoQuery())->boot();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsTaintedPostsWhereFilterReturn(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-posts-where-filter.php"), `<?php
class DemoQuery {
    public function boot() {
        add_filter('posts_where', array($this, 'redirect_posts_where'), 10, 2);
    }

    public function redirect_posts_where($posts_where, $query) {
        $fragment = $_GET['where'];
        return $posts_where . ' AND ' . $fragment;
    }
}

(new DemoQuery())->boot();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Extra.Context.EntryPoints[0].Name != "posts_where" {
		t.Fatalf("entrypoint hook = %q, want posts_where", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootFindsTaintedGetMetaSQLFilterReturn(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-get-meta-sql-filter.php"), `<?php
class DemoQuery {
    public function boot() {
        add_filter('get_meta_sql', array($this, 'change_meta_sql'), 10, 6);
    }

    public function change_meta_sql($sql, $queries, $type, $primary_table, $primary_id_column, $context) {
        $search = sanitize_text_field($_POST['search']);
        $sql['where'] = $sql['where'] . " AND meta_value LIKE '%" . $search . "%'";
        return $sql;
    }
}

(new DemoQuery())->boot();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Extra.Context.EntryPoints[0].Name != "get_meta_sql" {
		t.Fatalf("entrypoint hook = %q, want get_meta_sql", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootFindsUltimateMemberStyleSortOrderQuery(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-ultimate-member-sort.php"), `<?php
class WPDBLike {
    public function prepare($query, ...$args) { return $query; }
    public function get_col($query) {}
    public $prefix = 'wp_';
    public $users = 'wp_users';
}

class MemberDirectoryMeta {
    public $joins = array();
    public $where_clauses = array();
    public $sql_order = '';
    public $sql_limit = '';
    public $select = '';
    public $having = '';
    public $core_users_fields = array('user_login', 'display_name');

    public function ajax_get_members($wpdb) {
        $order = 'ASC';
        $sortby = ! empty($_POST['sorting']) ? sanitize_text_field($_POST['sorting']) : 'user_login';
        if (in_array($sortby, $this->core_users_fields, true)) {
            $sortby = esc_sql($sortby);
            $order = esc_sql($order);
            $this->sql_order = " ORDER BY u.{$sortby} {$order} ";
        }
        $sql_select = esc_sql($this->select);
        $sql_having = esc_sql($this->having);
        $sql_join = implode(' ', $this->joins);
        $sql_where = implode(' AND ', $this->where_clauses);
        $sql_where = ! empty($sql_where) ? 'AND ' . $sql_where : '';
        $wpdb->get_col(
            "SELECT SQL_CALC_FOUND_ROWS DISTINCT u.ID
            {$sql_select}
            FROM {$wpdb->users} AS u
            {$sql_join}
            WHERE 1=1 {$sql_where}
            {$sql_having}
            {$this->sql_order}
            {$this->sql_limit}"
        );
    }
}

(new MemberDirectoryMeta())->ajax_get_members(new WPDBLike());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootFindsSubclassOverrideCallbackRegisteredFromParent(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "parent-registered-child-override.php"), `<?php
class WPDBLike {
    public function get_col($query) {}
}

class BaseDirectory {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_members', array($this, 'ajax_get_members'));
    }

    public function ajax_get_members() {
        echo 'base';
    }
}

class ChildDirectory extends BaseDirectory {
    public function ajax_get_members() {
        $wpdb = new WPDBLike();
        $sortby = ! empty($_POST['sorting']) ? sanitize_text_field($_POST['sorting']) : 'user_login';
        $sortby = esc_sql($sortby);
        $wpdb->get_col("SELECT u.ID FROM wp_users AS u ORDER BY u.{$sortby}");
    }
}

new ChildDirectory();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 21 {
		t.Fatalf("sink line = %d, want 21", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsCachedFactoryCallbackRegisteredThroughMethodReturn(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "cached-factory-callback.php"), `<?php
class WPDBLike {
    public function get_col($query) {}
}

class UM_Init {
    public $classes = array();

    public function member_directory() {
        if (empty($this->classes['member_directory'])) {
            if (get_option('member_directory_own_table')) {
                $this->classes['member_directory'] = new MemberDirectoryMeta();
            } else {
                $this->classes['member_directory'] = new MemberDirectory();
            }
        }
        return $this->classes['member_directory'];
    }
}

function UM() {
    static $um = null;
    if ($um === null) {
        $um = new UM_Init();
    }
    return $um;
}

class AJAX_Common {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_members', array(UM()->member_directory(), 'ajax_get_members'));
    }
}

class MemberDirectory {
    public function ajax_get_members() {
        echo 'base';
    }
}

class MemberDirectoryMeta extends MemberDirectory {
    public function ajax_get_members() {
        $wpdb = new WPDBLike();
        $sortby = ! empty($_POST['sorting']) ? sanitize_text_field($_POST['sorting']) : 'user_login';
        $sortby = esc_sql($sortby);
        $wpdb->get_col("SELECT u.ID FROM wp_users AS u ORDER BY u.{$sortby}");
    }
}

new AJAX_Common();
UM()->member_directory();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 46 {
		t.Fatalf("sink line = %d, want 46", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsCallbackRegisteredThroughStaticSingletonFactory(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static-singleton-callback.php"), `<?php
class WPDBLike {
    public function get_col($query) {}
}

class UM_Init {
    protected static $instance = null;
    public $classes = array();

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function member_directory() {
        if (empty($this->classes['member_directory'])) {
            if (get_option('member_directory_own_table')) {
                $this->classes['member_directory'] = new MemberDirectoryMeta();
            } else {
                $this->classes['member_directory'] = new MemberDirectory();
            }
        }
        return $this->classes['member_directory'];
    }
}

function UM() {
    return UM_Init::instance();
}

class AJAX_Common {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_members', array(UM()->member_directory(), 'ajax_get_members'));
    }
}

class MemberDirectory {
    public function ajax_get_members() {
        echo 'base';
    }
}

class MemberDirectoryMeta extends MemberDirectory {
    public function ajax_get_members() {
        $wpdb = new WPDBLike();
        $sortby = ! empty($_POST['sorting']) ? sanitize_text_field($_POST['sorting']) : 'user_login';
        $sortby = esc_sql($sortby);
        $wpdb->get_col("SELECT u.ID FROM wp_users AS u ORDER BY u.{$sortby}");
    }
}

new AJAX_Common();
UM()->member_directory();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Start.Line != 50 {
		t.Fatalf("sink line = %d, want 50", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsArrayIntersectKeyFilteredRequestQuery(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-array-intersect-key.php"), `<?php
class DB {
    public function query($query) {}
}

function demo($db) {
    $search_filters = array('nickname');
    $filter_query = array_intersect_key($_POST, array_flip($search_filters));
    foreach ($filter_query as $field => $value) {
        $db->query("SELECT * FROM wp_users WHERE " . $field . " = '" . $value . "'");
    }
}

demo(new DB());
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
}

func TestAnalyzeRootFindsPostSMTPDisclosureSink(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/post-smtp__3.6.0"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("post-smtp test target unavailable: %v", err)
	}

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	payload := engine.run()

	for _, finding := range payload.Results {
		if finding.CheckID != "wp-request-record-read-to-output-without-cap-check" {
			continue
		}
		if finding.Start.Line != 72 {
			continue
		}
		if filepath.Base(finding.Path) != "PostmanEmailLogs.php" {
			continue
		}
		return
	}
	constructorKey := `method::\PostmanEmailLogs::__construct`
	purifyKey := `method::\PostmanEmailLogs::purify_html`
	t.Fatalf(
		"did not find Post SMTP disclosure sink at PostmanEmailLogs.php:72; findings=%#v constructor_ctx=%+v constructor_summary=%+v purify_summary=%+v",
		payload.Results,
		engine.contexts[constructorKey],
		engine.summaries[constructorKey],
		engine.summaries[purifyKey],
	)
}

func TestAnalyzeCallablePostSMTPConstructorWithSeededPurifySummary(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/post-smtp__3.6.0"
	if _, err := os.Stat(root); err != nil {
		t.Skipf("post-smtp test target unavailable: %v", err)
	}

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	constructorKey := `method::\PostmanEmailLogs::__construct`
	purifyKey := `method::\PostmanEmailLogs::purify_html`
	engine.summaries[purifyKey] = summary{
		ReturnParams:         []int{0},
		ParamFindings:        map[int][]sinkTemplate{},
		StaticWrites:         map[string]taintSummary{},
		ReceiverWrites:       map[string]taintSummary{},
		ReceiverPathWrites:   map[string]taintSummary{},
		ReceiverStorageLinks: map[string]string{},
		StorageWrites:        map[string]taintSummary{},
		StoragePathWrites:    map[string]taintSummary{},
	}

	out := engine.analyzeCallable(engine.callables[constructorKey])
	if len(out.SourceFindings) == 0 {
		t.Fatalf("constructor analysis produced no source findings with seeded purify summary: %+v", out)
	}
}

func TestAnalyzeCallableSkipsNoOpSourceFindingPropagationFromCallee(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "demo.php"), `<?php
function sink_helper() {
    $path = $_GET['template'];
    require_once $path;
}

function wrapper() {
    sink_helper();
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"include": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := `function::\sink_helper`
	wrapperKey := `function::\wrapper`

	helperSummary := engine.analyzeCallable(engine.callables[helperKey])
	if len(helperSummary.SourceFindings) == 0 {
		t.Fatalf("helper summary produced no source findings: %+v", helperSummary)
	}
	engine.summaries[helperKey] = helperSummary

	wrapperSummary := engine.analyzeCallable(engine.callables[wrapperKey])
	if len(wrapperSummary.SourceFindings) != 0 {
		t.Fatalf("wrapper summary propagated no-op callee source findings: %+v", wrapperSummary.SourceFindings)
	}
}

func TestAnalyzeCallableSkipsNoOpStaticWritePropagationFromCallee(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static_wrapper.php"), `<?php
class StaticWrapDemo {
    public static $script = '';

    public function helper() {
        self::$script = $_GET['piece'];
    }

    public function wrapper() {
        $this->helper();
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := `method::\StaticWrapDemo::helper`
	wrapperKey := `method::\StaticWrapDemo::wrapper`

	helperSummary := engine.analyzeCallable(engine.callables[helperKey])
	if len(helperSummary.StaticWrites) == 0 {
		t.Fatalf("helper summary produced no static writes: %+v", helperSummary)
	}
	engine.summaries[helperKey] = helperSummary

	wrapperSummary := engine.analyzeCallable(engine.callables[wrapperKey])
	if len(wrapperSummary.StaticWrites) != 0 {
		t.Fatalf("wrapper summary propagated redundant source-based static writes: %+v", wrapperSummary.StaticWrites)
	}
}

func TestAnalyzeCallableKeepsParameterizedStaticWritePropagationFromCallee(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static_param_wrapper.php"), `<?php
class StaticParamWrapDemo {
    public static $script = '';

    public function helper($value) {
        self::$script = $value;
    }

    public function wrapper($value) {
        $this->helper($value);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := `method::\StaticParamWrapDemo::helper`
	wrapperKey := `method::\StaticParamWrapDemo::wrapper`

	helperSummary := engine.analyzeCallable(engine.callables[helperKey])
	if len(helperSummary.StaticWrites) == 0 {
		t.Fatalf("helper summary produced no static writes: %+v", helperSummary)
	}
	engine.summaries[helperKey] = helperSummary

	wrapperSummary := engine.analyzeCallable(engine.callables[wrapperKey])
	effect, ok := wrapperSummary.StaticWrites[`\StaticParamWrapDemo.$script`]
	if !ok {
		t.Fatalf("wrapper summary lost parameterized static write propagation: %+v", wrapperSummary.StaticWrites)
	}
	if len(effect.Params) != 1 || effect.Params[0] != 0 {
		t.Fatalf("wrapper static write params = %+v, want [0]", effect.Params)
	}
}

func TestAnalyzeCallableSkipsNoOpStorageWritePropagationFromCallee(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "storage_wrapper.php"), `<?php
function helper() {
    update_option('demo_value', $_GET['piece']);
}

function wrapper() {
    helper();
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := `function::\helper`
	wrapperKey := `function::\wrapper`

	helperSummary := engine.analyzeCallable(engine.callables[helperKey])
	if len(helperSummary.StorageWrites) == 0 && len(helperSummary.StoragePathWrites) == 0 {
		t.Fatalf("helper summary produced no storage writes: %+v", helperSummary)
	}
	engine.summaries[helperKey] = helperSummary

	wrapperSummary := engine.analyzeCallable(engine.callables[wrapperKey])
	if len(wrapperSummary.StorageWrites) != 0 || len(wrapperSummary.StoragePathWrites) != 0 {
		t.Fatalf("wrapper summary propagated redundant source-based storage writes: %+v %+v", wrapperSummary.StorageWrites, wrapperSummary.StoragePathWrites)
	}
}

func TestAnalyzeCallableKeepsParameterizedStorageWritePropagationFromCallee(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "storage_param_wrapper.php"), `<?php
function helper($value) {
    update_option('demo_value', $value);
}

function wrapper($value) {
    helper($value);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := `function::\helper`
	wrapperKey := `function::\wrapper`

	helperSummary := engine.analyzeCallable(engine.callables[helperKey])
	if len(helperSummary.StorageWrites) == 0 && len(helperSummary.StoragePathWrites) == 0 {
		t.Fatalf("helper summary produced no storage writes: %+v", helperSummary)
	}
	engine.summaries[helperKey] = helperSummary

	wrapperSummary := engine.analyzeCallable(engine.callables[wrapperKey])
	found := false
	for _, effect := range wrapperSummary.StorageWrites {
		if len(effect.Params) == 1 && effect.Params[0] == 0 {
			found = true
			break
		}
	}
	for _, effect := range wrapperSummary.StoragePathWrites {
		if len(effect.Params) == 1 && effect.Params[0] == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("wrapper summary lost parameterized storage write propagation: %+v %+v", wrapperSummary.StorageWrites, wrapperSummary.StoragePathWrites)
	}
}

func TestAnalyzeCallableCompactsOutputWriterContextOnlySummaries(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output_writer_context_only.php"), `<?php
class WriterDemo {
    public function persist() {
        update_option('demo_value', $_GET['piece']);
        $this->cache = get_option('shadow_value');
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"

	key := `method::\WriterDemo::persist`
	summary := engine.analyzeCallable(engine.callables[key])
	if len(summary.StorageWrites) == 0 && len(summary.StoragePathWrites) == 0 {
		t.Fatalf("writer summary produced no storage writes: %+v", summary)
	}
	if len(summary.ReceiverWrites) != 0 || len(summary.ReceiverPathWrites) != 0 || len(summary.ReceiverStorageLinks) != 0 {
		t.Fatalf("writer summary kept receiver state in output batch: %+v %+v %+v", summary.ReceiverWrites, summary.ReceiverPathWrites, summary.ReceiverStorageLinks)
	}
	if len(summary.ReturnSources) != 0 || len(summary.ReturnSourceOrigins) != 0 || len(summary.ReturnReceiverPaths) != 0 {
		t.Fatalf("writer summary kept return state in output batch: %+v %+v %+v", summary.ReturnSources, summary.ReturnSourceOrigins, summary.ReturnReceiverPaths)
	}
}

func TestBuildEngineForwardRelevanceSkipsStandaloneRenderHelpers(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "page.php"), `<?php
class Entry {
    public static function delete_by_entry($id) {
        $path = $_GET['template'];
        unlink($path);
    }
}

class Page {
    public function before_render() {
        $this->process_request();
        $this->entries_iterator();
    }

    private function process_request() {
        $entry_id = $this->get_entry_id();
        Entry::delete_by_entry($entry_id);
    }

    private function get_entry_id() {
        return 1;
    }

    private function entries_iterator() {
        $this->render_row();
    }

    private function render_row() {
        echo "row";
    }
}

(new Page())->before_render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::Page::entries_iterator"]; ok {
		t.Fatalf("entries_iterator should not stay relevant")
	}
	if _, ok := engine.relevantCallables["method::Page::render_row"]; ok {
		t.Fatalf("render_row should not stay relevant")
	}
}

func TestBuildEngineOpenRelevanceSkipsUnusedDataCarrierHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "open-unused.php"), `<?php
function helper_path() {
    return $_GET['path'];
}

function unused_wrapper() {
    helper_path();
}

function real_sink() {
    $path = '/tmp/static.txt';
    fopen($path, 'r');
}

real_sink();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"open": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`function::\unused_wrapper`]; ok {
		t.Fatalf("unused_wrapper should not stay relevant in open batch")
	}
	if _, ok := engine.relevantCallables[`function::\helper_path`]; ok {
		t.Fatalf("helper_path should not stay relevant in open batch when its return is unused")
	}
}

func TestBuildEngineOpenRelevanceKeepsUsedDataCarrierHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "open-used.php"), `<?php
function helper_path() {
    return $_GET['path'];
}

function real_sink() {
    $path = helper_path();
    fopen($path, 'r');
}

real_sink();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"open": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`function::\helper_path`]; !ok {
		t.Fatalf("helper_path should stay relevant in open batch when its return feeds fopen")
	}
}

func TestBuildEngineDeleteRelevanceSkipsUnrelatedDataCarrierHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-unrelated-data-helper.php"), `<?php
class Mailer {
    public function send($payload) {
        return $payload['email'];
    }
}

function delete_path($path) {
    unlink($path);
}

function run_demo() {
    $payload = array(
        'path' => $_POST['path'],
        'email' => $_POST['email'],
    );
    delete_path($payload['path']);
    $mailer = new Mailer();
    $mailer->send($payload);
}

run_demo();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`function::\delete_path`]; !ok {
		t.Fatalf("delete_path should stay relevant in delete batch")
	}
	if _, ok := engine.relevantCallables[`method::Mailer::send`]; ok {
		t.Fatalf("Mailer::send should not stay relevant in delete batch")
	}
}

func TestBuildEngineDeleteRelevanceKeepsIntermediateWrapper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-wrapper.php"), `<?php
function delete_path($path) {
    unlink($path);
}

function delete_wrapper($path) {
    delete_path($path);
}

function run_demo() {
    $path = $_POST['path'];
    delete_wrapper($path);
}

run_demo();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`function::\delete_wrapper`]; !ok {
		t.Fatalf("delete_wrapper should stay relevant in delete batch")
	}
}

func TestBuildEngineDeleteRelevanceSkipsHelpersAfterStorageWriterAnchor(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-storage-anchor.php"), `<?php
class Mailer {
    public function send($payload) {
        return $payload['email'];
    }
}

function store_path($path) {
    update_post_meta(1, 'file_path', $path);
}

function delete_saved_path() {
    $path = get_post_meta(1, 'file_path', true);
    unlink($path);
}

function handle_submit() {
    $payload = array(
        'path' => $_POST['path'],
        'email' => $_POST['email'],
    );
    store_path($payload['path']);
    $mailer = new Mailer();
    $mailer->send($payload);
}

handle_submit();
delete_saved_path();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`function::\store_path`]; !ok {
		t.Fatalf("store_path should stay relevant in delete batch")
	}
	if _, ok := engine.relevantCallables[`method::Mailer::send`]; ok {
		t.Fatalf("Mailer::send should not stay relevant after a storage-writer anchor in delete batch")
	}
}

func TestBuildEngineIndexesExactStaticPathReadersSeparately(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static-readers.php"), `<?php
class StaticReaderDemo {
    public static $prepared_data = array();

    public function read_file() {
        return self::$prepared_data['file']['path'];
    }

    public function read_text() {
        return self::$prepared_data['text'];
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	filePathKey := `\StaticReaderDemo.$prepared_data[file][path]`
	textPathKey := `\StaticReaderDemo.$prepared_data[text]`
	if readers := engine.staticPathReadersByExact[filePathKey]; len(readers) != 1 {
		t.Fatalf("exact readers for %s = %d, want 1", filePathKey, len(readers))
	}
	if readers := engine.staticPathReadersByExact[textPathKey]; len(readers) != 1 {
		t.Fatalf("exact readers for %s = %d, want 1", textPathKey, len(readers))
	}
	bucket := staticPathInvalidationBucket(filePathKey)
	if readers := engine.staticPathReadersByBucket[bucket]; len(readers) != 0 {
		t.Fatalf("bucket readers for %s = %d, want 0 exact-reader spillover", bucket, len(readers))
	}
}

func TestBuildEngineSkipsStaticSelfAccumulatorRootReaders(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static-accumulator.php"), `<?php
class SelfAccumulatorDemo {
    public static $script = '';

    public function append_piece() {
        self::$script .= helper_piece();
    }

    public function print_script() {
        return self::$script;
    }
}

function helper_piece() {
    return $_GET['piece'];
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	rootKey := `\SelfAccumulatorDemo.$script`
	readers := engine.staticBaseReadersByRoot[rootKey]
	if _, ok := readers[`method::\SelfAccumulatorDemo::append_piece`]; ok {
		t.Fatalf("compound self-accumulator should not be indexed as a root reader: %#v", readers)
	}
	if _, ok := readers[`method::\SelfAccumulatorDemo::print_script`]; !ok {
		t.Fatalf("true root reader missing from %#v", readers)
	}
}

func TestAnalyzeCallableStaticAccumulatorSummarySkipsGlobalTargetFeedback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static-accumulator-global.php"), `<?php
class StaticAccumulatorGlobalDemo {
    public static $script = '';

    public function append_piece() {
        self::$script .= $_GET['piece'];
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.staticProps[`\StaticAccumulatorGlobalDemo.$script`] = makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "seed.php", Line: 99},
	})

	summary := engine.analyzeCallable(engine.callables[`method::\StaticAccumulatorGlobalDemo::append_piece`])
	effect, ok := summary.StaticWrites[`\StaticAccumulatorGlobalDemo.$script`]
	if !ok {
		t.Fatalf("append_piece summary missing static write: %+v", summary.StaticWrites)
	}
	for _, loc := range effect.Sources {
		if loc.Path == "seed.php" && loc.Line == 99 {
			t.Fatalf("append_piece summary leaked global static target feedback: %+v", effect)
		}
	}
}

func TestAnalyzeCallableStaticAccumulatorKeepsEarlierLocalAppend(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static-accumulator-local.php"), `<?php
class StaticAccumulatorLocalDemo {
    public static $script = '';

    public function append_twice() {
        self::$script .= $_GET['first'];
        self::$script .= $_GET['second'];
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	summary := engine.analyzeCallable(engine.callables[`method::\StaticAccumulatorLocalDemo::append_twice`])
	effect, ok := summary.StaticWrites[`\StaticAccumulatorLocalDemo.$script`]
	if !ok {
		t.Fatalf("append_twice summary missing static write: %+v", summary.StaticWrites)
	}
	if len(effect.Sources) < 2 {
		t.Fatalf("append_twice summary lost earlier local append: %+v", effect)
	}
}

func TestAnalyzeRootMarksAjaxNoPrivAsUnauthenticated(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ajax.php"), `<?php
class AjaxDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_file', array($this, 'handle'));
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Name != "wp_ajax_nopriv_demo_file" {
		t.Fatalf("entrypoint hook = %q, want wp_ajax_nopriv_demo_file", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootMarksAjaxCapabilityAndNonceChecks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ajax.php"), `<?php
class AjaxGuardedDemo {
    public function __construct() {
        add_action('wp_ajax_demo_guarded', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo');
        if ( current_user_can('manage_options') ) {
            $path = $_GET['template'];
            require_once $path;
        }
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.CapabilityChecks) != 1 {
		t.Fatalf("capability checks = %d, want 1", len(finding.Extra.Context.CapabilityChecks))
	}
	if len(finding.Extra.Context.NonceChecks) != 1 {
		t.Fatalf("nonce checks = %d, want 1", len(finding.Extra.Context.NonceChecks))
	}
}

func TestAnalyzeRootDoesNotTreatBareCurrentUserCanAsGate(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ajax.php"), `<?php
class AjaxBareCapabilityDemo {
    public function __construct() {
        add_action('wp_ajax_demo_bare_cap', array($this, 'handle'));
    }

    public function handle() {
        current_user_can('manage_options');
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.CapabilityChecks) != 0 {
		t.Fatalf("capability checks = %d, want 0", len(finding.Extra.Context.CapabilityChecks))
	}
}

func TestAnalyzeRootMarksNegativeCapabilityGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "negative-capability.php"), `<?php
class NegativeCapabilityDemo {
    public function __construct() {
        add_action('wp_ajax_demo_negative_cap', array($this, 'handle'));
    }

    public function handle() {
        if ( ! current_user_can('manage_options') ) {
            wp_die('forbidden');
        }
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.CapabilityChecks) != 1 {
		t.Fatalf("capability checks = %d, want 1", len(finding.Extra.Context.CapabilityChecks))
	}
}

func TestAnalyzeRootMarksAuthenticatedAjaxNonceOnlyGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "nonce-only.php"), `<?php
class AjaxNonceOnlyDemo {
    public function __construct() {
        add_action('wp_ajax_demo_nonce_only', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo');
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.NonceChecks) != 1 {
		t.Fatalf("nonce checks = %d, want 1", len(finding.Extra.Context.NonceChecks))
	}
	if len(finding.Extra.Context.CapabilityChecks) != 0 {
		t.Fatalf("capability checks = %d, want 0", len(finding.Extra.Context.CapabilityChecks))
	}
}

func TestAnalyzeRootMarksNegativeNonceGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "negative-nonce.php"), `<?php
class NegativeNonceDemo {
    public function __construct() {
        add_action('wp_ajax_demo_negative_nonce', array($this, 'handle'));
    }

    public function handle() {
        if ( ! wp_verify_nonce($_REQUEST['nonce'], 'demo') ) {
            wp_die('bad nonce');
        }
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.NonceChecks) != 1 {
		t.Fatalf("nonce checks = %d, want 1", len(finding.Extra.Context.NonceChecks))
	}
}

func TestAnalyzeRootMarksStatementValidatorHelperAsNonceOnly(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "validator-helper.php"), `<?php
function demo_validate_nonce() {
    if ( ! wp_verify_nonce($_REQUEST['nonce'], 'demo') ) {
        wp_send_json_error('bad nonce');
    }
}

class ValidatorHelperDemo {
    public function __construct() {
        add_action('wp_ajax_demo_validator_helper', array($this, 'handle'));
    }

    public function handle() {
        demo_validate_nonce();
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.NonceChecks) != 1 {
		t.Fatalf("nonce checks = %d, want 1", len(finding.Extra.Context.NonceChecks))
	}
	if len(finding.Extra.Context.ValidationChecks) != 1 {
		t.Fatalf("validation checks = %d, want 1", len(finding.Extra.Context.ValidationChecks))
	}
}

func TestAnalyzeRootMarksStatementAuthHelperAsAuthenticated(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "auth-helper.php"), `<?php
function demo_require_login() {
    if ( ! is_user_logged_in() ) {
        wp_die('forbidden');
    }
}

class AuthHelperDemo {
    public function __construct() {
        add_action('wp_ajax_demo_auth_helper', array($this, 'handle'));
    }

    public function handle() {
        demo_require_login();
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) != 1 {
		t.Fatalf("auth checks = %d, want 1", len(finding.Extra.Context.AuthChecks))
	}
	if len(finding.Extra.Context.UnauthChecks) != 0 {
		t.Fatalf("unauth checks = %d, want 0", len(finding.Extra.Context.UnauthChecks))
	}
}

func TestAnalyzeRootMarksDieAuthHelperWithWeakCapabilityAsAuthenticated(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "helpers.php"), `<?php
function demo_user_can() {
    $cap = $GLOBALS['demo_cap'];
    if ( current_user_can($cap) ) {
        return true;
    }
    return false;
}

function demo_kill_invalid_user() {
    if ( $ok = demo_user_can() ) {
        return $ok;
    }
    die('forbidden');
}
`)
	writePHP(t, filepath.Join(root, "ajax.php"), `<?php
class WeakCapabilityStatementHelperDemo {
    public function __construct() {
        add_action('wp_ajax_demo_weak_cap_helper', array($this, 'handle'));
    }

    public function handle() {
        demo_kill_invalid_user();
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) == 0 {
		t.Fatalf("auth checks = %d, want >0", len(finding.Extra.Context.AuthChecks))
	}
	if len(finding.Extra.Context.CapabilityChecks) != 0 {
		t.Fatalf("capability checks = %d, want 0", len(finding.Extra.Context.CapabilityChecks))
	}
}

func TestAnalyzeRootMarksGetCurrentUserIDAuthGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "auth.php"), `<?php
class AuthGuardedDemo {
    public function __construct() {
        add_action('wp_ajax_demo_auth_guard', array($this, 'handle'));
    }

    public function handle() {
        if ( get_current_user_id() ) {
            $path = $_GET['template'];
            require_once $path;
        }
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) != 1 {
		t.Fatalf("auth checks = %d, want 1", len(finding.Extra.Context.AuthChecks))
	}
}

func TestAnalyzeRootMarksAdminAndAjaxGuards(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "admin-ajax.php"), `<?php
class AdminAjaxDemo {
    public function __construct() {
        add_action('wp_ajax_demo_admin_ajax', array($this, 'handle'));
    }

    public function handle() {
        if ( is_admin() && wp_doing_ajax() ) {
            $path = $_GET['template'];
            require_once $path;
        }
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if len(finding.Extra.Context.AdminChecks) != 1 {
		t.Fatalf("admin checks = %d, want 1", len(finding.Extra.Context.AdminChecks))
	}
	if len(finding.Extra.Context.AjaxChecks) != 1 {
		t.Fatalf("ajax checks = %d, want 1", len(finding.Extra.Context.AjaxChecks))
	}
}

func TestAnalyzeRootMarksMethodWrappedCapabilityGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "method-wrapper.php"), `<?php
class WrappedCapabilityDemo {
    public function __construct() {
        add_action('wp_ajax_demo_method_wrapper', array($this, 'handle'));
    }

    private function allowed() {
        return current_user_can('manage_options');
    }

    public function handle() {
        if ( $this->allowed() ) {
            $path = $_GET['template'];
            require_once $path;
        }
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.CapabilityChecks) != 1 {
		t.Fatalf("capability checks = %d, want 1", len(finding.Extra.Context.CapabilityChecks))
	}
}

func TestAnalyzeRootMarksFunctionWrappedAuthGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "function-wrapper.php"), `<?php
function demo_is_logged_in() {
    return is_user_logged_in();
}

function demo_handle_wrapper() {
    if ( demo_is_logged_in() ) {
        $path = $_GET['template'];
        require_once $path;
    }
}

add_action('wp_ajax_demo_function_wrapper', 'demo_handle_wrapper');
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) != 1 {
		t.Fatalf("auth checks = %d, want 1", len(finding.Extra.Context.AuthChecks))
	}
}

func TestAnalyzeRootSuppressesActionFindingForFilteredCapabilityWrapper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "filtered-cap-wrapper.php"), `<?php
class AccessDemo {
    public function current_user_can($caps = [], $id = 0) {
        return current_user_can('manage_options');
    }
}

function demo_current_user_can($caps = [], $id = 0) {
    $access = new AccessDemo();
    $user_can = $access->current_user_can($caps, $id);
    return apply_filters('demo_current_user_can', $user_can, $caps, $id);
}

function demo_save_settings() {
    if ( ! demo_current_user_can('edit_forms') ) {
        return;
    }
    update_option('demo_settings', sanitize_text_field($_POST['value']));
}

add_action('wp_ajax_demo_save_settings', 'demo_save_settings');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootSuppressesActionFindingForFilteredCapabilityVariable(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "filtered-capability-variable.php"), `<?php
function demo_save_settings() {
    $capability = apply_filters('demo_capability_save', 'manage_options');
    if ( ! current_user_can($capability) ) {
        return;
    }
    update_option('demo_settings', sanitize_text_field($_POST['value']));
}

add_action('wp_ajax_demo_save_settings', 'demo_save_settings');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootMarksLoggedOutGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "logged-out.php"), `<?php
if ( ! is_user_logged_in() ) {
    $path = $_GET['template'];
    require_once $path;
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.UnauthChecks) != 1 {
		t.Fatalf("unauth checks = %d, want 1", len(finding.Extra.Context.UnauthChecks))
	}
}

func TestAnalyzeRootMarksRestPermissionCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest.php"), `<?php
class RestDemo {
    public function __construct() {
        register_rest_route('demo/v1', '/file', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle'),
            'permission_callback' => '__return_true',
        ));
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Kind != "rest" {
		t.Fatalf("entrypoint kind = %q, want rest", finding.Extra.Context.EntryPoints[0].Kind)
	}
	if finding.Extra.Context.EntryPoints[0].Route != "/demo/v1/file" {
		t.Fatalf("entrypoint route = %q, want /demo/v1/file", finding.Extra.Context.EntryPoints[0].Route)
	}
}

func TestAnalyzeRootMarksRestPermissionCallbackCapabilityGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-cap.php"), `<?php
class RestDemo {
    public function __construct() {
        register_rest_route('demo/v1', '/file', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle'),
            'permission_callback' => array($this, 'allowed'),
        ));
    }

    public function allowed() {
        return current_user_can('manage_options');
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.CapabilityChecks) != 1 {
		t.Fatalf("capability checks = %d, want 1", len(finding.Extra.Context.CapabilityChecks))
	}
}

func TestAnalyzeRootMarksRestPermissionCallbackAuthGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-auth.php"), `<?php
class RestDemo {
    public function __construct() {
        register_rest_route('demo/v1', '/file', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle'),
            'permission_callback' => array($this, 'allowed'),
        ));
    }

    public function allowed() {
        return is_user_logged_in();
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) != 1 {
		t.Fatalf("auth checks = %d, want 1", len(finding.Extra.Context.AuthChecks))
	}
}

func TestAnalyzeRootMarksRestPermissionCallbackHashEqualsAuthGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-auth-hash-equals.php"), `<?php
class WP_REST_Request {
    public function get_header($key) {
        return 'Bearer signed-token';
    }
}

class RestDemo {
    private $secret = 'signed-token';

    public function __construct() {
        register_rest_route('demo/v1', '/file', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle'),
            'permission_callback' => array($this, 'allowed'),
        ));
    }

    public function allowed($request) {
        $token = $request->get_header('X-Demo-Auth');
        return hash_equals($this->secret, $token);
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) != 1 {
		t.Fatalf("auth checks = %d, want 1", len(finding.Extra.Context.AuthChecks))
	}
}

func TestAnalyzeRootMarksRestPermissionCallbackNegativeHashEqualsAuthGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-auth-negative-hash-equals.php"), `<?php
class WP_REST_Request {
    public function get_header($key) {
        return 'Bearer signed-token';
    }
}

class RestDemo {
    private $secret = 'signed-token';

    public function __construct() {
        register_rest_route('demo/v1', '/file', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle'),
            'permission_callback' => array($this, 'allowed'),
        ));
    }

    public function allowed($request) {
        $token = $request->get_header('X-Demo-Auth');
        if (empty($token) || empty($this->secret) || !hash_equals($this->secret, $token)) {
            return false;
        }
        return true;
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) != 1 {
		t.Fatalf("auth checks = %d, want 1", len(finding.Extra.Context.AuthChecks))
	}
}

func TestAnalyzeRootDoesNotMarkRestPermissionCallbackHashEqualsWithPublicSeedAsAuthenticated(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-auth-public-seed.php"), `<?php
define('DEMO_BASE_FILE', __FILE__);

class WP_REST_Request {
    public function get_json_params() {
        return array('signature' => $_GET['signature']);
    }
}

class Auth {
    private $secret_key;

    public function __construct($secret_key = '') {
        if (!empty($secret_key)) {
            $this->secret_key = hash('sha256', $secret_key);
        }
    }

    public function get_secret_key() {
        return $this->secret_key;
    }

    public function generate_token($data, $secret_key) {
        return hash_hmac('sha256', $data, $secret_key);
    }
}

class RestDemo {
    public function __construct() {
        register_rest_route('demo/v1', '/file', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle'),
            'permission_callback' => array($this, 'allowed'),
        ));
    }

    public function allowed($request) {
        $body = $request->get_json_params();
        $auth = new Auth(DEMO_BASE_FILE);
        $secret_key = $auth->get_secret_key();
        $expected_signature = $auth->generate_token('demo', $secret_key);
        return hash_equals($expected_signature, $body['signature']);
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access == "authenticated" {
		t.Fatalf("access = %q, want non-authenticated permission callback", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) != 0 {
		t.Fatalf("auth checks = %d, want 0", len(finding.Extra.Context.AuthChecks))
	}
}

func TestAnalyzeRootMarksRestPermissionCallbackHashEqualsWithMixedSecretAndPublicSeedAsAuthenticated(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-auth-mixed-seed.php"), `<?php
define('NONCE_SALT', 'super-secret');

class WP_REST_Request {
    public function get_json_params() {
        return array('signature' => $_GET['signature']);
    }
}

class RestDemo {
    public function __construct() {
        register_rest_route('demo/v1', '/file', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle'),
            'permission_callback' => array($this, 'allowed'),
        ));
    }

    public function allowed($request) {
        $body = $request->get_json_params();
        $expected_signature = hash_hmac('sha256', 'demo', NONCE_SALT . __FILE__);
        return hash_equals($expected_signature, $body['signature']);
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.AuthChecks) != 1 {
		t.Fatalf("auth checks = %d, want 1", len(finding.Extra.Context.AuthChecks))
	}
}

func TestAnalyzeRootFindsSecretDerivedPublicRestRoute(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-surface.php"), `<?php
class Core {
    public function get_option($key) {
        return 'secret';
    }
}

class RestDemo {
    private $core;
    private $token;

    public function __construct() {
        $this->core = new Core();
        add_action('rest_api_init', array($this, 'rest_api_init'));
    }

    public function rest_api_init() {
        $this->token = $this->core->get_option('demo_bearer_token');
        register_rest_route('demo/v1', '/' . $this->token . '/messages', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle'),
            'permission_callback' => '__return_true',
        ));
    }

    public function handle() {
        return true;
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-rest-public-data-disclosure-surface" {
		t.Fatalf("check_id = %q, want wp-rest-public-data-disclosure-surface", finding.CheckID)
	}
	if !strings.Contains(strings.ToLower(finding.Extra.Trace.Source.Snippet), "get_option('demo_bearer_token')") {
		t.Fatalf("source snippet = %q, want get_option('demo_bearer_token')", finding.Extra.Trace.Source.Snippet)
	}
	if !strings.Contains(strings.ToLower(finding.Extra.Trace.Sink.Snippet), "register_rest_route") {
		t.Fatalf("sink snippet = %q, want register_rest_route", finding.Extra.Trace.Sink.Snippet)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 || finding.Extra.Context.EntryPoints[0].Kind != "rest_init" {
		t.Fatalf("entrypoints = %#v, want single rest_init entrypoint", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootSkipsHiddenSecretRestRoute(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-hidden.php"), `<?php
class Core {
    public function get_option($key) {
        return 'secret';
    }
}

class RestDemo {
    private $core;
    private $token;

    public function __construct() {
        $this->core = new Core();
        add_action('rest_api_init', array($this, 'rest_api_init'));
    }

    public function rest_api_init() {
        $this->token = $this->core->get_option('demo_bearer_token');
        register_rest_route('demo/v1', '/' . $this->token . '/messages', array(
            'methods' => 'POST',
            'show_in_index' => false,
            'callback' => array($this, 'handle'),
            'permission_callback' => '__return_true',
        ));
    }

    public function handle() {
        return true;
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootSkipsNonSecretDynamicRestRoute(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-nonsecret.php"), `<?php
class Core {
    public function get_option($key) {
        return 'value';
    }
}

class RestDemo {
    private $core;
    private $version;

    public function __construct() {
        $this->core = new Core();
        add_action('rest_api_init', array($this, 'rest_api_init'));
    }

    public function rest_api_init() {
        $this->version = $this->core->get_option('api_version');
        register_rest_route('demo/v1', '/' . $this->version . '/messages', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle'),
            'permission_callback' => '__return_true',
        ));
    }

    public function handle() {
        return true;
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsPublicRestTokenIssuanceSurface(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-token-surface.php"), `<?php
class WP_REST_Request {
    public function get_param($key) {
        return array(1, 2);
    }
}

class TokenFactory {
    public static function make() {
        return new Token();
    }
}

class Token {
    public function create($publicKey, $formIds = array()) {
        return implode(':', $formIds);
    }
}

class KeyFactory {
    public static function make($length) {
        return 'public';
    }
}

class RestDemo {
    public function __construct() {
        add_action('rest_api_init', array($this, 'rest_api_init'));
    }

    public function rest_api_init() {
        register_rest_route('demo/v1', 'token/refresh', array(
            'methods' => 'POST',
            'callback' => array($this, 'refresh'),
            'permission_callback' => '__return_true',
        ));
    }

    public function refresh($request) {
        $formIds = $request->get_param('formIds');
        $tokenGenerator = TokenFactory::make();
        $publicKey = KeyFactory::make(32);
        $newToken = $tokenGenerator->create($publicKey, $formIds);
        return array(
            'token' => $newToken,
            'formIds' => $formIds,
        );
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-rest-token-issuance-surface" {
		t.Fatalf("check_id = %q, want wp-rest-token-issuance-surface", finding.CheckID)
	}
	if !strings.Contains(strings.ToLower(finding.Extra.Trace.Source.Snippet), "get_param('formids')") {
		t.Fatalf("source snippet = %q, want get_param('formIds')", finding.Extra.Trace.Source.Snippet)
	}
	if !strings.Contains(strings.ToLower(finding.Extra.Trace.Sink.Snippet), "'token' => $newtoken") {
		t.Fatalf("sink snippet = %q, want token response item", finding.Extra.Trace.Sink.Snippet)
	}
	if len(finding.Extra.Context.EntryPoints) == 0 || finding.Extra.Context.EntryPoints[0].Kind != "rest" {
		t.Fatalf("entrypoints = %#v, want rest callback context", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootSkipsPublicRestTokenIssuanceAfterTokenValidationGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-token-surface-safe.php"), `<?php
class WP_REST_Request {
    public function get_param($key) {
        return 7;
    }
    public function get_header($key) {
        return 'signed-token';
    }
}

class TokenFactory {
    public static function make() {
        return new Token();
    }
}

class Token {
    public function create($publicKey, $formIds = array()) {
        return implode(':', $formIds);
    }
    public function validateSignatureOnly($token) {
        return $token === 'signed-token';
    }
}

class KeyFactory {
    public static function make($length) {
        return 'public';
    }
}

class RestDemo {
    public function __construct() {
        add_action('rest_api_init', array($this, 'rest_api_init'));
    }

    public function rest_api_init() {
        register_rest_route('demo/v1', 'token/refresh', array(
            'methods' => 'POST',
            'callback' => array($this, 'refresh'),
            'permission_callback' => '__return_true',
        ));
    }

    public function refresh($request) {
        $tokenValidator = TokenFactory::make();
        $oldToken = $request->get_header('X-Demo-Auth');
        if (!$tokenValidator->validateSignatureOnly($oldToken)) {
            return false;
        }
        $formId = $request->get_param('formID');
        $publicKey = KeyFactory::make(32);
        $tokenGenerator = TokenFactory::make();
        $newToken = $tokenGenerator->create($publicKey, array($formId));
        return array(
            'token' => $newToken,
            'formID' => $formId,
        );
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsIssuedAuthLinkSurface(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "auth-link-surface.php"), `<?php
class DemoSocial {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_social', array($this, 'ajax_handler'));
        add_action('init', array($this, 'google_log_user_in'));
    }

    public function ajax_handler() {
        $token = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_STRING);
        $provider = 'gid-' . $token;
        $unique_login_url = $this->create_login_link($provider);
        $login = array(
            'login_url' => $unique_login_url,
        );
        wp_send_json_success($login);
    }

    private function create_login_link($provider) {
        $site = site_url();
        return $site . '?demo-social-login=' . $provider;
    }

    public function google_log_user_in() {
        if ( empty($_GET['demo-social-login']) ) {
            return;
        }
        $provider = sanitize_text_field($_GET['demo-social-login']);
        $user_id = 7;
        wp_set_auth_cookie($user_id);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	ajaxKey := engine.lookupMethodKey(`\DemoSocial`, "ajax_handler")
	if ajaxKey == "" {
		t.Fatalf("missing ajax_handler method key")
	}
	issueOK := false
	walkCallableExecutableNodes(engine.callables[ajaxKey], func(node ast.Node) {
		call, ok := node.(*ast.ExprFuncCall)
		if !ok || normalizeName(identifierText(call.Name)) != "wp_send_json_success" || len(call.Args) == 0 {
			return
		}
		if issue, ok := authLinkSurfaceIssueForPayload(argValue(call.Args[0]), engine.callables[ajaxKey], engine, newLocalArrayLiteralResolver(engine.callables[ajaxKey]), call.StartLine()); ok {
			issueOK = issue.QueryKey == "demo-social-login"
		}
	})
	if !issueOK {
		t.Fatalf("did not recover demo-social-login issue payload from ajax_handler")
	}
	if !engine.callableHasIssuedAuthLinkSurfaceSink(engine.callables[ajaxKey]) {
		t.Fatalf("ajax_handler not marked as issued auth-link surface sink")
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-issued-auth-link-surface" {
		t.Fatalf("check_id = %q, want wp-issued-auth-link-surface", finding.CheckID)
	}
	if !strings.Contains(strings.ToLower(finding.Extra.Trace.Source.Snippet), "'login_url' => $unique_login_url") {
		t.Fatalf("source snippet = %q, want login_url response item", finding.Extra.Trace.Source.Snippet)
	}
	if !strings.Contains(strings.ToLower(finding.Extra.Trace.Sink.Snippet), "wp_set_auth_cookie($user_id)") {
		t.Fatalf("sink snippet = %q, want auth cookie sink", finding.Extra.Trace.Sink.Snippet)
	}
}

func TestAnalyzeRootSkipsIssuedAuthLinkSurfaceWhenLoginHappensInline(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "auth-link-surface-safe.php"), `<?php
class DemoSocial {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_social', array($this, 'ajax_handler'));
    }

    public function ajax_handler() {
        $token = filter_input(INPUT_POST, 'token', FILTER_SANITIZE_STRING);
        $user_id = 7;
        wp_set_auth_cookie($user_id);
        $login = array(
            'siteURL' => site_url(),
            'redirectUrl' => site_url(),
        );
        wp_send_json_success($login);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsWPFluentPolicyFallbackRouteAction(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "routes.php"), `<?php
$router->prefix('roles')->withPolicy('RoleManagerPolicy')->group(function ($router) {
    $router->get('/', 'RolesController@index');
    $router->post('/', 'RolesController@addCapability');
});
`)
	writePHP(t, filepath.Join(root, "Policies.php"), `<?php
namespace Demo\App\Http\Policies;

class Policy {
    public function __returnTrue() {
        return true;
    }
}

class RoleManagerPolicy extends Policy {
    public function index() {
        return current_user_can('manage_options');
    }
}
`)
	writePHP(t, filepath.Join(root, "Controllers.php"), `<?php
namespace Demo\App\Http\Controllers;

class RolesController {
    public function index() {
        return array();
    }

    public function addCapability() {
        update_option('_demo_permission', $_REQUEST['capability'], 'no');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		manifest, manifestErr := parsetree.BuildManifestForRoot(root, nil, 1)
		if manifestErr != nil {
			t.Fatalf("findings = %d, want 1 (manifest err: %v)", len(result.Payload.Results), manifestErr)
		}
		files, loadErr := loadFiles(manifest, 1)
		if loadErr != nil {
			t.Fatalf("findings = %d, want 1 (load err: %v)", len(result.Payload.Results), loadErr)
		}
		engine, buildErr := buildEngine(root, files, Options{
			AllowedSinkOps: map[string]struct{}{"action": {}},
		})
		if buildErr != nil {
			t.Fatalf("findings = %d, want 1 (build err: %v)", len(result.Payload.Results), buildErr)
		}
		controllerKey := engine.lookupMethodKey(`\Demo\App\Http\Controllers\ManagersController`, "addmanager")
		serviceKey := engine.lookupMethodKey(`\Demo\App\Services\Manager\ManagerService`, "addmanager")
		var controllerParams map[string]string
		var controllerEdges map[string]struct{}
		var serviceEntry []EntryPoint
		resolvedClass := ""
		resolvedCandidates := []string(nil)
		specializedKey := ""
		if controller, ok := engine.callables[controllerKey]; ok {
			controllerParams = controller.ParamTypes
			controllerEdges = engine.callEdges[controllerKey]
			walkNodes(controller.Stmts, func(node ast.Node) {
				if resolvedClass != "" {
					return
				}
				call, ok := node.(*ast.ExprMethodCall)
				if !ok || strings.ToLower(identifierText(call.Name)) != "addmanager" {
					return
				}
				resolvedClass = resolveCallGraphClassExpr(engine, controller, call.Var, nil)
				resolvedCandidates = resolveCallGraphClassExprCandidates(engine, controller, call.Var, nil)
				specializedKey = engine.maybeSpecializeRuntimeMethodKeyForLiteralArgs(
					resolvedClass,
					strings.ToLower(identifierText(call.Name)),
					literalArgHintsForArgs(call.Args, controller, engine),
				)
			})
		}
		if serviceKey != "" {
			serviceEntry = engine.contexts[serviceKey].EntryPoints
		}
		t.Fatalf("findings = %d, want 1; controllerKey=%q serviceKey=%q controllerParams=%#v controllerEdges=%#v resolvedClass=%q resolvedCandidates=%#v specializedKey=%q serviceEntry=%#v results=%#v", len(result.Payload.Results), controllerKey, serviceKey, controllerParams, controllerEdges, resolvedClass, resolvedCandidates, specializedKey, serviceEntry, result.Payload.Results)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 10 {
		t.Fatalf("sink line = %d, want 10", finding.Start.Line)
	}
	if len(finding.Extra.Context.EntryPoints) == 0 {
		t.Fatalf("entrypoints = %#v, want rest entrypoint", finding.Extra.Context.EntryPoints)
	}
	foundRest := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Kind == "rest" && entry.Access == "unauthenticated" && entry.Route == "/roles" && entry.Methods == "POST" {
			foundRest = true
		}
	}
	if !foundRest {
		t.Fatalf("entrypoints = %#v, want unauthenticated POST /roles rest entrypoint", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootSkipsWPFluentRouteActionAfterVerifyRequestGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "routes.php"), `<?php
$router->prefix('roles')->withPolicy('RoleManagerPolicy')->group(function ($router) {
    $router->get('/', 'RolesController@index');
    $router->post('/', 'RolesController@addCapability');
});
`)
	writePHP(t, filepath.Join(root, "Policies.php"), `<?php
namespace Demo\App\Http\Policies;

class Policy {
    public function __returnTrue() {
        return true;
    }
}

class RoleManagerPolicy extends Policy {
    public function verifyRequest($request) {
        return current_user_can('manage_options');
    }

    public function index() {
        return current_user_can('manage_options');
    }
}
`)
	writePHP(t, filepath.Join(root, "Controllers.php"), `<?php
namespace Demo\App\Http\Controllers;

class RolesController {
    public function index() {
        return array();
    }

    public function addCapability() {
        update_option('_demo_permission', $_REQUEST['capability'], 'no');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsWPFluentPolicyFallbackPrivilegeMutationThroughTypedServiceParam(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "routes.php"), `<?php
$router->prefix('managers')->withPolicy('RoleManagerPolicy')->group(function ($router) {
    $router->post('/', 'ManagersController@addManager');
});
`)
	writePHP(t, filepath.Join(root, "Foundation.php"), `<?php
namespace Demo\Framework\Foundation;

abstract class Policy {
    public function __returnTrue() {
        return true;
    }
}
`)
	writePHP(t, filepath.Join(root, "Policies.php"), `<?php
namespace Demo\App\Http\Policies;

use Demo\Framework\Foundation\Policy;

class RoleManagerPolicy extends Policy {
    public function index() {
        return current_user_can('manage_options');
    }
}
`)
	writePHP(t, filepath.Join(root, "Controllers.php"), `<?php
namespace Demo\App\Http\Controllers;

use Demo\App\Services\Manager\ManagerService;

class ManagersController {
    public function addManager(ManagerService $managerService) {
        $managerService->addManager($_REQUEST);
    }
}
`)
	writePHP(t, filepath.Join(root, "Service.php"), `<?php
namespace Demo\App\Services\Manager;

class ManagerService {
    public function addManager($attributes = []) {
        $user = new \WP_User(7);
        $user->set_role($_REQUEST['role']);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-tainted-privilege-mutation" {
		t.Fatalf("check_id = %q, want wp-request-tainted-privilege-mutation", finding.CheckID)
	}
	if finding.Start.Line != 7 {
		t.Fatalf("sink line = %d, want 7", finding.Start.Line)
	}
	foundRest := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Kind == "rest" && entry.Access == "unauthenticated" && entry.Route == "/managers" && entry.Methods == "POST" {
			foundRest = true
		}
	}
	if !foundRest {
		t.Fatalf("entrypoints = %#v, want unauthenticated POST /managers rest entrypoint", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootTreatsRequestHolderAllAsRequestSource(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "request-all.php"), `<?php
class Request {
    public function all() {
        return $_REQUEST;
    }
}

class DemoController {
    protected $request;

    public function __construct() {
        $this->request = $GLOBALS['request'];
    }

    public function save() {
        update_option('_demo_permission', $this->request->all(), 'no');
    }
}

$GLOBALS['request'] = new Request();
$demo = new DemoController();
$demo->save();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 16 {
		t.Fatalf("sink line = %d, want 16", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsPublicOAuthCallbackAuthSurface(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "oauth-callback-surface.php"), `<?php
function add_action($hook, $callback) {}

class Sanitizer {
    public static function sanitize($source, $key, $filter) {
        return filter_input($source, $key, $filter);
    }
}

class DemoSocial {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_login_callback', array($this, 'loginCallback'));
    }

    public function loginCallback() {
        $provider = Sanitizer::sanitize(INPUT_GET, 'provider', FILTER_SANITIZE_STRING);
        if ($provider === 'wordpress') {
            $this->wordpressLoginCallback();
        }
    }

    private function wordpressLoginCallback() {
        $code = Sanitizer::sanitize(INPUT_GET, 'code', FILTER_SANITIZE_STRING);
        if (!$code) {
            return;
        }
        $this->setCurrentUser(7);
    }

    private function setCurrentUser($userID) {
        wp_set_auth_cookie($userID);
    }
}

new DemoSocial();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	loginKey := engine.lookupMethodKey(`\DemoSocial`, "loginCallback")
	if loginKey == "" {
		t.Fatalf("missing loginCallback method key")
	}
	if len(engine.directEntryPointsByCallable[loginKey]) == 0 {
		t.Fatalf("loginCallback missing direct entrypoint context")
	}
	state := &analysisState{
		engine:  engine,
		current: engine.callables[loginKey],
	}
	if sourceNode, ok := oauthCallbackRequestSourceNode(engine.callables[loginKey], 0); !ok || sourceNode == nil {
		t.Fatalf("did not recover provider request source from loginCallback")
	}
	authSinkOK := false
	walkCallableExecutableNodes(engine.callables[loginKey], func(node ast.Node) {
		if authSinkOK {
			return
		}
		call, ok := node.(*ast.ExprMethodCall)
		if !ok || strings.ToLower(identifierText(call.Name)) != "wordpresslogincallback" {
			return
		}
		_, authSinkOK = state.authCookieSinkForMethodCall(call)
	})
	if !authSinkOK {
		t.Fatalf("did not recover auth cookie sink through wordpressLoginCallback")
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-public-oauth-callback-auth-surface" {
		t.Fatalf("check_id = %q, want wp-public-oauth-callback-auth-surface", finding.CheckID)
	}
	if !strings.Contains(strings.ToLower(finding.Extra.Trace.Source.Snippet), "sanitize(input_get, 'provider'") {
		t.Fatalf("source snippet = %q, want provider sanitize read", finding.Extra.Trace.Source.Snippet)
	}
	if !strings.Contains(strings.ToLower(finding.Extra.Trace.Sink.Snippet), "wp_set_auth_cookie($userid)") {
		t.Fatalf("sink snippet = %q, want auth cookie sink", finding.Extra.Trace.Sink.Snippet)
	}
}

func TestAnalyzeRootSkipsPublicOAuthCallbackAuthSurfaceAfterUsersCanRegisterGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "oauth-callback-surface-safe.php"), `<?php
function add_action($hook, $callback) {}
function get_option($key) { return false; }

class Sanitizer {
    public static function sanitize($source, $key, $filter) {
        return filter_input($source, $key, $filter);
    }
}

class DemoSocial {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_login_callback', array($this, 'loginCallback'));
    }

    public function loginCallback() {
        if (!get_option('users_can_register')) {
            return;
        }
        $provider = Sanitizer::sanitize(INPUT_GET, 'provider', FILTER_SANITIZE_STRING);
        if ($provider === 'wordpress') {
            $this->wordpressLoginCallback();
        }
    }

    private function wordpressLoginCallback() {
        $code = Sanitizer::sanitize(INPUT_GET, 'code', FILTER_SANITIZE_STRING);
        if (!$code) {
            return;
        }
        $this->setCurrentUser(7);
    }

    private function setCurrentUser($userID) {
        wp_set_auth_cookie($userID);
    }
}

new DemoSocial();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestBuildEngineLinksWpDiscuzOAuthCallbackSurfacePieces(t *testing.T) {
	requireRealPluginFixtureTest(t)
	root := "/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/wpdiscuz__7.6.24"
	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	loginKey := engine.lookupMethodKey(`\wpdFormAttr\Login\SocialLogin`, "loginCallBack")
	if loginKey == "" {
		matches := []string{}
		for key := range engine.callables {
			if strings.Contains(strings.ToLower(key), "sociallogin::logincallback") {
				loginKey = key
				break
			}
			if strings.Contains(strings.ToLower(key), "sociallogin") || strings.Contains(strings.ToLower(key), "logincallback") {
				matches = append(matches, key)
			}
		}
		if loginKey == "" && len(matches) != 0 {
			sort.Strings(matches)
			t.Fatalf("missing wpDiscuz loginCallBack method key; nearby keys=%v", matches)
		}
	}
	if loginKey == "" {
		t.Fatalf("missing wpDiscuz loginCallBack method key")
	}
	if len(engine.directEntryPointsByCallable[loginKey]) == 0 {
		t.Fatalf("wpDiscuz loginCallBack missing direct entrypoint context")
	}
	loginCallable := engine.callables[loginKey]
	sourceNode, ok := oauthCallbackRequestSourceNode(loginCallable, 0)
	if !ok || sourceNode == nil {
		t.Fatalf("did not recover wpDiscuz provider request source")
	}
	state := &analysisState{
		engine:  engine,
		current: loginCallable,
	}
	authSinkOK := false
	walkCallableExecutableNodes(loginCallable, func(node ast.Node) {
		if authSinkOK {
			return
		}
		call, ok := node.(*ast.ExprMethodCall)
		if !ok || strings.ToLower(identifierText(call.Name)) != "wordpresslogincallback" {
			return
		}
		_, authSinkOK = state.authCookieSinkForMethodCall(call)
	})
	if !authSinkOK {
		t.Fatalf("did not recover wpDiscuz auth cookie sink through wordpressLoginCallBack")
	}
	if !engine.callableHasPublicOAuthCallbackAuthSurfaceSink(loginCallable) {
		t.Fatalf("wpDiscuz loginCallBack not marked as public OAuth callback surface sink")
	}
}

func TestLoadFilesAcceptsRecoverableInterpolatedArrayKeyParseErrors(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "recoverable-interpolation.php"), `<?php
namespace Demo\Login;

class SocialLogin {
    public function loginCallBack() {
        $provider = Sanitizer::sanitize(INPUT_GET, "provider", FILTER_SANITIZE_STRING);
        if ($provider === "wordpress") {
            $this->wordpressLoginCallBack();
        }
    }

    private function wordpressLoginCallBack() {
        $this->setCurrentUser(1);
    }

    private function setCurrentUser($userID) {
        wp_set_auth_cookie($userID);
    }

    private function parseBrokenInterpolation() {
        $sig = md5("application_key={$this->generalOptions->social[\"okAppKey\"]}format=jsonmethod=users.getCurrentUser");
        return $sig;
    }
}
`)
	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("unexpected loaded files count: %d", len(files))
	}
	if len(files[0].AST) == 0 {
		t.Fatalf("unexpected loaded file ast length: %d", len(files[0].AST))
	}
	methods := collectMethodCallables(files[0].AST, "", files[0].Relative, nil)
	if len(methods) == 0 {
		t.Fatalf("collectMethodCallables() returned no methods for recoverable interpolation file")
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	if key := engine.lookupMethodKey(`\Demo\Login\SocialLogin`, "loginCallBack"); key == "" {
		matches := []string{}
		for candidate := range engine.callables {
			lower := strings.ToLower(candidate)
			if strings.Contains(lower, "sociallogin") || strings.Contains(lower, "logincallback") {
				matches = append(matches, candidate)
			}
		}
		sort.Strings(matches)
		methodKeys := make([]string, 0, len(methods))
		for _, method := range methods {
			methodKeys = append(methodKeys, method.Key)
		}
		sort.Strings(methodKeys)
		t.Fatalf("missing loginCallBack method after recoverable interpolation parse path; nearby keys=%v method_keys=%v", matches, methodKeys)
	}
}

func TestAnalyzeRootFindsPublicRestTokenIssuanceSurfaceInInlineClosure(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest-token-surface-closure.php"), `<?php
class WP_REST_Request {
    public function get_param($key) {
        return array(1, 2);
    }
}

class TokenFactory {
    public static function make() {
        return new Token();
    }
}

class Token {
    public function create($publicKey, $formIds = array()) {
        return implode(':', $formIds);
    }
}

class KeyFactory {
    public static function make($length) {
        return 'public';
    }
}

add_action('rest_api_init', function () {
    register_rest_route('demo/v1', 'token/refresh', array(
        'methods' => 'POST',
        'callback' => function (WP_REST_Request $request) {
            $formIds = $request->get_param('formIds');
            $formIds = array_map('absint', $formIds);
            $formIds = array_filter($formIds);
            $tokenGenerator = TokenFactory::make();
            $publicKey = KeyFactory::make(32);
            $newToken = $tokenGenerator->create($publicKey, $formIds);
            return array(
                'token' => $newToken,
                'formIds' => $formIds,
            );
        },
        'permission_callback' => '__return_true',
    ));
});
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsUnsafeUploadValidationSurfaceFromFilenameSubstringCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "upload-validation-surface.php"), `<?php
function add_filter($hook, $callback, $priority = 10, $accepted_args = 1) {}

class DemoUploadSurface {
    public function __construct() {
        add_filter('wp_check_filetype_and_ext', array($this, 'real_mime_types'), 10, 4);
    }

    public function real_mime_types($defaults, $file, $filename, $mimes) {
        return $this->real_mimes($defaults, $filename, $file);
    }

    public function real_mimes($defaults, $filename, $file) {
        if (strpos($filename, 'wxr') !== false) {
            $defaults['ext'] = 'xml';
            $defaults['type'] = 'text/xml';
        }
        return $defaults;
    }
}

new DemoUploadSurface();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 2 {
		t.Fatalf("findings = %d, want 2", len(result.Payload.Results))
	}
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "upload-api-surface" {
			t.Fatalf("check_id = %q, want upload-api-surface", finding.CheckID)
		}
		if finding.Extra.Trace.Sink.Path == "" || finding.Extra.Trace.Sink.Line == 0 {
			t.Fatalf("missing sink trace: %#v", finding.Extra.Trace)
		}
		if len(finding.Extra.Context.EntryPoints) == 0 || finding.Extra.Context.EntryPoints[0].Kind != "filter" {
			t.Fatalf("entrypoints = %#v, want filter callback context", finding.Extra.Context.EntryPoints)
		}
		if finding.Extra.Context.EntryPoints[0].Name != "wp_check_filetype_and_ext" {
			t.Fatalf("entrypoint name = %q, want wp_check_filetype_and_ext", finding.Extra.Context.EntryPoints[0].Name)
		}
	}
}

func TestAnalyzeRootSkipsUploadValidationSurfaceAfterExactExtensionGuard(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "upload-validation-surface-safe.php"), `<?php
function add_filter($hook, $callback, $priority = 10, $accepted_args = 1) {}

class DemoUploadSurface {
    public function __construct() {
        add_filter('wp_check_filetype_and_ext', array($this, 'real_mime_types'), 10, 4);
    }

    public function real_mime_types($defaults, $file, $filename, $mimes) {
        return $this->real_mimes($defaults, $filename, $file);
    }

    public function real_mimes($defaults, $filename, $file) {
        $file_extension = pathinfo($filename, PATHINFO_EXTENSION);
        if ('xml' === $file_extension && strpos($filename, 'wxr') !== false) {
            $defaults['ext'] = 'xml';
            $defaults['type'] = 'text/xml';
        }
        return $defaults;
    }
}

new DemoUploadSurface();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootMarksValidatorChecks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rest.php"), `<?php
class LogStore {
    public function get_log($id) {
        return array('original_message' => $id);
    }
}

class RestDemo {
    public function __construct() {
        register_rest_route('demo/v1', '/log', array(
            'methods' => 'GET',
            'callback' => array($this, 'handle'),
            'permission_callback' => '__return_true',
        ));
    }

    private function validate($token) {
        if ( empty($token) ) {
            wp_send_json_error(array('error' => 'missing'), 401);
        }
        return true;
    }

    public function handle() {
        $token = $_GET['token'];
        if ( $this->validate($token) ) {
            $id = $_GET['log_id'];
            $store = new LogStore();
            $log = $store->get_log($id);
            echo $log['original_message'];
        }
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-record-read-to-output-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-record-read-to-output-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.ValidationChecks) == 0 {
		t.Fatalf("validation checks = %d, want > 0", len(finding.Extra.Context.ValidationChecks))
	}
}

func TestAnalyzeRootFindsUnauthenticatedUploadWithoutCapCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ajax.php"), `<?php
class UploadDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_upload', array($this, 'handle'));
    }

    public function handle() {
        $tmp = $_FILES['file']['tmp_name'];
        move_uploaded_file($tmp, '/tmp/demo.bin');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Name != "wp_ajax_nopriv_demo_upload" {
		t.Fatalf("entrypoint hook = %q, want wp_ajax_nopriv_demo_upload", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootPropagatesAjaxContextIntoHelperUpload(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ajax-helper.php"), `<?php
class UploadHelperDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_upload_helper', array($this, 'handle'));
    }

    public function handle() {
        $this->upload();
    }

    private function upload() {
        $tmp = $_FILES['file']['tmp_name'];
        move_uploaded_file($tmp, '/tmp/demo-helper.bin');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Name != "wp_ajax_nopriv_demo_upload_helper" {
		t.Fatalf("entrypoint hook = %q, want wp_ajax_nopriv_demo_upload_helper", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootFindsUploadThroughPropertyStoredHelperReceiver(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "property-helper-upload.php"), `<?php
class FileManager {
    public static function get_instance() {
        return new self();
    }

    public function temp_file_upload($file) {
        move_uploaded_file($file['tmp_name'], '/tmp/demo-property.bin');
    }
}

class Ajax {
    private $fm;

    public function __construct() {
        $this->fm = FileManager::get_instance();
        add_action('wp_ajax_nopriv_demo_upload_property', array($this, 'temp_file_upload'));
    }

    public function temp_file_upload() {
        $file = $_FILES['ht_form_file'];
        return $this->fm->temp_file_upload($file);
    }
}

new Ajax();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsUploadRegisteredThroughLifecycleClosureAndSingletonConstructors(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "lifecycle-closure-upload.php"), `<?php
class FileManager {
    public function temp_file_upload($file) {
        move_uploaded_file($file['tmp_name'], '/tmp/demo-lifecycle.bin');
    }
}

class Ajax {
    private static $instance;
    private $fm;

    public static function get_instance() {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function __construct() {
        $this->fm = new FileManager();
        add_action('wp_ajax_nopriv_demo_upload', array($this, 'temp_file_upload'));
    }

    public function temp_file_upload() {
        $file = $_FILES['ht_form_file'];
        return $this->fm->temp_file_upload($file);
    }
}

class Admin {
    public static function get_instance() {
        return new self();
    }

    public function __construct() {
        Ajax::get_instance();
    }
}

class Bootstrap {
    public static function get_instance() {
        return new self();
    }

    public function __construct() {
        add_action('plugins_loaded', array($this, 'include_files'));
    }

    public function include_files() {
        add_action('init', function() {
            Admin::get_instance();
        });
    }
}

Bootstrap::get_instance();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	foundAjax := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Name == "wp_ajax_nopriv_demo_upload" {
			foundAjax = true
			break
		}
	}
	if !foundAjax {
		t.Fatalf("entrypoints = %#v, want wp_ajax_nopriv_demo_upload", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootFindsUnauthenticatedFilePutContentsUpload(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "file-put-contents.php"), `<?php
class UploadWriteDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_upload_write', array($this, 'handle'));
    }

    public function handle() {
        $data = $_FILES['file']['tmp_name'];
        file_put_contents('/tmp/demo-upload.bin', $data);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsUnauthenticatedWPUploadBitsSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "wp-upload-bits.php"), `<?php
class UploadBitsDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_upload_bits', array($this, 'handle'));
    }

    public function handle() {
        $name = $_POST['name'];
        wp_upload_bits($name, null, 'static-bits');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsUnauthenticatedWPSideloadSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "wp-handle-sideload.php"), `<?php
class SideloadDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_sideload', array($this, 'handle'));
    }

    public function handle() {
        $file = array(
            'name' => $_FILES['upload']['name'],
            'tmp_name' => $_FILES['upload']['tmp_name'],
            'error' => 0,
            'size' => 123,
        );
        wp_handle_sideload($file, array('test_form' => false));
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Trace.Sink.Line != 14 {
		t.Fatalf("sink line = %d, want 14", finding.Extra.Trace.Sink.Line)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsUnauthenticatedUnzipFileSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "unzip-file.php"), `<?php
class UnzipUploadDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_unzip_upload', array($this, 'handle'));
    }

    public function handle() {
        $archive = $_FILES['archive']['tmp_name'];
        unzip_file($archive, '/var/www/html/wp-content/uploads/spbct_demo');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Trace.Sink.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Extra.Trace.Sink.Line)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 || finding.Extra.Context.EntryPoints[0].Name != "wp_ajax_nopriv_demo_unzip_upload" {
		t.Fatalf("entrypoints = %#v, want wp_ajax_nopriv_demo_unzip_upload", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootFindsUnauthenticatedFilesystemMoveSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "filesystem-move.php"), `<?php
class WPFS {
    public function move($from, $to, $overwrite = false) {}
}

class UploadFilesystemDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_fs_move', array($this, 'handle'));
    }

    public function handle() {
        $wpfs = new WPFS();
        $from = $_FILES['file']['tmp_name'];
        $wpfs->move($from, '/tmp/demo-fs.bin', true);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsUnauthenticatedArchiveExtractMethodSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "archive-extract.php"), `<?php
class ZipBridge {
    public function extract($from, $to) {}
}

class ArchiveUploadDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_archive_extract', array($this, 'handle'));
    }

    public function handle() {
        $zip = new ZipBridge();
        $archive = $_FILES['archive']['tmp_name'];
        $zip->extract($archive, '/tmp/demo-archive');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-upload-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-upload-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Trace.Sink.Line != 14 {
		t.Fatalf("sink line = %d, want 14", finding.Extra.Trace.Sink.Line)
	}
}

func TestAnalyzeRootDoesNotTreatNonArchiveExtractMethodsAsUploadSinks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "non-archive-extract.php"), `<?php
class TemplateExtractor {
    public function extract($data) {}
}

class NonArchiveDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_non_archive_extract', array($this, 'handle'));
    }

    public function handle() {
        $extractor = new TemplateExtractor();
        $archive = $_FILES['archive']['tmp_name'];
        $extractor->extract($archive);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootSkipsStatementsAfterThrowingStaticHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "throwing-helper.php"), `<?php
class Thrower {
    public static function fail($message) {
        throw new Exception($message);
    }
}

class ZipBridge {
    public function extract($tmp, $dest) {}
}

class Demo {
    public function run() {
        Thrower::fail('blocked');
        $zip = new ZipBridge();
        $zip->extract($_FILES['archive']['tmp_name'], '/tmp/extracted');
    }
}

(new Demo())->run();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	runKey := engine.lookupMethodKey(`\Demo`, "run")
	if runKey == "" {
		t.Fatal("missing Demo::run")
	}
	if got := engine.summaries[runKey]; !summaryHasNoEffects(got) {
		t.Fatalf("Demo::run summary leaked effects after throwing helper: %+v", got)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0; results=%#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootFindsUnauthenticatedDeleteWithoutCapCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ajax-delete.php"), `<?php
class DeleteDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_delete', array($this, 'handle'));
    }

    public function handle() {
        $path = $_POST['path'];
        unlink($path);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsNonceOnlyDeleteWithoutCapCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ajax-delete-nonce.php"), `<?php
class DeleteNonceDemo {
    public function __construct() {
        add_action('wp_ajax_demo_delete_nonce', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo');
        $path = $_POST['path'];
        wp_delete_file($path);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootKeepsGenericDeleteWhenCapabilityChecked(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "ajax-delete-cap.php"), `<?php
class DeleteCapDemo {
    public function __construct() {
        add_action('wp_ajax_demo_delete_cap', array($this, 'handle'));
    }

    public function handle() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $path = $_POST['path'];
        unlink($path);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "request-path-read-delete" {
		t.Fatalf("check_id = %q, want request-path-read-delete", finding.CheckID)
	}
	if finding.Extra.Context.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootDispatchesConcatHookWithStaticRequestGetterToSensitiveAction(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "router.php"), `<?php
class Util_Request {
    public static function get_string($key) {}
}

class ActionRouterDemo {
    public function __construct() {
        add_action('wp_ajax_demo_router', array($this, 'route'));
        add_action('demo_save', array($this, 'save'));
    }

    public function route() {
        do_action('demo_' . Util_Request::get_string('action'));
    }

    public function save() {
        update_option('demo_value', $_POST['value']);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
		if err != nil {
			t.Fatalf("BuildManifestForRoot(): %v", err)
		}
		files, err := loadFiles(manifest, 1)
		if err != nil {
			t.Fatalf("loadFiles(): %v", err)
		}
		engine, err := buildEngine(root, files, Options{
			AllowedSinkOps: map[string]struct{}{"action": {}},
		})
		if err != nil {
			t.Fatalf("buildEngine(): %v", err)
		}
		_ = engine
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if finding.Extra.Trace.Source.Line != 17 {
		t.Fatalf("source line = %d, want 17", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootDispatchesConcatHookWithVariableSuffixToDeleteSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "router-var.php"), `<?php
class DeleteRouterDemo {
    public function __construct() {
        add_action('demo_pre_update_setting_cache_keys', array($this, 'clean_stale_cache'), 10, 2);
    }

    public function update_settings() {
        $updated_settings = $_POST;
        foreach ($updated_settings as $option_name => $option_value) {
            if (!is_array($option_value)) {
                continue;
            }
            foreach ($option_value as $setting_name => $setting_value) {
                do_action('demo_pre_update_setting_' . $setting_name, $setting_name, $setting_value);
            }
        }
    }

    public function clean_stale_cache($option_name, $option_value) {
        $dir_to_remove = $option_value;
        unlink('/tmp/' . $dir_to_remove);
    }
}

(new DeleteRouterDemo())->update_settings();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 21 {
		t.Fatalf("sink line = %d, want 21", finding.Start.Line)
	}
}

func TestAnalyzeRootDispatchesConcatHookAfterRecursiveArrayMapSanitizer(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "router-array-map-clean.php"), `<?php
function add_action($hook, $callback, $priority = 10, $argc = 1) {}
function do_action($hook, ...$args) {}
function sanitize_text_field($value) { return $value; }
function wp_unslash($value) { return $value; }

class DeleteRouterArrayMapDemo {
    public function __construct() {
        add_action('demo_pre_update_setting_cache_keys', array($this, 'clean_stale_cache'), 10, 2);
    }

    private function clean($var) {
        if (is_array($var)) {
            return array_map([__CLASS__, __METHOD__], $var);
        }
        return is_scalar($var) ? sanitize_text_field(wp_unslash($var)) : $var;
    }

    public function update_settings() {
        $updated_settings = $this->clean($_POST);
        foreach ($updated_settings as $option_name => $option_value) {
            if (!is_array($option_value)) {
                continue;
            }
            foreach ($option_value as $setting_name => $setting_value) {
                do_action('demo_pre_update_setting_' . $setting_name, $setting_name, $setting_value);
            }
        }
    }

    public function clean_stale_cache($option_name, $option_value) {
        unlink('/tmp/' . $option_value);
    }
}

(new DeleteRouterArrayMapDemo())->update_settings();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 32 {
		t.Fatalf("sink line = %d, want 32", finding.Start.Line)
	}
}

func TestAnalyzeRootPropagatesSelectorChosenDeletePath(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "selector-chosen-delete.php"), `<?php
function add_action($hook, $callback, $priority = 10, $argc = 1) {}
function do_action($hook, ...$args) {}
function sanitize_text_field($value) { return $value; }
function wp_unslash($value) { return $value; }
define('OMGF_UPLOAD_DIR', '/tmp');

class Helper {
    public static function cache_keys() {
        return ['abc', 'safe'];
    }
}

class SelectorDeleteDemo {
    public function __construct() {
        add_action('demo_pre_update_setting_cache_keys', array($this, 'clean_stale_cache'), 10, 2);
    }

    private function clean($var) {
        if (is_array($var)) {
            return array_map([__CLASS__, __METHOD__], $var);
        }
        return is_scalar($var) ? sanitize_text_field(wp_unslash($var)) : $var;
    }

    public function update_settings() {
        $updated_settings = $this->clean($_POST);
        foreach ($updated_settings as $option_name => $option_value) {
            if (strpos($option_name, 'omgf_') !== 0 || (empty($option_value) && $option_value !== '0')) {
                continue;
            }
            if (!is_array($option_value)) {
                continue;
            }
            foreach ($option_value as $setting_name => $setting_value) {
                do_action('demo_pre_update_setting_' . $setting_name, $setting_name, $setting_value);
            }
        }
    }

    public function clean_stale_cache($option_name, $option_value) {
        $old_keys = Helper::cache_keys();
        $new_keys = explode(',', $option_value);
        foreach ($new_keys as $new_cache_key) {
            $dir_to_remove = '';
            $base_key = preg_replace('/-mod.*?$/', '', $new_cache_key);
            foreach ($old_keys as $old_cache_key) {
                if (strpos($old_cache_key, $base_key) !== false) {
                    $dir_to_remove = $old_cache_key;
                    break;
                }
            }
            if (!$dir_to_remove) {
                continue;
            }
            rmdir(OMGF_UPLOAD_DIR . '/' . $dir_to_remove);
        }
    }
}

(new SelectorDeleteDemo())->update_settings();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 56 {
		t.Fatalf("sink line = %d, want 56", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 27 {
		t.Fatalf("source line = %d, want 27", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsRmdirDeleteSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "rmdir.php"), `<?php
class DeleteDirDemo {
    public function run() {
        rmdir($_GET['path']);
    }
}

(new DeleteDirDemo())->run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-file-delete-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-file-delete-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 4 {
		t.Fatalf("sink line = %d, want 4", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsWeakDynamicCapabilitySensitiveAction(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "dynamic-cap.php"), `<?php
class Util_Request {
    public static function get_string($key) {}
}

class SensitiveActionDynamicCapDemo {
    public function __construct() {
        add_action('wp_ajax_demo_sensitive', array($this, 'handle'));
    }

    public function handle() {
        $capability = apply_filters('demo_cap_' . Util_Request::get_string('action'), 'manage_options');
        if ( current_user_can($capability) ) {
            update_option('demo_value', $_POST['value']);
        }
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.CapabilityChecks) != 0 {
		t.Fatalf("capability checks = %d, want 0 for weak dynamic capability gate", len(finding.Extra.Context.CapabilityChecks))
	}
}

func TestAnalyzeRootDoesNotFlagCapabilityGuardedSensitiveAction(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "guarded-action.php"), `<?php
class SensitiveActionGuardedDemo {
    public function __construct() {
        add_action('wp_ajax_demo_guarded_action', array($this, 'handle'));
    }

    public function handle() {
        if ( current_user_can('manage_options') ) {
            update_option('demo_value', $_POST['value']);
        }
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsAjaxInsertPostWithoutCapabilityCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "insert-post-action.php"), `<?php
class InsertPostActionDemo {
    public function __construct() {
        add_action('wp_ajax_demo_insert_post', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo-insert-post', 'nonce');
        wp_insert_post(array(
            'post_type' => 'demo_form',
            'post_content' => $_POST['content'],
        ));
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsAjaxUpdatePostMetaWithoutCapabilityCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "update-post-meta-action.php"), `<?php
class UpdatePostMetaActionDemo {
    public function __construct() {
        add_action('wp_ajax_demo_update_meta', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo-update-meta', 'nonce');
        update_post_meta(77, 'default_role', $_POST['role']);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsAjaxSensitiveActionThroughExplodeResetWithoutCapabilityCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "explode-reset-action.php"), `<?php
class ExplodeResetActionDemo {
    public function __construct() {
        add_action('wp_ajax_demo_explode_reset', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo-explode-reset', 'nonce');
        $parts = explode('[', $_POST['name']);
        $key = reset($parts);
        update_option($key, $_POST['value']);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 11 {
		t.Fatalf("sink line = %d, want 11", finding.Start.Line)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsPublicAjaxRoleMutationViaSetRole(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-ajax-set-role.php"), `<?php
class RoleMutationDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_role_mutation', array($this, 'handle'));
    }

    public function handle() {
        $payload = array(
            'role' => sanitize_text_field($_POST['role']),
        );
        $user = new \WP_User(7);
        $user->set_role($payload['role']);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-tainted-privilege-mutation" {
		t.Fatalf("check_id = %q, want wp-request-tainted-privilege-mutation", finding.CheckID)
	}
	if finding.Start.Line != 12 {
		t.Fatalf("sink line = %d, want 12", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsPublicAjaxRoleMutationViaWpInsertUserRoleField(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-ajax-insert-user-role.php"), `<?php
class RoleInsertUserDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_insert_user_role', array($this, 'handle'));
    }

    public function handle() {
        $user_data = array(
            'user_login' => sanitize_text_field($_POST['username']),
            'user_email' => sanitize_email($_POST['email']),
        );
        $user_data['role'] = sanitize_text_field($_POST['user_role']);
        wp_insert_user($user_data);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-tainted-privilege-mutation" {
		t.Fatalf("check_id = %q, want wp-request-tainted-privilege-mutation", finding.CheckID)
	}
	if finding.Start.Line != 13 {
		t.Fatalf("sink line = %d, want 13", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 12 {
		t.Fatalf("source line = %d, want 12", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootSkipsPublicAjaxLowPrivilegeWpInsertUserRoleAllowlist(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-ajax-insert-user-role-fixed.php"), `<?php
class RoleInsertUserSafeDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_insert_user_role_safe', array($this, 'handle'));
    }

    public function handle() {
        $allowed_roles = array('subscriber', 'customer');
        $requested_role = isset($_POST['user_role']) ? sanitize_text_field($_POST['user_role']) : 'subscriber';
        $user_role = in_array($requested_role, $allowed_roles, true) ? $requested_role : 'subscriber';
        $user_data = array(
            'user_login' => sanitize_text_field($_POST['username']),
            'user_email' => sanitize_email($_POST['email']),
        );
        if (!empty($user_role) && $user_role !== 'subscriber') {
            $user_data['role'] = $user_role;
        }
        wp_insert_user($user_data);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0: %#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootFindsPublicAjaxRoleMutationViaLiteralAddRole(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-ajax-add-role.php"), `<?php
class RoleAddDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_role_add', array($this, 'handle'));
    }

    public function handle() {
        $profile = sanitize_text_field($_POST['profile']);
        $user = new \WP_User(7);
        $user->add_role('tutor_instructor');
    }
}

$demo = new RoleAddDemo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-tainted-privilege-mutation" {
		t.Fatalf("check_id = %q, want wp-request-tainted-privilege-mutation", finding.CheckID)
	}
	if finding.Start.Line != 10 {
		t.Fatalf("sink line = %d, want 10", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 8 {
		t.Fatalf("source line = %d, want 8", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootSkipsCapabilityCheckedLiteralAddRoleMutation(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-ajax-add-role-fixed.php"), `<?php
class RoleAddGuardedDemo {
    public function __construct() {
        add_action('wp_ajax_demo_role_add_guarded', array($this, 'handle'));
    }

    public function handle() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $profile = sanitize_text_field($_POST['profile']);
        $user = new \WP_User(7);
        $user->add_role('tutor_instructor');
    }
}

$demo = new RoleAddGuardedDemo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0: %#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootFindsPublicAjaxRoleMutationThroughHelperChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-ajax-set-role-chain.php"), `<?php
class MembersService {
    public function prepare_members_data($data) {
        $response = array();
        $response['role'] = isset($data['role']) ? sanitize_text_field($data['role']) : 'subscriber';
        return $response;
    }

    public function update_user_meta($data, $new_user_id) {
        $user = new \WP_User($new_user_id);
        $user->set_role($data['role']);
    }
}

class MembershipService {
    private $members_service;

    public function __construct() {
        $this->members_service = new MembersService();
    }

    public function create_membership_order_and_subscription($data) {
        $members_data = $this->members_service->prepare_members_data($data);
        $this->members_service->update_user_meta($members_data, 7);
    }
}

class AjaxDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_role_mutation_chain', array($this, 'register_member'));
    }

    public function register_member() {
        $data = array(
            'role' => sanitize_text_field($_POST['role']),
        );
        $membership_service = new MembershipService();
        $membership_service->create_membership_order_and_subscription($data);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-tainted-privilege-mutation" {
		t.Fatalf("check_id = %q, want wp-request-tainted-privilege-mutation", finding.CheckID)
	}
	if finding.Start.Line != 11 {
		t.Fatalf("sink line = %d, want 11", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 35 {
		t.Fatalf("source line = %d, want 35", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootSkipsPublicAjaxRoleMutationWhenFrontendRoleIsOverwritten(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-ajax-set-role-fixed.php"), `<?php
class MembershipRepository {
    public function get_single_membership_by_ID($id) {
        return array('meta_value' => '{}');
    }
}

class MembersService {
    private $membership_repository;

    public function __construct() {
        $this->membership_repository = new MembershipRepository();
    }

    public function prepare_members_data($data, $context = 'admin') {
        if ('frontend' === $context) {
            $membership_detail = $this->membership_repository->get_single_membership_by_ID(absint($data['membership']));
            $data['role'] = isset($membership_detail['role']) ? sanitize_text_field($membership_detail['role']) : 'subscriber';
        }
        $response = array();
        $response['role'] = isset($data['role']) ? sanitize_text_field($data['role']) : 'subscriber';
        if (!empty($data['membership'])) {
            $membership_details = $this->membership_repository->get_single_membership_by_ID(absint($data['membership']));
            $membership_meta = json_decode($membership_details['meta_value'], true);
            $response['role'] = isset($membership_meta['role']) ? sanitize_text_field($membership_meta['role']) : $response['role'];
        }
        return $response;
    }

    public function update_user_meta($data, $new_user_id) {
        $user = new \WP_User($new_user_id);
        $user->set_role($data['role']);
    }
}

class MembershipService {
    private $members_service;

    public function __construct() {
        $this->members_service = new MembersService();
    }

    public function create_membership_order_and_subscription($data) {
        $members_data = $this->members_service->prepare_members_data($data, 'frontend');
        $this->members_service->update_user_meta($members_data, 7);
    }
}

class AjaxDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_role_mutation', array($this, 'register_member'));
    }

    public function register_member() {
        $data = array(
            'role' => sanitize_text_field($_POST['role']),
            'membership' => absint($_POST['membership']),
        );
        $membership_service = new MembershipService();
        $membership_service->create_membership_order_and_subscription($data);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 0, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestBuildEngineKeepsPublicAjaxRoleMutationHelperChainForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-ajax-set-role-chain.php"), `<?php
class MembersService {
    public function prepare_members_data($data) {
        $response = array();
        $response['role'] = isset($data['role']) ? sanitize_text_field($data['role']) : 'subscriber';
        return $response;
    }

    public function update_user_meta($data, $new_user_id) {
        $user = new \WP_User($new_user_id);
        $user->set_role($data['role']);
    }
}

class MembershipService {
    private $members_service;

    public function __construct() {
        $this->members_service = new MembersService();
    }

    public function create_membership_order_and_subscription($data) {
        $members_data = $this->members_service->prepare_members_data($data);
        $this->members_service->update_user_meta($members_data, 7);
    }
}

class AjaxDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_role_mutation_chain', array($this, 'register_member'));
    }

    public function register_member() {
        $data = array(
            'role' => sanitize_text_field($_POST['role']),
        );
        $membership_service = new MembershipService();
        $membership_service->create_membership_order_and_subscription($data);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	updateKey := `method::\MembersService::update_user_meta`
	createKey := `method::\MembershipService::create_membership_order_and_subscription`
	registerKey := `method::\AjaxDemo::register_member`

	if !engine.callInputConsumingCallables[updateKey] {
		t.Fatalf("update_user_meta should consume call input: %#v", engine.callInputConsumingCallables)
	}
	if _, ok := engine.relevantCallables[updateKey]; !ok {
		t.Fatalf("update_user_meta should stay relevant: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[createKey]; !ok {
		t.Fatalf("create_membership_order_and_subscription should stay relevant: %#v", engine.relevantCallables)
	}
	if !engine.callInputConsumingCallables[createKey] {
		t.Fatalf("create_membership_order_and_subscription should consume call input: consuming=%#v orders=%#v sites=%#v", engine.callInputConsumingCallables, engine.callSinkRelevantUseOrders[createKey], engine.callSiteEdges[createKey])
	}
	prepareRelevant := false
	for key := range engine.relevantCallables {
		if strings.Contains(key, `\MembersService::prepare_members_data`) {
			prepareRelevant = true
			break
		}
	}
	if !prepareRelevant {
		t.Fatalf("prepare_members_data should stay relevant: %#v", engine.relevantCallables)
	}
	if got := engine.receiverPropertyReturnClassHint(`\MembershipService`, "this.members_service"); got != `\MembersService` {
		t.Fatalf("receiverPropertyReturnClassHint(\\MembershipService, this.members_service) = %q, want \\MembersService; hints=%#v", got, engine.receiverPropertyClassHints)
	}
	if len(engine.callSiteEdges[registerKey]) == 0 {
		t.Fatalf("register_member should call create_membership_order_and_subscription: %#v", engine.callSiteEdges)
	}
	if _, ok := engine.relevantCallables[registerKey]; !ok {
		t.Fatalf("register_member should stay relevant: relevant=%#v sites=%#v consuming=%#v", engine.relevantCallables, engine.callSiteEdges[registerKey], engine.callInputConsumingCallables)
	}
	if !callRelevantRootPresent(engine.callSinkRelevantUseOrders[createKey], "members_data") {
		t.Fatalf("create_membership_order_and_subscription should keep members_data as call-relevant root: %#v", engine.callSinkRelevantUseOrders[createKey])
	}

	updateSummary := engine.analyzeCallable(engine.callables[updateKey])
	if len(updateSummary.ParamFindings[0]) == 0 {
		t.Fatalf("update_user_meta should summarize the role mutation sink: %#v", updateSummary)
	}
	createSummary := engine.analyzeCallable(engine.callables[createKey])
	if len(createSummary.SourceFindings) == 0 && len(createSummary.ParamFindings[0]) == 0 {
		t.Fatalf("create_membership_order_and_subscription should replay the downstream sink: %#v", createSummary)
	}
	registerSummary := engine.analyzeCallable(engine.callables[registerKey])
	if len(registerSummary.SourceFindings) == 0 {
		t.Fatalf("register_member should collapse the helper chain back to a concrete source: %#v", registerSummary)
	}
}

func TestAnalyzeRootResolvesLocalObjectCallbackRegistrationContext(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "local-object-callback.php"), `<?php
class SaveHandler {
    public function save() {
        update_option('demo_value', $_POST['value']);
    }
}

class RouterDemo {
    public function __construct() {
        add_action('wp_ajax_demo_router', array($this, 'route'));
        $handler = new SaveHandler();
        add_action('demo_save', array($handler, 'save'));
    }

    public function route() {
        do_action('demo_save');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	found := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Name == "wp_ajax_demo_router" {
			found = true
		}
	}
	if !found {
		t.Fatalf("entrypoints = %#v, want wp_ajax_demo_router", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootResolvesSingletonPropertyRegistryArrayDispatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "singleton-property-registry.php"), `<?php
class Handler_Save {
    public function process($data) {
        eval($data['payload']);
    }
}

class Handler_Log {
    public function process($data) {
        error_log($data['payload']);
    }
}

class Registry {
    public static $instance;
    public $handlers = array();

    public static function instance() {
        if (!self::$instance) {
            self::$instance = new Registry();
        }
        return self::$instance;
    }

    public static function load_classes($prefix) {
        $return = array();
        $name = 'Save';
        $class_name = $prefix . '_' . $name;
        $return[strtolower($name)] = new $class_name;
        $name = 'Log';
        $class_name = $prefix . '_' . $name;
        $return[strtolower($name)] = new $class_name;
        return $return;
    }

    public function boot() {
        $handlers = self::load_classes('Handler');
        self::$instance->handlers = apply_filters('demo_handlers', $handlers);
    }
}

function RegistryFunc() {
    return Registry::instance();
}

class Demo {
    public function __construct() {
        Registry::instance()->boot();
        add_action('wp_ajax_nopriv_demo_registry', array($this, 'run'));
    }

    public function run() {
        $type = 'save';
        $handler = RegistryFunc()->handlers[$type];
        $handler->process($_POST);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	runKey := engine.lookupMethodKey(`\Demo`, "run")
	if runKey == "" {
		t.Fatalf("missing Demo::run")
	}
	processKey := engine.lookupMethodKey(`\Handler_Save`, "process")
	if processKey == "" {
		t.Fatalf("missing Handler_Save::process")
	}
	loadClassesKey := engine.lookupMethodKey(`\Registry`, "load_classes")
	if loadClassesKey == "" {
		t.Fatalf("missing Registry::load_classes")
	}
	loadClassesKey = engine.specializeCallableKeyForIntrospection(loadClassesKey, map[int]string{0: "Handler"})
	loadEntryClasses := engine.callableReturnArrayEntryClassRefs(loadClassesKey, map[string]struct{}{})
	foundHandlerSave := false
	foundRegistry := false
	for _, className := range loadEntryClasses {
		if className == `\Handler_Save` {
			foundHandlerSave = true
		}
		if className == `\Registry` {
			foundRegistry = true
		}
	}
	if !foundHandlerSave || foundRegistry {
		t.Fatalf("Registry::load_classes array entries = %#v, want Handler_Save and no Registry fallback", loadEntryClasses)
	}
	if _, ok := engine.relevantCallables[processKey]; !ok {
		t.Fatalf("Handler_Save::process should stay relevant: %#v", engine.relevantCallables)
	}
	hasProcessEdge := false
	for _, site := range engine.callSiteEdges[runKey] {
		if site.callee == processKey {
			hasProcessEdge = true
			break
		}
	}
	if !hasProcessEdge {
		t.Fatalf("Demo::run call edges = %#v, want edge to %s", engine.callSiteEdges[runKey], processKey)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "unsafe-use" {
			continue
		}
		if !strings.HasSuffix(finding.Path, "singleton-property-registry.php") {
			continue
		}
		if finding.Start.Line != 4 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 55 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("singleton property registry dispatch finding missing: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsFinancialRefundActionWithoutCapCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "financial-refund.php"), `<?php
class UpdateHelpers {
    public static function refund_payment($payment_id) {}
}

class FinancialRefundDemo {
    public function __construct() {
        add_action('wp_ajax_demo_refund', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo-refund', 'nonce');
        UpdateHelpers::refund_payment($_POST['payment_id']);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-ajax-financial-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-ajax-financial-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.NonceChecks) == 0 {
		t.Fatalf("nonce checks = %d, want > 0", len(finding.Extra.Context.NonceChecks))
	}
}

func TestAnalyzeRootFindsFinancialCancelActionWithoutCapCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "financial-cancel.php"), `<?php
class PaymentIntents {
    public function cancel_subscription($subscription_id) {}
}

class FinancialCancelDemo {
    private $payment_intents;

    public function __construct() {
        $this->payment_intents = new PaymentIntents();
        add_action('wp_ajax_demo_cancel', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo-cancel', 'nonce');
        $this->payment_intents->cancel_subscription($_POST['subscription_id']);
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-ajax-financial-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-ajax-financial-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.NonceChecks) == 0 {
		t.Fatalf("nonce checks = %d, want > 0", len(finding.Extra.Context.NonceChecks))
	}
}

func TestAnalyzeRootFindsLateStaticAjaxRegistrationThroughInheritedInit(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "late-static-ajax.php"), `<?php
namespace Demo;

define('DEMO_PREFIX', strtolower(__NAMESPACE__));

class DemoPlugin {
    const PREFIX = DEMO_PREFIX;
}

class DemoAjaxBase {
    public static function init() {
        add_action('wp_ajax_' . static::getAction(), array(static::class, 'execute'));
    }

    protected static function getAction() {}

    public static function execute() {
        check_ajax_referer('demo-late-static', 'nonce');
        $data = static::validateData();
        $data = static::sanitizeData($data);
        static::buildResponse($data);
    }

    public static function validateData() {
        return wp_unslash($_POST['data']);
    }

    public static function sanitizeData($data) {
        return $data;
    }

    public static function buildResponse($data) {}
}

class DemoLateStaticUpdate extends DemoAjaxBase {
    protected static function getAction() {
        return DemoPlugin::PREFIX . '_late_static';
    }

    public static function sanitizeData($data) {
        return array(
            'name' => sanitize_text_field($_POST['name']),
            'value' => sanitize_text_field($_POST['value']),
        );
    }

    public static function buildResponse($data) {
        update_option($data['name'], $data['value']);
    }
}

class DemoAjaxBootstrap {
    public static function init() {
        DemoLateStaticUpdate::init();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	found := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Name == "wp_ajax_demo_late_static" {
			found = true
		}
	}
	if !found {
		t.Fatalf("entrypoints = %#v, want wp_ajax_demo_late_static", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootFindsLateStaticAjaxRegistrationThroughInheritedInitWithExplodeResetKey(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "late-static-ajax-explode.php"), `<?php
namespace Demo;

define('DEMO_PREFIX', strtolower(__NAMESPACE__));

class DemoPlugin {
    const PREFIX = DEMO_PREFIX;
}

class DemoAjaxBase {
    public static function init() {
        add_action('wp_ajax_' . static::getAction(), array(static::class, 'execute'));
    }

    protected static function getAction() {}

    public static function execute() {
        check_ajax_referer('demo-late-static', 'nonce');
        $data = static::validateData();
        $data = static::sanitizeData($data);
        static::buildResponse($data);
    }

    public static function validateData() {
        return wp_unslash($_POST['data']);
    }

    public static function sanitizeData($data) {
        return $data;
    }

    public static function buildResponse($data) {}
}

class DemoLateStaticExplodeUpdate extends DemoAjaxBase {
    protected static function getAction() {
        return DemoPlugin::PREFIX . '_late_static_explode';
    }

    public static function sanitizeData($data) {
        return array(
            'name' => $_POST['name'],
            'value' => $_POST['value'],
        );
    }

    public static function buildResponse($data) {
        $parts = explode('[', $data['name']);
        $key = reset($parts);
        update_option($key, $data['value']);
    }
}

class DemoAjaxBootstrap {
    public static function init() {
        DemoLateStaticExplodeUpdate::init();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	found := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Name == "wp_ajax_demo_late_static_explode" {
			found = true
		}
	}
	if !found {
		t.Fatalf("entrypoints = %#v, want wp_ajax_demo_late_static_explode", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootFindsLateStaticAjaxSensitiveActionFromDynamicOptionKeyOnly(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "late-static-ajax-option-key.php"), `<?php
namespace Demo;

define('DEMO_PREFIX', strtolower(__NAMESPACE__));

class DemoPlugin {
    const PREFIX = DEMO_PREFIX;
}

class DemoAjaxBase {
    public static function init() {
        add_action('wp_ajax_' . static::getAction(), array(static::class, 'execute'));
    }

    protected static function getAction() {}

    public static function execute() {
        check_ajax_referer('demo-late-static', 'nonce');
        $data = static::validateData();
        $data = static::sanitizeData($data);
        static::buildResponse($data);
    }

    public static function validateData() {
        return wp_unslash($_POST['data']);
    }

    public static function sanitizeData($data) {
        return $data;
    }

    public static function buildResponse($data) {}
}

class DemoLateStaticOptionKeyUpdate extends DemoAjaxBase {
    protected static function getAction() {
        return DemoPlugin::PREFIX . '_late_static_option_key';
    }

    public static function sanitizeData($data) {
        return array(
            'name' => sanitize_text_field($data['name']),
            'value' => wp_kses(wp_unslash($data['value']), array()),
        );
    }

    public static function buildResponse($data) {
        $parts = explode('[', $data['name']);
        $key = reset($parts);
        update_option($key, 'safe');
    }
}

class DemoAjaxBootstrap {
    public static function init() {
        DemoLateStaticOptionKeyUpdate::init();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Start.Line != 50 {
		t.Fatalf("sink line = %d, want 50", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 25 {
		t.Fatalf("source line = %d, want 25", finding.Extra.Trace.Source.Line)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 || finding.Extra.Context.EntryPoints[0].Name != "wp_ajax_demo_late_static_option_key" {
		t.Fatalf("entrypoints = %#v, want wp_ajax_demo_late_static_option_key", finding.Extra.Context.EntryPoints)
	}
}

func TestAnalyzeRootFindsLateStaticAjaxSensitiveActionAfterJSONDecodeRecursiveSanitizer(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "late-static-ajax-json-recursive-sanitizer.php"), `<?php
namespace Demo;

define('DEMO_PREFIX', strtolower(__NAMESPACE__));

class DemoPlugin {
    const PREFIX = DEMO_PREFIX;
    const AJAX_NONCE = 'demo-ajax';
    const AJAX_ARG = 'security';
}

class Helper {
    public static function sanitizeStringArray(array $array = []): array {
        if (empty($array)) {
            return $array;
        }
        foreach ($array as $key => $value) {
            if (is_object($value)) {
                $value = (array) $value;
            }
            if (is_array($value)) {
                $array[$key] = self::sanitizeStringArray($value);
                continue;
            }
            $array[$key] = sanitize_text_field($value);
        }
        return $array;
    }
}

abstract class DemoAjaxBase {
    public static function init() {
        add_action('wp_ajax_' . static::getAction(), array(static::class, 'execute'));
    }

    protected static function getAction() {}

    public static function execute() {
        check_ajax_referer(DemoPlugin::AJAX_NONCE, DemoPlugin::AJAX_ARG);
        $data = static::validateData();
        $data = static::sanitizeData($data);
        static::buildResponse($data);
    }

    public static function validateData() {
        $data = ! empty($_POST['data']) ? wp_unslash($_POST['data']) : false;
        if (is_string($data)) {
            $data = (array) json_decode($data);
            $data = Helper::sanitizeStringArray($data);
        }
        return $data;
    }

    public static function sanitizeData($data) {
        return $data;
    }

    public static function buildResponse($data) {}
}

class DemoUpdateIntegration extends DemoAjaxBase {
    protected static function getAction() {
        return DemoPlugin::PREFIX . '_update_integration';
    }

    public static function sanitizeData($data) {
        return array(
            'name' => sanitize_text_field($data['name']),
            'value' => wp_kses(wp_unslash($data['value']), array()),
            'type' => sanitize_text_field($data['type']),
        );
    }

    public static function buildResponse($data) {
        $parts = explode('[', $data['name']);
        $key = reset($parts);
        update_option($key, $data['value']);
    }
}

class DemoBootstrap {
    public static function init() {
        DemoUpdateIntegration::init();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
		t.Fatalf("check_id = %q, want wp-request-sensitive-action-without-cap-check", finding.CheckID)
	}
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	if finding.Start.Line != 77 {
		t.Fatalf("sink line = %d, want 77", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 46 {
		t.Fatalf("source line = %d, want 46", finding.Extra.Trace.Source.Line)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 || finding.Extra.Context.EntryPoints[0].Name != "wp_ajax_demo_update_integration" {
		t.Fatalf("entrypoints = %#v, want wp_ajax_demo_update_integration", finding.Extra.Context.EntryPoints)
	}
}

func TestActionSinkRelevantUseOrdersTrackReturnedRuntimeLocal(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "late-static-ajax-json-recursive-sanitizer-summary.php"), `<?php
namespace Demo;

define('DEMO_PREFIX', strtolower(__NAMESPACE__));

class DemoPlugin {
    const PREFIX = DEMO_PREFIX;
    const AJAX_NONCE = 'demo-ajax';
    const AJAX_ARG = 'security';
}

class Helper {
    public static function sanitizeStringArray(array $array = []): array {
        if (empty($array)) {
            return $array;
        }
        foreach ($array as $key => $value) {
            if (is_object($value)) {
                $value = (array) $value;
            }
            if (is_array($value)) {
                $array[$key] = self::sanitizeStringArray($value);
                continue;
            }
            $array[$key] = sanitize_text_field($value);
        }
        return $array;
    }
}

abstract class DemoAjaxBase {
    public static function init() {
        add_action('wp_ajax_' . static::getAction(), array(static::class, 'execute'));
    }

    protected static function getAction() {}

    public static function execute() {
        check_ajax_referer(DemoPlugin::AJAX_NONCE, DemoPlugin::AJAX_ARG);
        $data = static::validateData();
        $data = static::sanitizeData($data);
        static::buildResponse($data);
    }

    public static function validateData() {
        $data = ! empty($_POST['data']) ? wp_unslash($_POST['data']) : false;
        if (is_string($data)) {
            $data = (array) json_decode($data);
            $data = Helper::sanitizeStringArray($data);
        }
        return $data;
    }

    public static function sanitizeData($data) {
        return $data;
    }

    public static function buildResponse($data) {}
}

class DemoUpdateIntegration extends DemoAjaxBase {
    protected static function getAction() {
        return DemoPlugin::PREFIX . '_update_integration';
    }

    public static function sanitizeData($data) {
        return array(
            'name' => sanitize_text_field($data['name']),
            'value' => wp_kses(wp_unslash($data['value']), array()),
            'type' => sanitize_text_field($data['type']),
        );
    }

    public static function buildResponse($data) {
        $parts = explode('[', $data['name']);
        $key = reset($parts);
        update_option($key, $data['value']);
    }
}

class DemoBootstrap {
    public static function init() {
        DemoUpdateIntegration::init();
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := `method::\Demo\Helper::sanitizeStringArray`
	runtimeValidateKey := `\Demo\DemoUpdateIntegration::validatedata#runtime`
	if _, ok := engine.callables[runtimeValidateKey]; !ok {
		t.Fatalf("missing callable %q", runtimeValidateKey)
	}

	orders, _ := engine.actionSinkRelevantUseOrdersForCallable(engine.callables[runtimeValidateKey])
	if orders["data"] == 0 {
		t.Fatalf("runtime validate action orders = %+v, want data root after return", orders)
	}

	foundHelper := false
	for _, edge := range engine.forwardRelevantCallees(runtimeValidateKey, map[string]struct{}{}, map[string]struct{}{}, false) {
		if edge.callee == helperKey && edge.dataCarrier {
			foundHelper = true
			break
		}
	}
	if !foundHelper {
		t.Fatalf("forward relevant callees for %s did not keep helper edge", runtimeValidateKey)
	}
}

func TestAnalyzeRootKeepsAuthenticatedAjaxWhenLateStaticPublicFlagIsFalse(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "late-static-ajax-public-flag.php"), `<?php
namespace Demo;

define('DEMO_PREFIX', strtolower(__NAMESPACE__));

class DemoPlugin {
    const PREFIX = DEMO_PREFIX;
    const AJAX_NONCE = 'demo-ajax';
    const AJAX_ARG = 'security';
}

abstract class DemoAjaxBase {
    public static function init() {
        add_action('wp_ajax_' . static::getAction(), array(static::class, 'execute'));
        if ( static::isPublic() ) {
            add_action('wp_ajax_nopriv_' . static::getAction(), array(static::class, 'execute'));
        }
    }

    protected static function getAction() {}

    protected static function isPublic() {
        return false;
    }

    public static function execute() {
        check_ajax_referer(DemoPlugin::AJAX_NONCE, DemoPlugin::AJAX_ARG);
        $data = static::sanitizeData($_POST);
        static::buildResponse($data);
    }

    public static function sanitizeData($data) {
        return $data;
    }

    public static function buildResponse($data) {}
}

class DemoUpdateIntegration extends DemoAjaxBase {
    protected static function getAction() {
        return DemoPlugin::PREFIX . '_update_integration';
    }

    protected static function isPublic() {
        return false;
    }

    public static function sanitizeData($data) {
        return array(
            'name' => sanitize_text_field($data['name']),
            'value' => sanitize_text_field($data['value']),
        );
    }

    public static function buildResponse($data) {
        $parts = explode('[', $data['name']);
        $key = reset($parts);
        update_option($key, $data['value']);
    }
}

class DemoBootstrap {
    public static function init() {
        DemoUpdateIntegration::init();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "nonce_only" {
		t.Fatalf("access = %q, want nonce_only", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Name != "wp_ajax_demo_update_integration" {
		t.Fatalf("entrypoint = %q, want wp_ajax_demo_update_integration", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestCollectDirectCallEdgesMarksBooleanOnlyCallUse(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "boolean-call-context.php"), `<?php
namespace Demo;

function helper() {
	return 'demo';
}

function render() {
	if ( ! helper() ) {
		echo 'fallback';
	}

	$value = helper();
	echo esc_html( $value );
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	renderKey := `function::\Demo\render`
	helperKey := `function::\Demo\helper`
	var sawBooleanUse bool
	var sawValueUse bool
	for _, edge := range engine.callSiteEdges[renderKey] {
		if edge.callee != helperKey {
			continue
		}
		if edge.booleanUse {
			sawBooleanUse = true
			continue
		}
		if edge.dataCarrier {
			sawValueUse = true
		}
	}
	if !sawBooleanUse {
		t.Fatalf("call edges for %s did not mark boolean-only helper use", renderKey)
	}
	if !sawValueUse {
		t.Fatalf("call edges for %s did not keep value-carrying helper use", renderKey)
	}
}

func TestAnalyzeRootSkipsLateStaticAjaxActionWhenExecuteAddsCapabilityCheck(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "late-static-ajax-cap-check.php"), `<?php
namespace Demo;

define('DEMO_PREFIX', strtolower(__NAMESPACE__));

class DemoPlugin {
    const PREFIX = DEMO_PREFIX;
    const AJAX_NONCE = 'demo-ajax';
    const AJAX_ARG = 'security';
}

abstract class DemoAjaxBase {
    public static function init() {
        add_action('wp_ajax_' . static::getAction(), array(static::class, 'execute'));
        if ( static::isPublic() ) {
            add_action('wp_ajax_nopriv_' . static::getAction(), array(static::class, 'execute'));
        }
    }

    protected static function getAction() {}

    protected static function isPublic() {
        return false;
    }

    public static function execute() {
        check_ajax_referer(DemoPlugin::AJAX_NONCE, DemoPlugin::AJAX_ARG);
        if ( ! static::isPublic() && ! current_user_can('manage_options') ) {
            wp_die('forbidden');
        }
        $data = static::sanitizeData($_POST);
        static::buildResponse($data);
    }

    public static function sanitizeData($data) {
        return $data;
    }

    public static function buildResponse($data) {}
}

class DemoUpdateIntegration extends DemoAjaxBase {
    protected static function getAction() {
        return DemoPlugin::PREFIX . '_update_integration';
    }

    protected static function isPublic() {
        return false;
    }

    public static function sanitizeData($data) {
        return array(
            'name' => sanitize_text_field($data['name']),
            'value' => sanitize_text_field($data['value']),
        );
    }

    public static function buildResponse($data) {
        $parts = explode('[', $data['name']);
        $key = reset($parts);
        update_option($key, $data['value']);
    }
}

class DemoBootstrap {
    public static function init() {
        DemoUpdateIntegration::init();
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootDoesNotFlagCapabilityGuardedFinancialAction(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "financial-guarded.php"), `<?php
class UpdateHelpers {
    public static function refund_payment($payment_id) {}
}

class FinancialGuardedDemo {
    public function __construct() {
        add_action('wp_ajax_demo_guarded_refund', array($this, 'handle'));
    }

    public function handle() {
        check_ajax_referer('demo-guarded-refund', 'nonce');
        if ( current_user_can('manage_options') ) {
            UpdateHelpers::refund_payment($_POST['payment_id']);
        }
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsUnsafeDeserialization(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "unsafe-deserialization.php"), `<?php
function run() {
    $payload = $_POST['blob'];
    $value = unserialize($payload);
}

run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		manifest, manifestErr := parsetree.BuildManifestForRoot(root, nil, 1)
		if manifestErr != nil {
			t.Fatalf("findings = %d, want 1 (manifest err=%v)", len(result.Payload.Results), manifestErr)
		}
		files, loadErr := loadFiles(manifest, 1)
		if loadErr != nil {
			t.Fatalf("findings = %d, want 1 (load err=%v)", len(result.Payload.Results), loadErr)
		}
		engine, buildErr := buildEngine(root, files, Options{
			AllowedSinkOps: map[string]struct{}{"call": {}},
		})
		if buildErr != nil {
			t.Fatalf("findings = %d, want 1 (build err=%v)", len(result.Payload.Results), buildErr)
		}
		t.Fatalf(
			"findings = %d, want 1 ctor=%+v enable=%+v",
			len(result.Payload.Results),
			engine.summaries[`method::\\Importer::__construct`],
			engine.summaries[`method::\\Importer::enableplugins`],
		)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 4 {
		t.Fatalf("sink line = %d, want 4", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsMaybeUnsafeDeserialization(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "maybe-unsafe-deserialization.php"), `<?php
function run() {
    $payload = $_POST['blob'];
    $value = maybe_unserialize($payload);
}

run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		manifest, manifestErr := parsetree.BuildManifestForRoot(root, nil, 1)
		if manifestErr != nil {
			t.Fatalf("findings = %d, want 1 (manifest err=%v)", len(result.Payload.Results), manifestErr)
		}
		files, loadErr := loadFiles(manifest, 1)
		if loadErr != nil {
			t.Fatalf("findings = %d, want 1 (load err=%v)", len(result.Payload.Results), loadErr)
		}
		engine, buildErr := buildEngine(root, files, Options{
			AllowedSinkOps: map[string]struct{}{"call": {}},
		})
		if buildErr != nil {
			t.Fatalf("findings = %d, want 1 (build err=%v)", len(result.Payload.Results), buildErr)
		}
		t.Fatalf(
			"findings = %d, want 1 ctor=%+v enable=%+v",
			len(result.Payload.Results),
			engine.summaries[`method::\Importer::__construct`],
			engine.summaries[`method::\Importer::enableplugins`],
		)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 4 {
		t.Fatalf("sink line = %d, want 4", finding.Start.Line)
	}
}

func TestAnalyzeRootFindsMaybeUnsafeDeserializationInHookCallbackSwitchCase(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "hook-switch-maybe-unsafe-deserialization.php"), `<?php
function add_action($hook, $cb, $p=10, $argc=1) {}
function do_action($hook, ...$args) {}
function maybe_unserialize($x) { return $x; }

function demo_cb($payment, $key) {
    switch ($key) {
        case 'user_info':
            if (empty($payment->user_info)) {
                break;
            } elseif (is_string($payment->user_info)) {
                $payment->user_info = maybe_unserialize($payment->user_info);
            }
            break;
    }
}
add_action('demo_save', 'demo_cb', 10, 2);

class Demo {
    public $user_info;

    public function run() {
        $this->user_info = $_POST['data'];
        do_action('demo_save', $this, 'user_info');
    }
}

(new Demo())->run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 12 {
		t.Fatalf("sink line = %d, want 12", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 23 {
		t.Fatalf("source line = %d, want 23", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsArrayMapMaybeUnserializeCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "array-map-maybe-unserialize.php"), `<?php
function run() {
    $payload = $_POST['blob'];
    $payloads = array($payload);
    $value = array_map('maybe_unserialize', $payloads);
}

run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 5 {
		t.Fatalf("sink line = %d, want 5", finding.Start.Line)
	}
}

func TestAnalyzeRootDoesNotFlagSafeAllowedClassesFalseUnserialize(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "safe-unserialize.php"), `<?php
function run() {
    $payload = $_POST['blob'];
    $value = unserialize($payload, array('allowed_classes' => false));
}

run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsUnsafeDeserializationFromRemoteResponseBody(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "remote-unserialize.php"), `<?php
function run() {
    $request = wp_remote_get("http://example.test/?ip=" . $_GET['ip']);
    $body = wp_remote_retrieve_body($request);
    $value = unserialize($body);
}

run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Extra.Trace.Source.Line != 3 {
		t.Fatalf("source line = %d, want 3", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsUnsafeDeserializationFromDynamicFileContents(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "dynamic-file-unserialize.php"), `<?php
function run($name) {
    $path = sys_get_temp_dir() . "/" . $name;
    $value = unserialize(file_get_contents($path));
}

if (isset($_POST['restore'])) {
    run("payload.bin");
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 4 {
		t.Fatalf("sink line = %d, want 4", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 4 {
		t.Fatalf("source line = %d, want 4", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootDoesNotFlagUnsafeDeserializationFromDefinitelyStaticFileContents(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static-file-unserialize.php"), `<?php
function run() {
    $value = unserialize(file_get_contents(__DIR__ . "/payload.bin"));
}

if (isset($_POST['restore'])) {
    run();
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsUnsafeDeserializationFromConstructorSeededReceiverPath(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "constructor-receiver-unserialize.php"), `<?php
class Importer {
    public function __construct() {
        $this->map = json_decode(file_get_contents(sys_get_temp_dir() . '/.table_map'), true);
        $this->seek = &$this->map['seek'];
    }

    public function enablePlugins() {
        $plugins = unserialize($this->seek['active_plugins']);
    }
}

function handle() {
    if (isset($_POST['restore'])) {
        $importer = new Importer();
        $importer->enablePlugins();
    }
}

handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 4 {
		t.Fatalf("source line = %d, want 4", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsUnsafeDeserializationFromRequestReachableWildcardDBSelectContent(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-unserialize.php"), `<?php
class DB {
    public function get_results($query) {}
}
class Repo {
    private $db;
    public function __construct() { $this->db = new DB(); }
    public function parse_value($blob) {
        return unserialize($blob);
    }
    public function process() {
        $rows = $this->db->get_results("SELECT * FROM entry_meta");
        foreach ($rows as $row) {
            $this->parse_value($row['meta_value']);
        }
    }
}
function handle() {
    if ( isset($_POST['run']) ) {
        (new Repo())->process();
    }
}
handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 12 {
		t.Fatalf("source line = %d, want 12", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootDoesNotFlagSafeRequestReachableWildcardDBSelectUnserialize(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-safe-unserialize.php"), `<?php
class DB {
    public function get_results($query) {}
}
class Repo {
    private $db;
    public function __construct() { $this->db = new DB(); }
    public function parse_value($blob) {
        return unserialize($blob, array('allowed_classes' => false));
    }
    public function process() {
        $rows = $this->db->get_results("SELECT * FROM entry_meta");
        foreach ($rows as $row) {
            $this->parse_value($row['meta_value']);
        }
    }
}
function handle() {
    if ( isset($_POST['run']) ) {
        (new Repo())->process();
    }
}
handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsUnsafeDeserializationFromRequestReachableDynamicTableWildcardDBSelectContent(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-dynamic-table-unserialize.php"), `<?php
class DB {
    public function get_results($query, $output = null) {}
}
class Repo {
    private $db;
    public function __construct() { $this->db = new DB(); }
    public function get_columns($table) {
        return array('meta_value');
    }
    public function parse_value($blob) {
        return unserialize($blob);
    }
    public function process($table) {
        $columns = $this->get_columns($table);
        $rows = $this->db->get_results("SELECT * FROM " . $table . " LIMIT 0, 20", ARRAY_A);
        foreach ($rows as $row) {
            foreach ($columns as $column) {
                $this->parse_value($row[$column]);
            }
        }
    }
}
function handle() {
    if ( isset($_POST['run']) ) {
        (new Repo())->process('entry_meta');
    }
}
handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 12 {
		t.Fatalf("sink line = %d, want 12", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 16 {
		t.Fatalf("source line = %d, want 16", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsUnsafeDeserializationThroughRecursiveHelperFromDynamicTableWildcardDBSelectContent(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "db-recursive-dynamic-table-unserialize.php"), `<?php
class DB {
    public function get_results($query, $output = null) {}
}
class Repo {
    private $db;
    public function __construct() { $this->db = new DB(); }
    public function get_columns($table) {
        return array('meta_value');
    }
    public static function unsafe_decode($blob) {
        return unserialize($blob);
    }
    public function recursive_unserialize_replace($from = '', $to = '', $data = '', $serialised = false, $case_insensitive = false) {
        if ( is_string($data) && ($decoded = $this->unsafe_decode($data)) !== false ) {
            $data = $this->recursive_unserialize_replace($from, $to, $decoded, true, $case_insensitive);
        } elseif ( is_array($data) ) {
            $_tmp = array();
            foreach ($data as $key => $value) {
                $_tmp[$key] = $this->recursive_unserialize_replace($from, $to, $value, false, $case_insensitive);
            }
            $data = $_tmp;
        }
        return $data;
    }
    public function process($table) {
        $columns = $this->get_columns($table);
        $rows = $this->db->get_results("SELECT * FROM " . $table . " LIMIT 0, 20", ARRAY_A);
        foreach ($rows as $row) {
            foreach ($columns as $column) {
                $this->recursive_unserialize_replace('search', 'replace', $row[$column], false, false);
            }
        }
    }
}
function handle() {
    if ( isset($_POST['run']) ) {
        (new Repo())->process('entry_meta');
    }
}
handle();
`)
	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if finding.Start.Line != 12 {
		t.Fatalf("sink line = %d, want 12", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 28 {
		t.Fatalf("source line = %d, want 28", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsUnsafeDeserializationFromRequestGetterHelperChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "request-getter-helper-unserialize.php"), `<?php
class Request {
    public function getIp() {
        return $_SERVER['REMOTE_ADDR'];
    }
}

class App {
    public $request;
}

class Validator {
    private $app;

    public function __construct($app) {
        $this->app = $app;
    }

    public function validate() {
        $this->handle();
    }

    private function handle() {
        $ip = sanitize_text_field($this->app->request->getIp());
        $this->fetchCountry($ip);
    }

    private function fetchCountry($ip) {
        $request = wp_remote_get("http://example.test/?ip={$ip}");
        $body = wp_remote_retrieve_body($request);
        $value = unserialize($body);
    }
}

$app = new App();
$app->request = new Request();
$validator = new Validator($app);
$validator->validate();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "unsafe-deserialization" {
		t.Fatalf("check_id = %q, want unsafe-deserialization", finding.CheckID)
	}
	if !strings.Contains(finding.Path, "request-getter-helper-unserialize.php") {
		t.Fatalf("path = %q, want helper-chain fixture", finding.Path)
	}
}

func TestAnalyzeRootPropagatesContextThroughInternalHookRegistrar(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "internal-hook-registrar.php"), `<?php
class SaveHandler {
    public function save() {
        update_option('demo_value', $_POST['value']);
    }
}

class InternalRegistrar {
    public static function register() {
        $handler = new SaveHandler();
        add_action('demo_save', array($handler, 'save'));
    }
}

class RouterWithBusDemo {
    public function __construct() {
        add_action('wp_ajax_demo_router_bus', array($this, 'route'));
        add_action('demo_bus', array('InternalRegistrar', 'register'));
    }

    public function route() {
        do_action('demo_bus');
        do_action('demo_save');
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
	found := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Name == "wp_ajax_demo_router_bus" {
			found = true
		}
	}
	if !found {
		t.Fatalf("entrypoints = %#v, want wp_ajax_demo_router_bus", finding.Extra.Context.EntryPoints)
	}
}

func TestBuildEngineSkipsActionFilterCarrierWithoutActionRelevantUse(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-filter-noise.php"), `<?php
class ActionFilterNoiseDemo {
    public function __construct() {
        add_action('wp_ajax_demo_action_filter_noise', array($this, 'handle'));
        add_filter('demo_payload', array($this, 'normalize'));
    }

    public function handle() {
        $payload = apply_filters('demo_payload', $_POST['value']);
        update_option('demo_value', $_POST['other']);
    }

    public function normalize($payload) {
        return get_post_meta(1, '_demo_noise', true);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::\\ActionFilterNoiseDemo::normalize"]; ok {
		t.Fatalf("normalize should not stay relevant for action sinks when its returned root is not used in any action-relevant way: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsWriteCarrierWithoutWriteRelevantUse(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "write-carrier-noise.php"), `<?php
class WriteCarrierNoiseDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_write_carrier_noise', array($this, 'handle'));
    }

    public function handle() {
        $tmp = $_FILES['archive']['tmp_name'];
        $payload = $this->prepare_payload($tmp);
        $noise = $this->scan_signature($tmp);
        unzip_file($payload['file'], '/tmp/demo-write');
        if (!empty($noise['status'])) {
            strlen($noise['status']);
        }
    }

    private function prepare_payload($tmp) {
        return array('file' => $tmp);
    }

    private function scan_signature($tmp) {
        return array(
            'status' => md5($tmp),
            'details' => array('tmp' => $tmp),
        );
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::\\WriteCarrierNoiseDemo::scan_signature"]; ok {
		t.Fatalf("scan_signature should not stay relevant for write sinks when its returned root does not flow into any write-relevant use: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables["method::\\WriteCarrierNoiseDemo::prepare_payload"]; !ok {
		t.Fatalf("prepare_payload should stay relevant because its returned root feeds unzip_file")
	}
}

func TestBuildEngineKeepsActionFilterCarrierWhenResultFeedsSensitiveAction(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-filter-keep.php"), `<?php
class ActionFilterKeepDemo {
    public function __construct() {
        add_action('wp_ajax_demo_action_filter_keep', array($this, 'handle'));
        add_filter('demo_payload', array($this, 'normalize'));
    }

    public function handle() {
        $payload = apply_filters('demo_payload', $_POST['value']);
        update_option('demo_value', $payload);
    }

    public function normalize($payload) {
        return trim($payload);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::\\ActionFilterKeepDemo::normalize"]; !ok {
		t.Fatalf("normalize should stay relevant when the filter result feeds a sensitive action sink: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsReadFilterCarrierWithoutFileRelevantUse(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "read-filter-noise.php"), `<?php
class ReadFilterNoiseDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_read_filter_noise', array($this, 'handle'));
        add_filter('demo_read_payload', array($this, 'normalize'));
    }

    public function handle() {
        $payload = apply_filters('demo_read_payload', $_GET['other']);
        if (!empty($payload)) {
            strlen($payload);
        }
        return file_get_contents($_GET['path']);
    }

    public function normalize($payload) {
        return get_option('demo_roles', array());
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::\\ReadFilterNoiseDemo::normalize"]; ok {
		t.Fatalf("normalize should not stay relevant for read sinks when its returned root is not used in any file-relevant way: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables["method::\\ReadFilterNoiseDemo::handle"]; !ok {
		t.Fatalf("handle should stay relevant because it reaches file_get_contents")
	}
}

func TestBuildEngineKeepsReadFilterCarrierWhenResultFeedsReadSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "read-filter-keep.php"), `<?php
class ReadFilterKeepDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_read_filter_keep', array($this, 'handle'));
        add_filter('demo_read_path', array($this, 'normalize'));
    }

    public function handle() {
        $path = apply_filters('demo_read_path', $_GET['path']);
        return file_get_contents($path);
    }

    public function normalize($payload) {
        return trim($payload);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::\\ReadFilterKeepDemo::normalize"]; !ok {
		t.Fatalf("normalize should stay relevant because its returned root feeds file_get_contents: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsActionOnlyNonDataHelperBeforeSensitiveAction(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-helper-noise.php"), `<?php
class ActionHelperNoiseDemo {
    public function __construct() {
        add_action('wp_ajax_demo_action_helper_noise', array($this, 'handle'));
    }

    public function handle() {
        $this->note($_POST['value']);
        update_option('demo_value', $_POST['value']);
    }

    private function note($value) {
        strlen($value);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	for _, key := range engine.relevantCallOrder() {
		if key == "method::\\ActionHelperNoiseDemo::note" {
			t.Fatalf("note should not stay in action-only relevant call order when it does not feed any action-relevant use: %#v", engine.relevantCallOrder())
		}
	}
}

func TestAnalyzeRootFindsUnauthenticatedRenderCallbackExecution(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "render-callback.php"), `<?php
function acf_get_instance($name) {
    return null;
}

class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

class DemoHooks {
    public function __construct() {
        add_filter('acfe/form/prepare_form', array($this, 'prepare_form'));
        add_action('wp_ajax_nopriv_demo_render', array($this, 'render_ajax'));
    }

    public function render_ajax() {
        $form = $_POST['form'];
        apply_filters('acfe/form/prepare_form', $form);
    }

    public function prepare_form($form) {
        add_filter("acfe/form/prepare_form/form={$form['name']}", array(acf_get_instance('DemoRender'), 'prepare_form'));
        return apply_filters("acfe/form/prepare_form/form={$form['name']}", $form);
    }
}

new DemoHooks();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "render-callback-execution" {
		t.Fatalf("check_id = %q, want render-callback-execution", finding.CheckID)
	}
	if finding.Extra.Context.Access != "unauthenticated" {
		t.Fatalf("access = %q, want unauthenticated", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.EntryPoints) == 0 {
		t.Fatalf("entrypoints = 0, want at least 1")
	}
	found := false
	for _, entry := range finding.Extra.Context.EntryPoints {
		if entry.Name == "wp_ajax_nopriv_demo_render" {
			found = true
		}
	}
	if !found {
		t.Fatalf("entrypoints = %#v, want wp_ajax_nopriv_demo_render", finding.Extra.Context.EntryPoints)
	}
}

func TestBuildEngineDoesNotSeedLiteralCallbackHelpersAsCallSinks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "literal-callback-helper.php"), `<?php
function acf_get_instance($name) {
    return null;
}

class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

class DemoHooks {
    public function __construct() {
        add_filter('acfe/form/prepare_form', array($this, 'prepare_form'));
        add_shortcode('demo', array($this, 'render_shortcode'));
    }

    public function render_shortcode($atts) {
        $atts['name'] = 'demo';
        return apply_filters('acfe/form/prepare_form', $atts);
    }

    public function prepare_form($form) {
        add_filter("acfe/form/prepare_form/form={$form['name']}", array(acf_get_instance('DemoRender'), 'prepare_form'));
        return apply_filters("acfe/form/prepare_form/form={$form['name']}", $form);
    }
}

function unrelated_literal_callback_helper($value) {
    return call_user_func('trim', $value);
}

new DemoHooks();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["function::\\unrelated_literal_callback_helper"]; ok {
		t.Fatalf("literal callback helper should not be marked relevant for call sinks: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsCallSinkBookkeepingHelpers(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-bookkeeping-helper.php"), `<?php
function acfe_add_context($name, $value) {}

function helper_expensive($groups) {
    return $groups;
}

class DemoRender {
    public function get_form_fields_keys($form) {
        return helper_expensive($form['field_groups']);
    }

    public function prepare_form($form) {
        $mapped_fields = $this->get_form_fields_keys($form);
        acfe_add_context('mapped_fields', $mapped_fields);
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

function demo_shortcode($atts) {
    $form = array(
        'render' => $atts['render'],
        'field_groups' => array('group_demo'),
    );
    return (new DemoRender())->prepare_form($form);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::\\DemoRender::get_form_fields_keys"]; ok {
		t.Fatalf("get_form_fields_keys should not be marked relevant for call sinks when only used for bookkeeping: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables["function::\\helper_expensive"]; ok {
		t.Fatalf("helper_expensive should not be marked relevant for call sinks when only used for bookkeeping: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsUnreachableDynamicCallHelpersForCallSinks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-unreachable-helper.php"), `<?php
class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

function dead_dynamic_helper($callback) {
    call_user_func_array($callback, array('unused'));
}

function demo_shortcode($atts) {
    $form = array(
        'render' => $atts['render'],
    );
    return (new DemoRender())->prepare_form($form);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["function::\\dead_dynamic_helper"]; ok {
		t.Fatalf("dead dynamic helper should not be marked relevant for call sinks without request reachability: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsPublicDynamicCallSeedWithoutRequestSignal(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-public-no-request.php"), `<?php
function add_shortcode($tag, $callback) {}

class DemoSafe {
    public static function render($value) {
        return trim($value);
    }
}

class DemoPublic {
    private $callbacks;

    public function __construct() {
        $this->callbacks = array(
            'render' => array('DemoSafe', 'render'),
        );
        add_shortcode('demo', array($this, 'render'));
    }

    public function render() {
        return call_user_func($this->callbacks['render'], 'safe');
    }
}

new DemoPublic();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::\\DemoPublic::render"]; ok {
		t.Fatalf("public dynamic helper without request signal should not seed call relevance: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsLiteralOnlyDynamicCallHelperForRequestReachableCaller(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-literal-only-helper.php"), `<?php
function add_shortcode($tag, $callback) {}

function helper_dynamic($callback) {
    return call_user_func($callback, 'safe');
}

function demo_shortcode($atts) {
    return helper_dynamic('trim');
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["function::\\helper_dynamic"]; ok {
		t.Fatalf("literal-only dynamic helper should not be marked relevant for call sinks: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineKeepsRuntimeArgDynamicCallHelperForRequestReachableCaller(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-runtime-helper.php"), `<?php
function add_shortcode($tag, $callback) {}

function helper_dynamic($callback) {
    return call_user_func($callback, 'safe');
}

function demo_shortcode($atts) {
    return helper_dynamic($atts['callback']);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["function::\\helper_dynamic"]; !ok {
		t.Fatalf("runtime-arg dynamic helper should stay relevant for call sinks: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsLiteralOnlyDynamicCallHelperForCallInputConsumption(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-input-literal-only-helper.php"), `<?php
function add_shortcode($tag, $callback) {}

function helper_dynamic($callback) {
    return call_user_func($callback, 'safe');
}

function demo_shortcode($atts) {
    return helper_dynamic('trim');
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if engine.callInputConsumingCallables["function::\\demo_shortcode"] {
		t.Fatalf("literal-only wrapper should not be marked as consuming call input: %#v", engine.callInputConsumingCallables)
	}
}

func TestBuildEngineKeepsRuntimeArgDynamicCallHelperForCallInputConsumption(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-input-runtime-helper.php"), `<?php
function add_shortcode($tag, $callback) {}

function helper_dynamic($callback) {
    return call_user_func($callback, 'safe');
}

function demo_shortcode($atts) {
    return helper_dynamic($atts['callback']);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if !engine.callInputConsumingCallables["function::\\demo_shortcode"] {
		t.Fatalf("runtime-arg wrapper should stay marked as consuming call input: %#v", engine.callInputConsumingCallables)
	}
}

func TestBuildEngineSkipsOmittedDefaultDynamicCallHelperForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-input-omitted-default-helper.php"), `<?php
function add_shortcode($tag, $callback) {}

function helper_dynamic_default($value, $callback = 'trim') {
    if (is_callable($callback)) {
        return call_user_func($callback, $value);
    }
    return trim($value);
}

function demo_shortcode($atts) {
    return helper_dynamic_default($atts['name']);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if engine.callInputConsumingCallables["function::\\demo_shortcode"] {
		t.Fatalf("omitted default callback wrapper should not be marked as consuming call input: %#v", engine.callInputConsumingCallables)
	}
	if _, ok := engine.relevantCallables["function::\\demo_shortcode"]; ok {
		t.Fatalf("omitted default callback wrapper should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables["function::\\helper_dynamic_default"]; ok {
		t.Fatalf("helper with omitted dangerous default arg should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsLiteralOnlyParamSinkWrapperForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-literal-param-sink.php"), `<?php
function add_shortcode($tag, $callback) {}

function helper_param_sink($blob) {
    return unserialize($blob);
}

function demo_shortcode($atts) {
    return helper_param_sink('a:0:{}');
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if engine.callInputConsumingCallables["function::\\demo_shortcode"] {
		t.Fatalf("literal-only param sink wrapper should not be marked as consuming call input: %#v", engine.callInputConsumingCallables)
	}
	if _, ok := engine.relevantCallables["function::\\demo_shortcode"]; ok {
		t.Fatalf("literal-only param sink wrapper should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables["function::\\helper_param_sink"]; ok {
		t.Fatalf("literal-only param sink helper should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineKeepsRuntimeParamSinkWrapperForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-runtime-param-sink.php"), `<?php
function add_shortcode($tag, $callback) {}

function helper_param_sink($blob) {
    return unserialize($blob);
}

function demo_shortcode($atts) {
    return helper_param_sink($atts['blob']);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if !engine.callInputConsumingCallables["function::\\demo_shortcode"] {
		t.Fatalf("runtime param sink wrapper should stay marked as consuming call input: %#v", engine.callInputConsumingCallables)
	}
	if _, ok := engine.relevantCallables["function::\\demo_shortcode"]; !ok {
		t.Fatalf("runtime param sink wrapper should stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables["function::\\helper_param_sink"]; !ok {
		t.Fatalf("runtime param sink helper should stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsUnrelatedParamDirectSinkWrapperForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-unrelated-param-sink.php"), `<?php
function add_shortcode($tag, $callback) {}

function helper_indirect_sink($query_args) {
    $callback = 'trim';
    $rows = array('demo');
    return array_map($callback, $rows);
}

function demo_shortcode($atts) {
    return helper_indirect_sink($atts['query']);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if engine.callInputConsumingCallables["function::\\helper_indirect_sink"] {
		t.Fatalf("indirect sink helper with unrelated param should not be marked as consuming call input: %#v", engine.callInputConsumingCallables)
	}
	if _, ok := engine.relevantCallables["function::\\demo_shortcode"]; ok {
		t.Fatalf("wrapper for unrelated-param direct sink should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables["function::\\helper_indirect_sink"]; ok {
		t.Fatalf("indirect sink helper with unrelated param should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestSummaryForKeySkipsWarmOfNonRelevantHelperInPureCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-nonrelevant-warm.php"), `<?php
function helper_passthrough($value) {
    return $value;
}

function wrapper($value) {
    return helper_passthrough($value);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := "function::\\helper_passthrough"
	wrapperKey := "function::\\wrapper"
	if !summaryHasNoEffects(engine.summaries[helperKey]) {
		t.Fatalf("expected helper summary to start empty, got %#v", engine.summaries[helperKey])
	}

	state := analysisState{
		engine:                  engine,
		current:                 engine.callables[wrapperKey],
		summaryWarmCache:        map[string]summary{},
		summaryWarmStack:        map[string]struct{}{wrapperKey: {}},
		summaryReturnPathCache:  map[string]map[string]originSet{},
		summaryReturnPathActive: map[string]struct{}{},
	}
	if warmed := state.summaryForKey(helperKey); !summaryHasNoEffects(warmed) {
		t.Fatalf("non-relevant helper should not warm in pure call batch, got %#v", warmed)
	}

	engine.relevantCallables[helperKey] = struct{}{}
	state = analysisState{
		engine:                  engine,
		current:                 engine.callables[wrapperKey],
		summaryWarmCache:        map[string]summary{},
		summaryWarmStack:        map[string]struct{}{wrapperKey: {}},
		summaryReturnPathCache:  map[string]map[string]originSet{},
		summaryReturnPathActive: map[string]struct{}{},
	}
	warmed := state.summaryForKey(helperKey)
	if summaryHasNoEffects(warmed) || len(warmed.ReturnParams) == 0 || warmed.ReturnParams[0] != 0 {
		t.Fatalf("relevant helper should still warm normally, got %#v", warmed)
	}
}

func TestSummaryForKeyWarmsSpecializedHelperWhenBaseIsRelevantInPureCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-specialized-relevant-warm.php"), `<?php
function helper_passthrough($tag, $value) {
    if ($tag === 'demo') {
        return $value;
    }
    return null;
}

function wrapper($value) {
    return helper_passthrough('demo', $value);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	baseKey := "function::\\helper_passthrough"
	wrapperKey := "function::\\wrapper"
	engine.currentBatchName = "call"
	specializedKey := engine.maybeSpecializeCallableForLiteralArgs(baseKey, map[int]string{0: "demo"})
	if specializedKey == "" || specializedKey == baseKey {
		t.Fatalf("expected specialized helper key for %s, got %q", baseKey, specializedKey)
	}
	if !summaryHasNoEffects(engine.summaries[specializedKey]) {
		t.Fatalf("expected specialized helper summary to start empty, got %#v", engine.summaries[specializedKey])
	}

	state := analysisState{
		engine:                  engine,
		current:                 engine.callables[wrapperKey],
		summaryWarmCache:        map[string]summary{},
		summaryWarmStack:        map[string]struct{}{wrapperKey: {}},
		summaryReturnPathCache:  map[string]map[string]originSet{},
		summaryReturnPathActive: map[string]struct{}{},
	}
	if warmed := state.summaryForKey(specializedKey); !summaryHasNoEffects(warmed) {
		t.Fatalf("non-relevant specialized helper should not warm in pure call batch, got %#v", warmed)
	}

	engine.relevantCallables[baseKey] = struct{}{}
	state = analysisState{
		engine:                  engine,
		current:                 engine.callables[wrapperKey],
		summaryWarmCache:        map[string]summary{},
		summaryWarmStack:        map[string]struct{}{wrapperKey: {}},
		summaryReturnPathCache:  map[string]map[string]originSet{},
		summaryReturnPathActive: map[string]struct{}{},
	}
	warmed := state.summaryForKey(specializedKey)
	if summaryHasNoEffects(warmed) || len(warmed.ReturnParams) == 0 || warmed.ReturnParams[0] != 1 {
		t.Fatalf("specialized helper should warm when base helper is relevant, got %#v", warmed)
	}
}

func TestSummaryForKeySkipsNonRelevantHelperInPureActionBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-helper-warm.php"), `<?php
function update_option($k, $v) {}

function helper_passthrough($value) {
    return $value;
}

function dispatcher() {
    update_option('demo', helper_passthrough($_POST['value']));
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := "function::\\helper_passthrough"
	dispatcherKey := "function::\\dispatcher"
	if !summaryHasNoEffects(engine.summaries[helperKey]) {
		t.Fatalf("expected helper summary to start empty, got %#v", engine.summaries[helperKey])
	}
	if _, ok := engine.relevantCallables[helperKey]; ok {
		t.Fatalf("helper should not stay relevant in pure action analysis: %#v", engine.relevantCallables)
	}

	state := analysisState{
		engine:                  engine,
		current:                 engine.callables[dispatcherKey],
		summaryWarmCache:        map[string]summary{},
		summaryWarmStack:        map[string]struct{}{dispatcherKey: {}},
		summaryReturnPathCache:  map[string]map[string]originSet{},
		summaryReturnPathActive: map[string]struct{}{},
	}
	if warmed := state.summaryForKey(helperKey); !summaryHasNoEffects(warmed) {
		t.Fatalf("non-relevant helper should not warm in pure action batch, got %#v", warmed)
	}
}

func TestCallableNeedsFileWarmSummaryKeepsDirectRequestWrapperThatCallsReadHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "read-wrapper.php"), `<?php
function leaf($path) {
    return file_get_contents($path);
}

function wrapper() {
    $path = $_GET['path'];
    leaf($path);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if !engine.callableNeedsFileWarmSummary("function::\\wrapper") {
		t.Fatalf("request-backed wrapper that calls a read helper should stay warm-summary relevant")
	}
}

func TestCallableNeedsFileWarmSummarySkipsNonReturningDirectRequestTemplateHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "read-template-helper.php"), `<?php
function helper($rows) {
    $user_id = isset($_REQUEST['user_id']) ? $_REQUEST['user_id'] : 0;
    foreach ($rows as $row) {
        echo $row . $user_id;
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if engine.callableNeedsFileWarmSummary("function::\\helper") {
		t.Fatalf("non-returning direct-request template helper should not require a full file-batch warm summary")
	}
}

func TestCallableNeedsOutputWarmSummarySkipsPassthroughHelperAndKeepsFinding(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-helper.php"), `<?php
function add_shortcode($tag, $callback) {}
function wp_kses($value, $allow = array()) { return $value; }
class DB {
    public function get_results($query) {}
}

class Demo {
    public function boot() {
        add_shortcode('demo', array($this, 'render'));
    }

    private function passthrough_first($row) {
        return $row->text;
    }

    public function render($atts) {
        $rows = (new DB())->get_results("SELECT * FROM reviews");
        $text = $this->passthrough_first($rows[0]);
        return wp_kses($text, array('div' => array('class' => true)));
    }
}

(new Demo())->boot();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := engine.lookupMethodKey(`\Demo`, "passthrough_first")
	if helperKey == "" {
		t.Fatal("missing helper key")
	}
	if engine.callableNeedsOutputWarmSummary(helperKey) {
		t.Fatalf("simple passthrough output helper should not require a full warm summary")
	}
}

func TestCallableNeedsOutputWarmSummaryKeepsPublicMarkupHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-markup-helper.php"), `<?php
class DB {
    public function get_results($query) {}
}

function helper() {
    $rows = (new DB())->get_results("SELECT * FROM reviews");
    echo $rows[0]->text;
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := engine.lookupFunctionKey("", "helper")
	if helperKey == "" {
		t.Fatal("missing helper key")
	}
	if !engine.callableNeedsOutputWarmSummary(helperKey) {
		t.Fatalf("record-read output helper should stay output warm-summary relevant")
	}
}

func TestAnalyzeCallableOutputFilterReplaySkipsCallbackStorageSideEffects(t *testing.T) {
	e := &engine{
		summaries: map[string]summary{
			"function::\\filter_cb": {
				ReturnParams: []int{0},
				StorageWrites: map[string]taintSummary{
					"option_value": {Params: []int{0}},
				},
			},
		},
	}
	s := &analysisState{
		engine:            e,
		current:           callable{Key: "function::\\render"},
		sourceHits:        map[string]findingRecord{},
		paramSinks:        map[int]map[string]sinkTemplate{},
		receiverSinks:     map[string]sinkTemplate{},
		staticPropTaint:   map[string]originSet{},
		propTaint:         map[string]originSet{},
		receiverWrites:    map[string]originSet{},
		storageWrites:     map[string]originSet{},
		storagePathWrites: map[string]originSet{},
	}

	arg := makeOriginSet(origin{kind: originParam, paramIdx: 0})
	returned := s.instantiateSummaryReturnWithOptions("function::\\filter_cb", []originSet{arg}, nil, "", true, false, 0)
	if len(returned) == 0 {
		t.Fatal("output filter replay should keep returned origins")
	}
	if len(s.storageWrites) != 0 || len(s.storagePathWrites) != 0 {
		t.Fatalf("output filter replay should skip callback storage side effects: %+v %+v", s.storageWrites, s.storagePathWrites)
	}

	s.storageWrites = map[string]originSet{}
	s.storagePathWrites = map[string]originSet{}
	returned = s.instantiateSummaryReturnWithOptions("function::\\filter_cb", []originSet{arg}, nil, "", true, true, 0)
	if len(returned) == 0 {
		t.Fatal("callback replay with state side effects should still keep returned origins")
	}
	if len(s.storageWrites) == 0 {
		t.Fatalf("callback replay should keep storage side effects when enabled: %+v", s.storageWrites)
	}
}

func TestInstantiateSummaryReturnWithOptionsSkipsPurePersistentReadParameterizedOutputStorageWrites(t *testing.T) {
	helperKey := `function::\helper`
	e := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		summaries: map[string]summary{
			helperKey: {
				ReturnParams: []int{0},
				StorageWrites: map[string]taintSummary{
					"option_value": {Params: []int{0}},
				},
			},
		},
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	s := &analysisState{
		engine:            e,
		current:           callable{Key: "function::\\render"},
		sourceHits:        map[string]findingRecord{},
		paramSinks:        map[int]map[string]sinkTemplate{},
		receiverSinks:     map[string]sinkTemplate{},
		staticPropTaint:   map[string]originSet{},
		propTaint:         map[string]originSet{},
		receiverWrites:    map[string]originSet{},
		storageWrites:     map[string]originSet{},
		storagePathWrites: map[string]originSet{},
	}

	args := []originSet{makeOriginSet(origin{
		kind:           originSource,
		source:         Location{Path: "demo.php", Line: 1},
		persistentRead: true,
	})}
	returned := s.instantiateSummaryReturnWithOptions(helperKey, args, nil, "", true, true, 0)
	if len(returned) == 0 {
		t.Fatal("instantiated return should be preserved")
	}
	if len(s.storageWrites) != 0 || len(s.storagePathWrites) != 0 {
		t.Fatalf("pure persistent-read parameterized output storage writes should be skipped: %+v %+v", s.storageWrites, s.storagePathWrites)
	}
}

func TestInstantiateSummaryReturnWithOptionsKeepsParameterizedOutputStorageWritesForParamOrigins(t *testing.T) {
	helperKey := `function::\helper`
	e := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		summaries: map[string]summary{
			helperKey: {
				ReturnParams: []int{0},
				StorageWrites: map[string]taintSummary{
					"option_value": {Params: []int{0}},
				},
			},
		},
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	s := &analysisState{
		engine:            e,
		current:           callable{Key: "function::\\render"},
		sourceHits:        map[string]findingRecord{},
		paramSinks:        map[int]map[string]sinkTemplate{},
		receiverSinks:     map[string]sinkTemplate{},
		staticPropTaint:   map[string]originSet{},
		propTaint:         map[string]originSet{},
		receiverWrites:    map[string]originSet{},
		storageWrites:     map[string]originSet{},
		storagePathWrites: map[string]originSet{},
	}

	args := []originSet{makeOriginSet(origin{kind: originParam, paramIdx: 0})}
	returned := s.instantiateSummaryReturnWithOptions(helperKey, args, nil, "", true, true, 0)
	if len(returned) == 0 {
		t.Fatal("instantiated return should be preserved")
	}
	if len(s.storageWrites) == 0 {
		t.Fatalf("parameterized output storage writes should be kept for param origins: %+v", s.storageWrites)
	}
}

func TestAnalysisStateFilterCurrentBatchStorageEffectsSkipsOutputRecordReadHelper(t *testing.T) {
	storageWrites := map[string]taintSummary{
		"option_value": {Params: []int{0}},
	}
	storagePathWrites := map[string]taintSummary{
		"option_value[um_noise]": {Params: []int{0}},
	}
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			"function::\\helper": {Key: "function::\\helper"},
		},
		recordReadCallables: map[string]struct{}{
			"function::\\helper": {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}

	filteredWrites, filteredPathWrites := state.filterCurrentBatchStorageEffects(storageWrites, storagePathWrites)
	if filteredWrites != nil || filteredPathWrites != nil {
		t.Fatalf("output record-read helper should suppress storage side effects: %+v %+v", filteredWrites, filteredPathWrites)
	}
}

func TestAnalysisStateFilterCurrentBatchStorageEffectsSkipsOutputRecordReadHelperInAllOps(t *testing.T) {
	storageWrites := map[string]taintSummary{
		"option_value": {Params: []int{0}},
	}
	storagePathWrites := map[string]taintSummary{
		"option_value[um_noise]": {Params: []int{0}},
	}
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}, "call": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			"function::\\helper": {Key: "function::\\helper"},
		},
		recordReadCallables: map[string]struct{}{
			"function::\\helper": {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}

	filteredWrites, filteredPathWrites := state.filterCurrentBatchStorageEffects(storageWrites, storagePathWrites)
	if filteredWrites != nil || filteredPathWrites != nil {
		t.Fatalf("all-ops output record-read helper should suppress storage side effects: %+v %+v", filteredWrites, filteredPathWrites)
	}
}

func TestAnalysisStateFilterCurrentBatchStorageEffectsKeepsNonRecordReadHelper(t *testing.T) {
	storageWrites := map[string]taintSummary{
		"option_value": {Params: []int{0}},
	}
	storagePathWrites := map[string]taintSummary{
		"option_value[um_noise]": {Params: []int{0}},
	}
	engine := &engine{
		allowedSinkOps: map[string]struct{}{"output": {}},
		callables: map[string]callable{
			"function::\\helper": {Key: "function::\\helper"},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: "function::\\helper"},
	}

	filteredWrites, filteredPathWrites := state.filterCurrentBatchStorageEffects(storageWrites, storagePathWrites)
	if len(filteredWrites) == 0 || len(filteredPathWrites) == 0 {
		t.Fatalf("non-record-read helper should keep storage side effects: %+v %+v", filteredWrites, filteredPathWrites)
	}
}

func TestAnalysisStateFilterCurrentBatchStorageEffectsFiltersNonPathFileBatchStorageWrites(t *testing.T) {
	storageWrites := map[string]taintSummary{
		"option_value":                {Params: []int{0}},
		"option_value[template_path]": {Params: []int{0}},
		"option_value[display_name]":  {Params: []int{0}},
	}
	storagePathWrites := map[string]taintSummary{
		"option_value[template_path]": {Params: []int{0}},
		"option_value[display_name]":  {Params: []int{0}},
	}
	state := &analysisState{
		engine: &engine{
			allowedSinkOps:   map[string]struct{}{"include": {}},
			currentBatchName: "include",
		},
	}

	filteredWrites, filteredPathWrites := state.filterCurrentBatchStorageEffects(storageWrites, storagePathWrites)
	if _, ok := filteredWrites["option_value[display_name]"]; ok {
		t.Fatalf("file batch should drop non-path storage writes: %+v", filteredWrites)
	}
	if _, ok := filteredPathWrites["option_value[display_name]"]; ok {
		t.Fatalf("file batch should drop non-path storage path writes: %+v", filteredPathWrites)
	}
	if _, ok := filteredWrites["option_value[template_path]"]; !ok {
		t.Fatalf("file batch should keep path-like storage writes: %+v", filteredWrites)
	}
	if _, ok := filteredPathWrites["option_value[template_path]"]; !ok {
		t.Fatalf("file batch should keep path-like storage path writes: %+v", filteredPathWrites)
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsReturnOnlyRecordReadHelper(t *testing.T) {
	helperKey := `function::\helper`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 1}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}

	if state.allowCurrentBatchStateSideEffectsForCall(helperKey, item, nil, "") {
		t.Fatal("return-only output helper should skip state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallKeepsParameterizedRecordReadHelper(t *testing.T) {
	helperKey := `function::\helper`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 1}},
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{kind: originParam, paramIdx: 0})}

	if !state.allowCurrentBatchStateSideEffectsForCall(helperKey, item, args, "") {
		t.Fatal("parameterized output helper should keep state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsPersistentReadArgs(t *testing.T) {
	helperKey := `function::\helper`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 1}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}
	args := []originSet{makeOriginSet(origin{kind: originSource, persistentRead: true})}

	if state.allowCurrentBatchStateSideEffectsForCall(helperKey, item, args, "") {
		t.Fatal("persistent-read-only arguments should not force output state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsPurePersistentReadStorageWritesEvenWithParamArgs(t *testing.T) {
	helperKey := `function::\helper`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 1}},
		StorageWrites: map[string]taintSummary{
			"option_value": {
				SourceOrigins: []sourceOriginRef{{
					Location:       Location{Path: "demo.php", Line: 1},
					PersistentRead: true,
				}},
			},
		},
	}
	args := []originSet{makeOriginSet(origin{kind: originParam, paramIdx: 0})}

	if state.allowCurrentBatchStateSideEffectsForCall(helperKey, item, args, "") {
		t.Fatal("pure persistent-read storage writes should not force output state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsThisReceiverRecordReadHelper(t *testing.T) {
	helperKey := `method::\Demo::helper`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `method::\Demo::render`, Class: `\Demo`},
	}
	item := summary{
		ReturnSources: []Location{{Path: "demo.php", Line: 1}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}

	if state.allowCurrentBatchStateSideEffectsForCall(helperKey, item, nil, "this") {
		t.Fatal("record-read method returning output should skip state side effects even on this receiver")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsPersistentReadWrapperWithoutDirectRecordRead(t *testing.T) {
	helperKey := `function::\helper`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		ReturnSourceOrigins: []sourceOriginRef{{
			Location:       Location{Path: "demo.php", Line: 1},
			PersistentRead: true,
		}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}

	if state.allowCurrentBatchStateSideEffectsForCall(helperKey, item, nil, "") {
		t.Fatal("persistent-read-only wrapper should skip output state side effects without direct record-read indexing")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsPersistentReadWrapperWithoutDirectRecordReadInAllOps(t *testing.T) {
	helperKey := `function::\helper`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}, "call": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		ReturnSourceOrigins: []sourceOriginRef{{
			Location:       Location{Path: "demo.php", Line: 1},
			PersistentRead: true,
		}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}

	if state.allowCurrentBatchStateSideEffectsForCall(helperKey, item, nil, "") {
		t.Fatal("all-ops output wrapper should skip persistent-read-only state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsStorageOnlyDirectOutputCaller(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-storage-only-callee.php"), `<?php
function mutate($value) {
    update_option('um_noise', $value);
}
function render() {
    mutate($_GET['value']);
    echo 'ok';
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadFamiliesByCallable[renderKey] = nil
	engine.storageReadBucketsByCallable[renderKey] = nil
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if state.allowCurrentBatchStateSideEffectsForCall(`function::\mutate`, item, args, "") {
		t.Fatalf(
			"terminal direct-output caller should skip storage-only callee side effects: storageOnly=%v directOutput=%v families=%d buckets=%d",
			summaryHasOnlyStorageEffects(item),
			engine.callableHasDirectOutputSyntax(engine.callables[renderKey]),
			len(engine.storageReadFamiliesByCallable[renderKey]),
			len(engine.storageReadBucketsByCallable[renderKey]),
		)
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallKeepsStorageOnlyDirectOutputCallerWithStorageRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-storage-read-callee.php"), `<?php
function mutate($value) {
    update_option('um_noise', $value);
}
function render() {
    mutate($_GET['value']);
    echo get_option('um_noise');
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadBucketsByCallable[renderKey] = map[string]struct{}{
		"option_value[um_noise]": {},
	}
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if !state.allowCurrentBatchStateSideEffectsForCall(`function::\mutate`, item, args, "") {
		t.Fatal("direct-output caller with storage read should keep storage-only callee side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallSkipsStorageOnlyDirectDeleteRenderer(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-storage-only-renderer.php"), `<?php
function mutate($value) {
    update_option('um_noise', $value);
}
function render() {
    mutate($_GET['value']);
    echo 'ok';
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "delete"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadFamiliesByCallable[renderKey] = nil
	engine.storageReadBucketsByCallable[renderKey] = nil
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if state.allowCurrentBatchStateSideEffectsForCall(`function::\mutate`, item, args, "") {
		t.Fatal("direct delete-batch renderer should skip unrelated storage-only callee side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallKeepsStorageOnlyDirectDeleteRendererWithStorageRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-storage-read-renderer.php"), `<?php
function mutate($value) {
    update_option('um_noise', $value);
}
function render() {
    mutate($_GET['value']);
    echo get_option('um_noise');
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "delete"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadBucketsByCallable[renderKey] = map[string]struct{}{
		"option_value[um_noise]": {},
	}
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if !state.allowCurrentBatchStateSideEffectsForCall(`function::\mutate`, item, args, "") {
		t.Fatal("direct delete-batch renderer with matching storage read should keep callee side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplaySkipsStorageOnlyDirectOutputCaller(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-callback-storage-only.php"), `<?php
function render() {
    echo $_GET['value'];
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadFamiliesByCallable[renderKey] = nil
	engine.storageReadBucketsByCallable[renderKey] = nil
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if state.allowCurrentBatchStateSideEffectsForCallbackReplay(`function::\callback`, item, args) {
		t.Fatal("direct-output caller should skip storage-only callback state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplaySkipsStorageOnlyDirectDeleteRenderer(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-callback-storage-only.php"), `<?php
function render() {
    echo $_GET['value'];
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "delete"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadFamiliesByCallable[renderKey] = nil
	engine.storageReadBucketsByCallable[renderKey] = nil
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if state.allowCurrentBatchStateSideEffectsForCallbackReplay(`function::\callback`, item, args) {
		t.Fatal("direct delete-batch renderer should skip unrelated storage-only callback state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplayKeepsStorageOnlyDirectDeleteRendererWithStorageRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-callback-storage-read.php"), `<?php
function render() {
    echo get_option('um_noise');
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "delete"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadBucketsByCallable[renderKey] = map[string]struct{}{
		"option_value[um_noise]": {},
	}
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if !state.allowCurrentBatchStateSideEffectsForCallbackReplay(`function::\callback`, item, args) {
		t.Fatal("direct delete-batch renderer with matching storage read should keep callback side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplayKeepsStorageOnlyDirectOutputCallerWithStorageRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-callback-storage-read.php"), `<?php
function render() {
    echo get_option('um_noise');
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadBucketsByCallable[renderKey] = map[string]struct{}{
		"option_value[um_noise]": {},
	}
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if !state.allowCurrentBatchStateSideEffectsForCallbackReplay(`function::\callback`, item, args) {
		t.Fatal("direct-output caller with storage read should keep storage-only callback side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplaySkipsStorageOnlyDirectOutputCallerWithUnrelatedStorageRead(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-callback-unrelated-storage-read.php"), `<?php
function render() {
    echo get_user_meta(1, 'avatar', true);
}
render();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	engine.currentBatchName = "output"

	renderKey := engine.lookupFunctionKey("", "render")
	if renderKey == "" {
		t.Fatal("missing render key")
	}
	engine.storageReadBucketsByCallable[renderKey] = map[string]struct{}{
		"user_meta_value[*][avatar]": {},
	}
	state := &analysisState{
		engine:  engine,
		current: engine.callables[renderKey],
	}
	item := summary{
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 1},
	})}

	if state.allowCurrentBatchStateSideEffectsForCallbackReplay(`function::\callback`, item, args) {
		t.Fatal("direct-output caller with unrelated storage read should skip storage-only callback side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplaySkipsPersistentReadOnlySourceCallback(t *testing.T) {
	helperKey := `function::\callback`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		SourceFindings: []findingRecord{{
			RuleID:   "wp-stored-xss-persistent-read-to-output",
			Source:   Location{Path: "demo.php", Line: 1},
			Sink:     Location{Path: "demo.php", Line: 2},
			Callable: `function::\callback`,
		}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}

	if state.allowCurrentBatchStateSideEffectsForCallbackReplay(helperKey, item, nil) {
		t.Fatal("persistent-read-only source callback should skip output state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplaySkipsPersistentReadOnlySourceCallbackInAllOps(t *testing.T) {
	helperKey := `function::\callback`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}, "call": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		SourceFindings: []findingRecord{{
			RuleID:   "wp-stored-xss-persistent-read-to-output",
			Source:   Location{Path: "demo.php", Line: 1},
			Sink:     Location{Path: "demo.php", Line: 2},
			Callable: `function::\callback`,
		}},
		StorageWrites: map[string]taintSummary{
			"option_value": {},
		},
	}

	if state.allowCurrentBatchStateSideEffectsForCallbackReplay(helperKey, item, nil) {
		t.Fatal("all-ops output callback should skip persistent-read-only state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplayKeepsParameterizedCallback(t *testing.T) {
	helperKey := `function::\callback`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		SourceFindings: []findingRecord{{
			RuleID:   "wp-stored-xss-persistent-read-to-output",
			Source:   Location{Path: "demo.php", Line: 1},
			Sink:     Location{Path: "demo.php", Line: 2},
			Callable: `function::\callback`,
		}},
		StorageWrites: map[string]taintSummary{
			"option_value": {Params: []int{0}},
		},
	}
	args := []originSet{makeOriginSet(origin{kind: originParam, paramIdx: 0})}

	if !state.allowCurrentBatchStateSideEffectsForCallbackReplay(helperKey, item, args) {
		t.Fatal("parameterized output callback should keep state side effects")
	}
}

func TestAllowCurrentBatchStateSideEffectsForCallbackReplaySkipsPurePersistentReadStorageWritesEvenWithParamArgs(t *testing.T) {
	helperKey := `function::\callback`
	engine := &engine{
		allowedSinkOps:   map[string]struct{}{"output": {}},
		currentBatchName: "output",
		callables: map[string]callable{
			helperKey: {Key: helperKey},
		},
		recordReadCallables: map[string]struct{}{
			helperKey: {},
		},
	}
	state := &analysisState{
		engine:  engine,
		current: callable{Key: `function::\render`},
	}
	item := summary{
		SourceFindings: []findingRecord{{
			RuleID:   "wp-stored-xss-persistent-read-to-output",
			Source:   Location{Path: "demo.php", Line: 1},
			Sink:     Location{Path: "demo.php", Line: 2},
			Callable: `function::\callback`,
		}},
		StorageWrites: map[string]taintSummary{
			"option_value": {
				SourceOrigins: []sourceOriginRef{{
					Location:       Location{Path: "demo.php", Line: 1},
					PersistentRead: true,
				}},
			},
		},
	}
	args := []originSet{makeOriginSet(origin{kind: originParam, paramIdx: 0})}

	if state.allowCurrentBatchStateSideEffectsForCallbackReplay(helperKey, item, args) {
		t.Fatal("pure persistent-read storage writes should not force output callback state side effects")
	}
}

func TestCallableNeedsFileWarmSummarySkipsNonPathRecordReadHelper(t *testing.T) {
	engine := &engine{
		callables: map[string]callable{
			"function::\\helper": {Key: "function::\\helper"},
		},
		recordReadCallables: map[string]struct{}{
			"function::\\helper": {},
		},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"function::\\helper": {"option_value[ur_confirm_email]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
	}

	if engine.callableNeedsFileWarmSummary("function::\\helper") {
		t.Fatalf("non-path record-read helper should not require a full file-batch warm summary")
	}
}

func TestCallableNeedsFileWarmSummaryKeepsPathLikeRecordReadHelper(t *testing.T) {
	engine := &engine{
		callables: map[string]callable{
			"function::\\helper": {Key: "function::\\helper"},
		},
		recordReadCallables: map[string]struct{}{
			"function::\\helper": {},
		},
		storageReadBucketsByCallable: map[string]map[string]struct{}{
			"function::\\helper": {"user_meta_value[*][avatar][file_path]": {}},
		},
		storageReadFamiliesByCallable: map[string]map[string]struct{}{},
	}

	if !engine.callableNeedsFileWarmSummary("function::\\helper") {
		t.Fatalf("path-like record-read helper should stay file-batch warm-summary relevant")
	}
}

func TestCallableNeedsFileWarmSummarySkipsCallerWhenCalleeOnlyHasInternalFileUseOrder(t *testing.T) {
	callerKey := `function::\caller`
	calleeKey := `function::\callee`
	engine := &engine{
		callables: map[string]callable{
			callerKey: {Key: callerKey},
			calleeKey: {Key: calleeKey},
		},
		callSiteEdges: map[string][]callSiteEdge{
			callerKey: {{callee: calleeKey, order: 1}},
		},
		fileSinkRelevantUseOrders: map[string]map[string]int{
			calleeKey: {"tmp": 1},
		},
		storageBaseWritersByFamily:      map[string]map[string]struct{}{},
		storageBaseWritersByFamilyClass: map[string]map[string]struct{}{},
		storagePathWritersByBucket:      map[string]map[string]struct{}{},
		storageReadBucketsByCallable:    map[string]map[string]struct{}{},
		storageReadFamiliesByCallable:   map[string]map[string]struct{}{},
		receiverMutatingCallables:       map[string]struct{}{},
		staticReadPathsByCallable:       map[string]map[string]struct{}{},
		staticReadRootsByCallable:       map[string]map[string]struct{}{},
	}

	if engine.callableNeedsFileWarmSummary(callerKey) {
		t.Fatalf("caller should not stay file-warm only because callee has internal file relevant use orders")
	}
}

func TestCallableNeedsFileWarmSummarySkipsCallerWhenCalleeOnlyHasDeleteSinkInReadBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "delete-wrapper.php"), `<?php
function leaf($path) {
    unlink($path);
}

function wrapper() {
    $path = $_GET['path'];
    leaf($path);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if engine.callableNeedsFileWarmSummary("function::\\wrapper") {
		t.Fatalf("read-batch wrapper should not stay warm only because callee has a delete sink")
	}
}

func TestBuildEngineSkipsNoArgSingletonReceiverWrapperForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-singleton-receiver.php"), `<?php
function add_shortcode($tag, $callback) {}

class DemoReceiver {
    public static function instance() {
        return new self();
    }

    public function run() {
        return unserialize('a:0:{}');
    }
}

function demo_shortcode($atts) {
    return DemoReceiver::instance()->run();
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if engine.callInputConsumingCallables["function::\\demo_shortcode"] {
		t.Fatalf("no-arg singleton receiver wrapper should not be marked as consuming call input: %#v", engine.callInputConsumingCallables)
	}
	if _, ok := engine.relevantCallables["function::\\demo_shortcode"]; ok {
		t.Fatalf("no-arg singleton receiver wrapper should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsUnusedDataCarrierHelperInCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-unused-data-helper.php"), `<?php
function helper_passthrough($value) {
    $copy = $value;
    return $copy;
}

function sink_wrapper($callback, $value) {
    helper_passthrough($value);
    return call_user_func($callback, $value);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := "function::\\helper_passthrough"
	wrapperKey := "function::\\sink_wrapper"
	if _, ok := engine.relevantCallables[wrapperKey]; !ok {
		t.Fatalf("sink wrapper should stay relevant: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[helperKey]; ok {
		t.Fatalf("unused data-carrier helper should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineDoesNotTreatFileWrapperAsCallSinkForNestedDeclaration(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "file-wrapper-nested-call.php"), `<?php
$loaded = true;

class DemoRender {
    public function render($atts) {
        call_user_func($atts['callback'], 'safe');
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	fileKey := "file::file-wrapper-nested-call.php"
	if _, ok := engine.callables[fileKey]; !ok {
		t.Fatalf("expected file callable %q to exist", fileKey)
	}
	if engine.callableHasDirectSink(engine.callables[fileKey]) {
		t.Fatalf("file wrapper should not inherit nested method call sink: %#v", engine.callables[fileKey])
	}
	if _, ok := engine.relevantCallables[fileKey]; ok {
		t.Fatalf("inert file wrapper should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineDoesNotTreatFileWrapperAsSQLSinkForNestedDeclaration(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "file-wrapper-nested-sql.php"), `<?php
$loaded = true;

class DemoQuery {
    public function run($wpdb) {
        return $wpdb->prepare("SELECT * FROM demo WHERE id = %s", $_GET['id']);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	fileKey := "file::file-wrapper-nested-sql.php"
	if _, ok := engine.callables[fileKey]; !ok {
		t.Fatalf("expected file callable %q to exist", fileKey)
	}
	if engine.callableHasDirectSink(engine.callables[fileKey]) {
		t.Fatalf("file wrapper should not inherit nested method sql sink: %#v", engine.callables[fileKey])
	}
	if engine.callableHasDirectRequestInput(engine.callables[fileKey]) {
		t.Fatalf("file wrapper should not inherit nested method request input: %#v", engine.callables[fileKey])
	}
	if len(engine.callSiteEdges[fileKey]) != 0 {
		t.Fatalf("file wrapper should not collect nested declaration call sites: %#v", engine.callSiteEdges[fileKey])
	}
	if _, ok := engine.relevantCallables[fileKey]; ok {
		t.Fatalf("inert file wrapper should not stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsLowValueFileWrapperForDeleteBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "dashboard-view.php"), `<?php
$form_id = filter_input(INPUT_GET, 'form_id', FILTER_VALIDATE_INT);
echo esc_html($form_id);
`)
	writePHP(t, filepath.Join(root, "delete-handler.php"), `<?php
function delete_handler() {
    $path = $_GET['path'];
    unlink($path);
}

delete_handler();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	fileKey := "file::dashboard-view.php"
	if _, ok := engine.callables[fileKey]; !ok {
		t.Fatalf("expected file callable %q to exist", fileKey)
	}
	if _, ok := engine.relevantCallables[`function::\delete_handler`]; !ok {
		t.Fatalf("expected delete_handler to stay relevant in delete-only analysis: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[fileKey]; ok {
		t.Fatalf("low-value file wrapper should not stay relevant in delete-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsOrphanRequestOnlyHelperForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-orphan-request-helper.php"), `<?php
function orphan_request_helper() {
    return $_REQUEST['tab'] ?? '';
}

function demo_shortcode($atts) {
    return trim($atts['name']);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["function::\\orphan_request_helper"]; ok {
		t.Fatalf("orphan request-only helper should not stay relevant in call-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsReverseCallersWithoutCallbackRelevantUse(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-reverse-prune.php"), `<?php
class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

function import_item($item) {
    $render = new DemoRender();
    $item = $render->prepare_form($item);
    return $item['title'];
}

function demo_shortcode($atts) {
    $form = array(
        'title' => 'demo',
        'render' => $atts['render'],
    );
    return (new DemoRender())->prepare_form($form);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["function::\\import_item"]; ok {
		t.Fatalf("reverse-only caller without callback-relevant use should not stay relevant for call sinks: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsSubpathAssignmentsUnusedByCallSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-subpath-prune.php"), `<?php
function normalize_field_groups($value) {
    return $value;
}

class DemoRender {
    public function prepare_form($form) {
        $form['field_groups'] = normalize_field_groups($form['field_groups']);
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

function demo_shortcode($atts) {
    $form = array(
        'field_groups' => array('group_demo'),
        'render' => $atts['render'],
    );
    return (new DemoRender())->prepare_form($form);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["function::\\normalize_field_groups"]; ok {
		t.Fatalf("subpath-only normalization helper should not stay relevant for call sinks: %#v", engine.relevantCallables)
	}
}

func TestBuildEnginePrunesActionOnlyBroadcastersAndReverseOnlyCallers(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-relevance-prune.php"), `<?php
function helper_broadcast($settings) {
    do_action('demo/form/prepare', $settings);
}

function save_settings($settings) {
    update_option($settings['key'], $settings['value']);
}

function import_item($item) {
    save_settings($item);
    return $item['title'];
}

function demo_shortcode($atts) {
    $settings = array(
        'key' => $atts['key'],
        'value' => $atts['value'],
    );
    helper_broadcast($settings);
    save_settings($settings);
    return '';
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	shortcodeKey := `function::\demo_shortcode`
	saveKey := `function::\save_settings`
	broadcastKey := `function::\helper_broadcast`
	importKey := `function::\import_item`

	if _, ok := engine.relevantCallables[shortcodeKey]; !ok {
		t.Fatalf("shortcode caller should stay relevant for action sinks: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[saveKey]; !ok {
		t.Fatalf("direct action sink should stay relevant: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[broadcastKey]; ok {
		t.Fatalf("pure action broadcaster should not stay relevant for action sinks: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[importKey]; ok {
		t.Fatalf("reverse-only caller without action-relevant use should not stay relevant for action sinks: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineDoesNotSeedPlainCallbackParamHelpersAsCallSinks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-plain-param-helper.php"), `<?php
function acfe_map_fields($field, $callback) {
    return call_user_func($callback, $field);
}

class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

function demo_shortcode($atts) {
    $form = array(
        'render' => $atts['render'],
    );
    return (new DemoRender())->prepare_form($form);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["function::\\acfe_map_fields"]; ok {
		t.Fatalf("plain callback-param helper should not seed call-sink relevance: %#v", engine.relevantCallables)
	}
}

func TestAnalyzeRootIgnoresStoredClosureBodiesForCallSinks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "stored-closures-call-sink.php"), `<?php
function import_0_9($form) {
    $rules = array(
        array(
            'render' => function($item) {
                call_user_func_array($_GET['dead'], array($item));
            },
        ),
        array(
            'render' => function($item) {
                return trim($item['name']);
            },
        ),
    );
    return $form;
}

class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

function demo_shortcode($atts) {
    $form = array(
        'name' => 'demo',
        'render' => $atts['render'],
    );
    $form = import_0_9($form);
    return (new DemoRender())->prepare_form($form);
}

add_shortcode('demo', 'demo_shortcode');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "render-callback-execution" {
			t.Fatalf("check_id = %q, want render-callback-execution", finding.CheckID)
		}
		if finding.Extra.Trace.Source.Line == 6 {
			t.Fatalf("closure body unexpectedly surfaced as a real source: %#v", finding.Extra.Trace.Source)
		}
		if finding.Start.Line != 21 {
			t.Fatalf("sink line = %d, want 21", finding.Start.Line)
		}
	}
}

func TestBuildEngineIndexesInterpolatedFilterDispatchForSingletonCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "render-callback-engine.php"), `<?php
function acf_get_instance($name) {
    return null;
}

class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

class DemoHooks {
    public function __construct() {
        add_filter('acfe/form/prepare_form', array($this, 'prepare_form'));
        add_action('wp_ajax_nopriv_demo_render', array($this, 'render_ajax'));
    }

    public function render_ajax() {
        $form = $_POST['form'];
        apply_filters('acfe/form/prepare_form', $form);
    }

    public function prepare_form($form) {
        add_filter("acfe/form/prepare_form/form={$form['name']}", array(acf_get_instance('DemoRender'), 'prepare_form'));
        return apply_filters("acfe/form/prepare_form/form={$form['name']}", $form);
    }
}

new DemoHooks();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	renderKey := engine.lookupMethodKey(`\DemoRender`, "prepare_form")
	if renderKey == "" {
		t.Fatalf("missing DemoRender::prepare_form")
	}
	dynamicHook := "acfe/form/prepare_form/form={form[name]}"
	foundCallback := false
	for _, key := range engine.filterCallbacks[dynamicHook] {
		if key == renderKey {
			foundCallback = true
		}
	}
	if !foundCallback {
		t.Fatalf("dynamic hook %q did not resolve singleton callback; callbacks=%#v", dynamicHook, engine.filterCallbacks[dynamicHook])
	}

	hooksKey := engine.lookupMethodKey(`\DemoHooks`, "prepare_form")
	if hooksKey == "" {
		t.Fatalf("missing DemoHooks::prepare_form")
	}
	if _, ok := engine.callEdges[hooksKey][renderKey]; !ok {
		allCallees, _, _ := engine.collectDirectCallEdges(engine.callables[hooksKey])
		hookKeys := []string{}
		walkNodes(engine.callables[hooksKey].Stmts, func(node ast.Node) {
			call, ok := node.(*ast.ExprFuncCall)
			if !ok || normalizeName(identifierText(call.Name)) != "apply_filters" {
				return
			}
			hookKeys = append(hookKeys, hookDispatchKey(argValue(call.Args[0]), engine.callables[hooksKey].Class, engine))
		})
		t.Fatalf(
			"missing apply_filters call edge from %s to %s; callEdges=%#v directCallees=%#v filterCallbacks=%#v hookKeys=%#v",
			hooksKey,
			renderKey,
			engine.callEdges[hooksKey],
			allCallees,
			engine.filterCallbacks[dynamicHook],
			hookKeys,
		)
	}
}

func TestAnalyzeRootTreatsShortcodeAttsAsSourceForRenderCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-render.php"), `<?php
function acf_get_instance($name) {
    return null;
}

class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

function demo_shortcode($atts) {
    $form = array(
        'name' => 'demo',
        'render' => $atts['render'],
    );
    add_filter("acfe/form/prepare_form/form={$form['name']}", array(acf_get_instance('DemoRender'), 'prepare_form'));
    return apply_filters("acfe/form/prepare_form/form={$form['name']}", $form);
}

add_shortcode('demo', 'demo_shortcode');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "render-callback-execution" {
			continue
		}
		for _, entry := range finding.Extra.Context.EntryPoints {
			if entry.Kind == "shortcode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("results = %#v, want render-callback-execution with shortcode entrypoint", result.Payload.Results)
	}
}

func TestAnalyzeRootPreservesShortcodeRenderThroughACFEHelpers(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-render-helpers.php"), `<?php
function acf_get_array($value) {
    return $value;
}

function acfe_parse_types($value) {
    return $value;
}

function acfe_parse_args_r(&$a, $b) {
    return array_merge($b, $a);
}

function acf_get_instance($name) {
    return null;
}

class DemoRender {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

function demo_shortcode($atts) {
    $atts = acf_get_array($atts);
    $atts = acfe_parse_types($atts);
    $form = array(
        'name' => 'demo',
        'render' => $atts['render'],
    );
    $item = array(
        'title' => 'Demo',
        'render' => false,
    );
    $form = acfe_parse_args_r($form, $item);
    add_filter("acfe/form/prepare_form/form={$form['name']}", array(acf_get_instance('DemoRender'), 'prepare_form'));
    return apply_filters("acfe/form/prepare_form/form={$form['name']}", $form);
}

add_shortcode('demo', 'demo_shortcode');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "render-callback-execution" {
			continue
		}
		for _, entry := range finding.Extra.Context.EntryPoints {
			if entry.Kind == "shortcode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("results = %#v, want render-callback-execution with shortcode entrypoint after helper normalization", result.Payload.Results)
	}
}

func TestAnalyzeRootPreservesShortcodeRenderThroughACFEModuleFactory(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-render-module-factory.php"), `<?php
function acf_get_array($value) {
    return $value;
}

function acfe_parse_types($value) {
    return $value;
}

function acfe_parse_args_r(&$a, $b) {
    return array_merge($b, $a);
}

function acf_get_instance($name) {
    return null;
}

function acfe_get_module($name) {
    return null;
}

class acfe_module_form {
    public function validate_item($item) {
        $defaults = array(
            'render' => '',
        );
        return acfe_parse_args_r($item, $defaults);
    }
}

class acfe_module_form_front_render {
    public function prepare_form($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

class acfe_module_form_front {
    public function get_form($form) {
        $module = acfe_get_module('form');
        return $module->validate_item($form);
    }

    public function render_form($form) {
        $form = $this->get_form($form);
        add_filter("acfe/form/prepare_form/form={$form['name']}", array(acf_get_instance('acfe_module_form_front_render'), 'prepare_form'));
        return apply_filters("acfe/form/prepare_form/form={$form['name']}", $form);
    }
}

function acfe_form($form = array()) {
    return acf_get_instance('acfe_module_form_front')->render_form($form);
}

function demo_shortcode($atts) {
    $atts = acf_get_array($atts);
    $atts = acfe_parse_types($atts);
    $atts['name'] = 'demo';
    return acfe_form($atts);
}

add_shortcode('demo', 'demo_shortcode');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "render-callback-execution" {
			continue
		}
		for _, entry := range finding.Extra.Context.EntryPoints {
			if entry.Kind == "shortcode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("results = %#v, want render-callback-execution after module factory resolution", result.Payload.Results)
	}
}

func TestAnalyzeRootPreservesShortcodeRenderThroughApplyFiltersRefArrayWrapper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "shortcode-render-apply-filters-ref-array.php"), `<?php
function acf_get_instance($name) {
    return null;
}

class DemoRender {
    public function on_validate($form) {
        if (is_callable($form['render'])) {
            call_user_func_array($form['render'], array($form));
        }
        return $form;
    }
}

class DemoModule {
    public $name = 'form';

    public function apply_module_filters($tag, ...$args) {
        $args[] = $this;
        $args[0] = apply_filters_ref_array("{$tag}/module={$this->name}", $args);
        $args[0] = apply_filters_ref_array($tag, $args);
        return $args[0];
    }

    public function validate_item($item) {
        return $this->apply_module_filters('acfe/module/validate_item', $item);
    }
}

function demo_shortcode($atts) {
    $module = new DemoModule();
    $atts['name'] = 'demo';
    add_filter('acfe/module/validate_item', array(acf_get_instance('DemoRender'), 'on_validate'));
    return $module->validate_item($atts);
}

add_shortcode('demo', 'demo_shortcode');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "render-callback-execution" {
			continue
		}
		for _, entry := range finding.Extra.Context.EntryPoints {
			if entry.Kind == "shortcode" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("results = %#v, want render-callback-execution after apply_filters_ref_array wrapper", result.Payload.Results)
	}
}

func TestDynamicForeachAjaxRegistrationResolvesExactMethodTargets(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "dynamic-foreach-ajax-registration.php"), `<?php
function add_action($hook, $callback) {}

class Demo {
    public function register() {
        $ajax_events = array(
            'upload_file',
            'remove_file',
        );
        foreach ( $ajax_events as $ajax_event ) {
            add_action( 'wp_ajax_demo_' . $ajax_event, array( $this, $ajax_event ) );
            add_action( 'wp_ajax_nopriv_demo_' . $ajax_event, array( $this, $ajax_event ) );
        }
    }

    public function upload_file() {
        return file_get_contents($_FILES['file']['tmp_name']);
    }

    public function remove_file() {
        unlink($_POST['file']);
    }

    public function unrelated() {
        echo $_POST['html'];
    }
}

(new Demo())->register();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"read": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	uploadKey := engine.lookupMethodKey(`\Demo`, "upload_file")
	removeKey := engine.lookupMethodKey(`\Demo`, "remove_file")
	unrelatedKey := engine.lookupMethodKey(`\Demo`, "unrelated")
	if uploadKey == "" || removeKey == "" || unrelatedKey == "" {
		t.Fatalf("missing expected callback keys: upload=%q remove=%q unrelated=%q", uploadKey, removeKey, unrelatedKey)
	}
	if _, ok := engine.directPublicCallables[uploadKey]; !ok {
		t.Fatalf("upload_file should be a direct public callback: %#v", engine.directPublicCallables)
	}
	if _, ok := engine.directPublicCallables[removeKey]; !ok {
		t.Fatalf("remove_file should be a direct public callback: %#v", engine.directPublicCallables)
	}
	if _, ok := engine.directPublicCallables[unrelatedKey]; ok {
		t.Fatalf("unrelated method should not be marked direct public: %#v", engine.directPublicCallables)
	}
	if len(engine.directEntryPointsByCallable[unrelatedKey]) != 0 {
		t.Fatalf("unrelated method should not inherit ajax entrypoints: %#v", engine.directEntryPointsByCallable[unrelatedKey])
	}
}

func TestCombinedFileBatchSkipsPublicOutputOnlyAjaxHandler(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "combined-file-output-only.php"), `<?php
function add_action($hook, $callback) {}

class Demo {
    public function __construct() {
        add_action('wp_ajax_demo_preview', array($this, 'ajax'));
    }

    public function ajax() {
        $html = isset($_POST['html']) ? $_POST['html'] : '';
        wp_send_json_success($html);
    }
}

new Demo();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{
			"delete": {},
			"open":   {},
			"read":   {},
			"write":  {},
		},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`method::\Demo::ajax`]; ok {
		t.Fatalf("output-only ajax handler should not stay relevant in combined file batch: %#v", engine.relevantCallables)
	}
}

func TestCombinedFileBatchKeepsPublicReadAjaxHandler(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "combined-file-read.php"), `<?php
function add_action($hook, $callback) {}

class Demo {
    public function __construct() {
        add_action('wp_ajax_demo_read', array($this, 'ajax'));
    }

    public function ajax() {
        $path = isset($_POST['path']) ? $_POST['path'] : '';
        file_get_contents($path);
    }
}

new Demo();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{
			"delete": {},
			"open":   {},
			"read":   {},
			"write":  {},
		},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`method::\Demo::ajax`]; !ok {
		t.Fatalf("read ajax handler should stay relevant in combined file batch: %#v", engine.relevantCallables)
	}
}

func TestCombinedFileBatchIgnoresOutputUseOrders(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "combined-file-output-orders.php"), `<?php
function wp_send_json_success($value) {}

class Demo {
    public function ajax() {
        $payload = isset($_POST['html']) ? $_POST['html'] : '';
        wp_send_json_success($payload);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{
			"delete": {},
			"open":   {},
			"read":   {},
			"write":  {},
		},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := `method::\Demo::ajax`
	if len(engine.fileSinkRelevantUseOrders[key]) != 0 {
		t.Fatalf("output-only callable should not get file relevant use orders: %#v", engine.fileSinkRelevantUseOrders[key])
	}
}

func TestBuildEngineLinksApplyFiltersRefArrayToRegisteredCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "apply-filters-ref-array-edge.php"), `<?php
function acf_get_instance($name) {
    return null;
}

class DemoRender {
    public function on_validate($form) {
        return $form;
    }
}

class DemoModule {
    public $name = 'form';

    public function apply_module_filters($tag, ...$args) {
        $args[] = $this;
        $args[0] = apply_filters_ref_array("{$tag}/module={$this->name}", $args);
        $args[0] = apply_filters_ref_array($tag, $args);
        return $args[0];
    }
}

function demo_shortcode($atts) {
    $module = new DemoModule();
    add_filter('acfe/module/validate_item', array(acf_get_instance('DemoRender'), 'on_validate'));
    return $module->apply_module_filters('acfe/module/validate_item', $atts);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	renderKey := engine.lookupMethodKey(`\DemoRender`, "on_validate")
	if renderKey == "" {
		t.Fatalf("missing DemoRender::on_validate")
	}
	moduleKey := engine.lookupMethodKey(`\DemoModule`, "apply_module_filters")
	if moduleKey == "" {
		t.Fatalf("missing DemoModule::apply_module_filters")
	}
	engine.currentBatchName = "call"
	specializedKey := engine.maybeSpecializeCallableForLiteralArgs(moduleKey, map[int]string{0: "acfe/module/validate_item"})
	callees, _, _ := engine.collectDirectCallEdges(engine.callables[specializedKey])
	found := false
	for _, key := range callees {
		if key == renderKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing apply_filters_ref_array call edge from %s to %s; callees=%#v filterCallbacks=%#v", specializedKey, renderKey, callees, engine.filterCallbacks)
	}
}

func TestBuildEngineSkipsSelfRecursiveApplyFiltersRefArrayCallbackEdge(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "apply-filters-ref-array-self-edge.php"), `<?php
class DemoModule {
    public function register() {
        add_filter('acfe/module/validate_item', array($this, 'validate_item'));
    }

    public function validate_item($item) {
        $args = array($item);
        return apply_filters_ref_array('acfe/module/validate_item', $args);
    }
}

function demo_shortcode($atts) {
    $module = new DemoModule();
    $module->register();
    return $module->validate_item($atts);
}

add_shortcode('demo', 'demo_shortcode');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	moduleKey := engine.lookupMethodKey(`\DemoModule`, "validate_item")
	if moduleKey == "" {
		t.Fatalf("missing DemoModule::validate_item")
	}
	if _, ok := engine.callEdges[moduleKey][moduleKey]; ok {
		t.Fatalf("unexpected self-recursive apply_filters_ref_array call edge on %s; callEdges=%#v filterCallbacks=%#v", moduleKey, engine.callEdges[moduleKey], engine.filterCallbacks)
	}
}

func TestBuildEngineUsesLiteralModulePropertyForHookDispatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "apply-filters-ref-array-literal-module-name.php"), `<?php
class BaseModule {
    public $name = '';

    public function dispatch($args) {
        return apply_filters_ref_array("demo/validate_item/module={$this->name}", $args);
    }
}

class FormModule extends BaseModule {
    public $name = 'form';
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	baseDispatchKey := engine.lookupMethodKey(`\BaseModule`, "dispatch")
	if baseDispatchKey == "" {
		t.Fatalf("missing BaseModule::dispatch")
	}
	baseDispatch := engine.callables[baseDispatchKey]
	var call *ast.ExprFuncCall
	walkNodes(baseDispatch.Stmts, func(node ast.Node) {
		if call != nil {
			return
		}
		typed, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		if normalizeName(identifierText(typed.Name)) == "apply_filters_ref_array" {
			call = typed
		}
	})
	if call == nil {
		t.Fatalf("missing apply_filters_ref_array call in %s", baseDispatchKey)
	}
	hook := hookDispatchKeyForCallable(argValue(call.Args[0]), callable{Class: `\FormModule`}, engine)
	if hook != "demo/validate_item/module=form" {
		t.Fatalf("hook = %q, want demo/validate_item/module=form", hook)
	}
}

func TestSpecializedHookWrapperUsesLiteralTagArgument(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "specialized-hook-wrapper-literal-tag.php"), `<?php
class BaseModule {
    public $name = '';

    public function dispatch($tag, $args) {
        return apply_filters_ref_array("{$tag}/module={$this->name}", $args);
    }
}

class FormModule extends BaseModule {
    public $name = 'form';
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	baseDispatchKey := engine.ensureRuntimeMethodCallable(`\FormModule`, "dispatch")
	if baseDispatchKey == "" {
		t.Fatalf("missing FormModule::dispatch runtime callable")
	}
	engine.currentBatchName = "call"
	specializedKey := engine.maybeSpecializeCallableForLiteralArgs(baseDispatchKey, map[int]string{0: "demo/validate_item"})
	if specializedKey == "" || specializedKey == baseDispatchKey {
		t.Fatalf("expected specialized callable for %s, got %q", baseDispatchKey, specializedKey)
	}
	current := engine.callables[specializedKey]
	var call *ast.ExprFuncCall
	walkNodes(current.Stmts, func(node ast.Node) {
		if call != nil {
			return
		}
		typed, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		if normalizeName(identifierText(typed.Name)) == "apply_filters_ref_array" {
			call = typed
		}
	})
	if call == nil {
		t.Fatalf("missing apply_filters_ref_array call in %s", specializedKey)
	}
	hook := hookDispatchKeyForCallable(argValue(call.Args[0]), current, engine)
	if hook != "demo/validate_item/module=form" {
		t.Fatalf("hook = %q, want demo/validate_item/module=form", hook)
	}
}

func TestBuildEngineAvoidsRecursiveCallbackClassResolutionThroughHookArgs(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "recursive-callback-class-hook.php"), `<?php
class Registry {
    public static function make($hook) {
        return null;
    }
}

class Demo {
    public function init() {
        $listener = Registry::make('demo/' . $listener->tag());
        add_action('demo/' . $listener->tag(), array($listener, 'run'));
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupMethodKey(`\Demo`, "init")
	if key == "" {
		t.Fatalf("missing Demo::init")
	}
	current := engine.callables[key]
	var call *ast.ExprFuncCall
	walkNodes(current.Stmts, func(node ast.Node) {
		if call != nil {
			return
		}
		typed, ok := node.(*ast.ExprFuncCall)
		if !ok {
			return
		}
		if normalizeName(identifierText(typed.Name)) == "add_action" {
			call = typed
		}
	})
	if call == nil {
		t.Fatalf("missing add_action call")
	}
	hook := hookDispatchKeyForCallable(argValue(call.Args[0]), current, engine)
	if hook != "" {
		t.Fatalf("hook = %q, want empty string for recursive unresolved hook", hook)
	}
	itemsNode, ok := argValue(call.Args[1]).(*ast.ExprArray)
	if !ok || len(itemsNode.Items) == 0 {
		t.Fatalf("callback arg is not array")
	}
	item, ok := itemsNode.Items[0].(*ast.ArrayItem)
	if !ok {
		t.Fatalf("callback first item is not ArrayItem")
	}
	if refs := engine.resolveCallbackClassRefs(item.Value, current); len(refs) != 0 {
		t.Fatalf("resolveCallbackClassRefs() = %#v, want none for recursive unresolved callback", refs)
	}
}

func TestLiteralArgSpecializationSkipsNonCallBatches(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "specialized-hook-wrapper-non-call-batch.php"), `<?php
class BaseModule {
    public function dispatch($tag, $args) {
        return apply_filters_ref_array($tag, $args);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupMethodKey(`\BaseModule`, "dispatch")
	if key == "" {
		t.Fatalf("missing BaseModule::dispatch")
	}
	engine.currentBatchName = "action"
	if got := engine.maybeSpecializeCallableForLiteralArgs(key, map[int]string{0: "demo/validate_item"}); got != key {
		t.Fatalf("maybeSpecializeCallableForLiteralArgs() = %q, want %q outside call batch", got, key)
	}
}

func TestLiteralArgIntrospectionSpecializationReusesExistingWithoutMutation(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "specialized-hook-wrapper-introspection-active-batch.php"), `<?php
class BaseModule {
    public function dispatch($tag, $args) {
        return apply_filters_ref_array($tag, $args);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupMethodKey(`\BaseModule`, "dispatch")
	if key == "" {
		t.Fatalf("missing BaseModule::dispatch")
	}

	engine.currentBatchName = "call"
	existing := engine.maybeSpecializeCallableForLiteralArgs(key, map[int]string{0: "demo/validate_item"})
	if existing == "" || existing == key {
		t.Fatalf("expected existing specialization, got %q", existing)
	}
	before := len(engine.callOrder)

	engine.currentBatchName = "action"
	if got := engine.specializeCallableKeyForIntrospection(key, map[int]string{0: "demo/validate_item"}); got != existing {
		t.Fatalf("specializeCallableKeyForIntrospection() = %q, want existing %q", got, existing)
	}
	if got := engine.specializeCallableKeyForIntrospection(key, map[int]string{0: "demo/other_item"}); got != key {
		t.Fatalf("specializeCallableKeyForIntrospection() = %q, want base key %q when specialization does not already exist", got, key)
	}
	if after := len(engine.callOrder); after != before {
		t.Fatalf("callOrder len = %d, want %d without active-batch mutation", after, before)
	}
}

func TestLiteralArgSpecializationAppliesForOutputTemplateIncludeHelpers(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-template-specialization.php"), `<?php
class Loader {
    public static $dir = '';
    public static function init() {
        self::$dir = __DIR__ . '/templates/';
    }
    public static function template($file, $data = array()) {
        extract($data);
        $path = self::$dir . $file;
        include $path;
    }
}
Loader::init();
`)
	writePHP(t, filepath.Join(root, "templates", "calcs.php"), `<?php echo $title;`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupMethodKey(`\Loader`, "template")
	if key == "" {
		t.Fatalf("missing Loader::template")
	}
	engine.currentBatchName = "output"
	specializedKey := engine.maybeSpecializeCallableForLiteralArgs(key, map[int]string{0: "calcs.php"})
	if specializedKey == "" || specializedKey == key {
		t.Fatalf("expected output-batch specialized callable for %s, got %q", key, specializedKey)
	}
	current := engine.callables[specializedKey]
	var includeExpr ast.Node
	walkNodes(current.Stmts, func(node ast.Node) {
		if includeExpr != nil {
			return
		}
		includeNode, ok := node.(*ast.ExprInclude)
		if !ok {
			return
		}
		includeExpr = includeNode.Expr
	})
	if includeExpr == nil {
		t.Fatalf("missing include expression in %s", specializedKey)
	}
	keys := engine.staticIncludedFileCallableKeys(includeExpr, current)
	if len(keys) != 1 || !strings.HasSuffix(keys[0], "templates/calcs.php") {
		t.Fatalf("staticIncludedFileCallableKeys() = %#v, want calcs.php", keys)
	}
}

func TestLiteralArgSpecializationAppliesForOutputLiteralReturnFunctions(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-function-specialization.php"), `<?php
function render_user_piece($mode) {
    switch ($mode) {
        case 'safe':
            return 'ok';
        case 'danger':
            echo $_GET['msg'];
            return 'bad';
        default:
            return '';
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupFunctionKey("", "render_user_piece")
	if key == "" {
		t.Fatalf("missing render_user_piece")
	}
	engine.currentBatchName = "output"
	specializedKey := engine.maybeSpecializeCallableForLiteralArgs(key, map[int]string{0: "safe"})
	if specializedKey == "" || specializedKey == key {
		t.Fatalf("expected output-batch specialized callable for %s, got %q", key, specializedKey)
	}
}

func TestOutputLiteralSpecializationBuildsSpecializedFunctionCallEdges(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-function-callgraph-specialization.php"), `<?php
function safe_piece() {
    return 'ok';
}
function danger_piece() {
    echo $_GET['msg'];
    return 'bad';
}
function route_piece($mode) {
    switch ($mode) {
        case 'safe':
            return safe_piece();
        case 'danger':
            return danger_piece();
        default:
            return '';
    }
}
function render_piece() {
    echo route_piece('safe');
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	routeKey := engine.lookupFunctionKey("", "route_piece")
	renderKey := engine.lookupFunctionKey("", "render_piece")
	safeKey := engine.lookupFunctionKey("", "safe_piece")
	dangerKey := engine.lookupFunctionKey("", "danger_piece")
	if routeKey == "" || renderKey == "" || safeKey == "" || dangerKey == "" {
		t.Fatalf("missing keys: route=%q render=%q safe=%q danger=%q", routeKey, renderKey, safeKey, dangerKey)
	}

	engine.currentBatchName = "output"
	specializedKey := engine.existingSpecializedCallableForLiteralArgs(routeKey, map[int]string{0: "safe"})
	if specializedKey == "" || specializedKey == routeKey {
		t.Fatalf("expected existing specialized route_piece callable, got %q", specializedKey)
	}

	foundSpecializedCaller := false
	foundBaseCaller := false
	for _, site := range engine.callSiteEdges[renderKey] {
		switch site.callee {
		case specializedKey:
			foundSpecializedCaller = true
		case routeKey:
			foundBaseCaller = true
		}
	}
	if !foundSpecializedCaller || foundBaseCaller {
		t.Fatalf("render_piece call sites = %#v, want specialized callee %q only", engine.callSiteEdges[renderKey], specializedKey)
	}
	if _, ok := engine.callEdges[specializedKey][safeKey]; !ok {
		t.Fatalf("specialized route_piece edges = %#v, want %q", engine.callEdges[specializedKey], safeKey)
	}
	if _, ok := engine.callEdges[specializedKey][dangerKey]; ok {
		t.Fatalf("specialized route_piece edges = %#v, should not include %q", engine.callEdges[specializedKey], dangerKey)
	}
}

func TestOutputLiteralSpecializationNarrowsLeadingDefaultSwitchFunctionCallEdges(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-function-leading-default-specialization.php"), `<?php
function default_piece($mode) {
    return $mode;
}
function id_piece() {
    return 'id';
}
function login_piece() {
    return 'login';
}
function route_piece($mode) {
    switch ($mode) {
        default:
            return default_piece($mode);
        case 'id':
            return id_piece();
        case 'login':
            return login_piece();
    }
}
function render_piece() {
    echo route_piece('display_name');
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	routeKey := engine.lookupFunctionKey("", "route_piece")
	defaultKey := engine.lookupFunctionKey("", "default_piece")
	idKey := engine.lookupFunctionKey("", "id_piece")
	loginKey := engine.lookupFunctionKey("", "login_piece")
	if routeKey == "" || defaultKey == "" || idKey == "" || loginKey == "" {
		t.Fatalf("missing keys: route=%q default=%q id=%q login=%q", routeKey, defaultKey, idKey, loginKey)
	}

	engine.currentBatchName = "output"
	specializedKey := engine.existingSpecializedCallableForLiteralArgs(routeKey, map[int]string{0: "display_name"})
	if specializedKey == "" || specializedKey == routeKey {
		t.Fatalf("expected existing specialized route_piece callable, got %q", specializedKey)
	}

	if _, ok := engine.callEdges[specializedKey][defaultKey]; !ok {
		t.Fatalf("specialized route_piece edges = %#v, want %q", engine.callEdges[specializedKey], defaultKey)
	}
	if _, ok := engine.callEdges[specializedKey][idKey]; ok {
		t.Fatalf("specialized route_piece edges = %#v, should not include %q", engine.callEdges[specializedKey], idKey)
	}
	if _, ok := engine.callEdges[specializedKey][loginKey]; ok {
		t.Fatalf("specialized route_piece edges = %#v, should not include %q", engine.callEdges[specializedKey], loginKey)
	}
}

func TestOutputLiteralSpecializationNarrowsSequentialLiteralIfFunctionCallEdges(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-function-literal-if-specialization.php"), `<?php
function default_piece() {
    return 'default';
}
function id_piece() {
    return $_GET['id'];
}
function login_piece() {
    return 'login';
}
function route_piece($mode) {
    $value = default_piece();
    if ($mode == 'id') {
        $value = id_piece();
    }
    if ($mode == 'login') {
        $value = login_piece();
    }
    return $value;
}
function render_piece() {
    echo route_piece('login');
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	routeKey := engine.lookupFunctionKey("", "route_piece")
	defaultKey := engine.lookupFunctionKey("", "default_piece")
	idKey := engine.lookupFunctionKey("", "id_piece")
	loginKey := engine.lookupFunctionKey("", "login_piece")
	if routeKey == "" || defaultKey == "" || idKey == "" || loginKey == "" {
		t.Fatalf("missing keys: route=%q default=%q id=%q login=%q", routeKey, defaultKey, idKey, loginKey)
	}

	engine.currentBatchName = "output"
	specializedKey := engine.existingSpecializedCallableForLiteralArgs(routeKey, map[int]string{0: "login"})
	if specializedKey == "" || specializedKey == routeKey {
		t.Fatalf("expected existing specialized route_piece callable, got %q", specializedKey)
	}

	defaultSummary := engine.analyzeCallable(engine.callables[defaultKey])
	engine.summaries[defaultKey] = defaultSummary
	idSummary := engine.analyzeCallable(engine.callables[idKey])
	engine.summaries[idKey] = idSummary
	loginSummary := engine.analyzeCallable(engine.callables[loginKey])
	engine.summaries[loginKey] = loginSummary

	specializedSummary := engine.analyzeCallable(engine.callables[specializedKey])
	if len(specializedSummary.ReturnSources) != 0 {
		t.Fatalf("specialized route_piece summary leaked request return source from sibling literal branch: %+v", specializedSummary.ReturnSources)
	}
}

func TestOutputLiteralSpecializationNarrowsStorageReadIndexes(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-function-storage-specialization.php"), `<?php
function load_piece($mode) {
    switch ($mode) {
        case 'avatar':
            return get_option('avatar_default');
        case 'profile':
            return get_user_meta(0, 'full_name', true);
        default:
            return '';
    }
}
function render_piece() {
    echo load_piece('avatar');
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	loadKey := engine.lookupFunctionKey("", "load_piece")
	if loadKey == "" {
		t.Fatalf("missing load_piece")
	}

	engine.currentBatchName = "output"
	specializedKey := engine.existingSpecializedCallableForLiteralArgs(loadKey, map[int]string{0: "avatar"})
	if specializedKey == "" || specializedKey == loadKey {
		t.Fatalf("expected existing specialized load_piece callable, got %q", specializedKey)
	}

	buckets := sortedStringSet(engine.storageReadBucketsByCallable[specializedKey])
	families := sortedStringSet(engine.storageReadFamiliesByCallable[specializedKey])
	if len(buckets) != 1 || buckets[0] != "option_value[avatar_default]" {
		t.Fatalf("specialized load_piece buckets = %#v, want only option_value[avatar_default]", buckets)
	}
	if len(families) != 1 || families[0] != "option_value" {
		t.Fatalf("specialized load_piece families = %#v, want only option_value", families)
	}
}

func TestOutputLiteralSpecializationBuildsSpecializedMethodCallEdgesForArraySelectorParams(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-method-array-selector-specialization.php"), `<?php
class Renderer {
    public function safe_piece() {
        return 'ok';
    }
    public function danger_piece() {
        echo $_GET['msg'];
        return 'bad';
    }
    public function edit_field($data) {
        $type = $data['type'];
        switch ($type) {
            case 'safe':
                return $this->safe_piece();
            case 'danger':
                return $this->danger_piece();
            default:
                return '';
        }
    }
    public function render() {
        $data = array('type' => 'safe');
        echo $this->edit_field($data);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	editKey := engine.lookupMethodKey(`\Renderer`, "edit_field")
	renderKey := engine.lookupMethodKey(`\Renderer`, "render")
	safeKey := engine.lookupMethodKey(`\Renderer`, "safe_piece")
	dangerKey := engine.lookupMethodKey(`\Renderer`, "danger_piece")
	if editKey == "" || renderKey == "" || safeKey == "" || dangerKey == "" {
		t.Fatalf("missing keys: edit=%q render=%q safe=%q danger=%q", editKey, renderKey, safeKey, dangerKey)
	}

	pathHints := map[int]map[string]string{
		0: {
			literalArgPathHintKey([]string{"type"}): "safe",
		},
	}
	specializedKey := engine.existingSpecializedCallableForLiteralArgsAndPaths(editKey, nil, pathHints)
	if specializedKey == "" || specializedKey == editKey {
		t.Fatalf("expected existing specialized edit_field callable, got %q", specializedKey)
	}

	foundSpecializedCaller := false
	foundBaseCaller := false
	for _, site := range engine.callSiteEdges[renderKey] {
		switch site.callee {
		case specializedKey:
			foundSpecializedCaller = true
		case editKey:
			foundBaseCaller = true
		}
	}
	if !foundSpecializedCaller || foundBaseCaller {
		t.Fatalf("render call sites = %#v, want specialized callee %q only", engine.callSiteEdges[renderKey], specializedKey)
	}
	if _, ok := engine.callEdges[specializedKey][safeKey]; !ok {
		t.Fatalf("specialized edit_field edges = %#v, want %q", engine.callEdges[specializedKey], safeKey)
	}
	if _, ok := engine.callEdges[specializedKey][dangerKey]; ok {
		t.Fatalf("specialized edit_field edges = %#v, should not include %q", engine.callEdges[specializedKey], dangerKey)
	}
}

func TestAnalyzeRootOutputLiteralSpecializationNarrowsArraySelectorMethods(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "output-method-array-selector-analyze-root.php"), `<?php
class Renderer {
    public function edit_field($data) {
        $type = $data['type'];
        switch ($type) {
            case 'safe':
                return 'ok';
            case 'danger':
                echo $_GET['msg'];
                return 'bad';
            default:
                return '';
        }
    }
    public function render() {
        $data = array('type' => 'safe');
        echo $this->edit_field($data);
    }
}

(new Renderer())->render();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected findings from specialized array-selector method: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootPrefixGuardedSiblingOutputBranchDoesNotFire(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "prefix-guarded-sibling-output.php"), `<?php
function sanitize_text_field($value) { return $value; }
function demo($key) {
    $key = sanitize_text_field($key);
    if (0 === strpos($key, 'safe_')) {
        echo 'safe';
        if (0 === strpos($key, 'danger_')) {
            echo $_GET['msg'];
        }
    }
}
demo($_GET['mode']);
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected findings from prefix-guarded sibling branch: %#v", result.Payload.Results)
	}
}

func TestLiteralArgSpecializationSkipsPlaceholderHints(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "placeholder-literal-specialization.php"), `<?php
class MembersService {
    public function prepare_members_data($data) {
        $response = array();
        $response['role'] = isset($data['role']) ? sanitize_text_field($data['role']) : 'subscriber';
        return $response;
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	key := engine.lookupMethodKey(`\MembersService`, "prepare_members_data")
	if key == "" {
		t.Fatalf("missing MembersService::prepare_members_data")
	}
	engine.currentBatchName = "call"
	if got := engine.maybeSpecializeCallableForLiteralArgs(key, map[int]string{0: "{data}"}); got != key {
		t.Fatalf("maybeSpecializeCallableForLiteralArgs() = %q, want %q for placeholder hint", got, key)
	}
}

func TestAnalyzeRootSwitchCasesDoNotShareBranchState(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "switch-branch-state-isolation.php"), `<?php
function demo($mode) {
    switch ($mode) {
        case 'a':
            $x = $_GET['msg'];
            break;
        case 'b':
            echo $x;
            break;
    }
}
demo('b');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected findings from isolated switch cases: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootLiteralSwitchOnlyExecutesMatchingCase(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "switch-literal-case-pruning.php"), `<?php
function render_user_piece($mode) {
    switch ($mode) {
        case 'safe':
            return 'ok';
        case 'danger':
            echo $_GET['msg'];
            break;
        default:
            return '';
    }
}

echo render_user_piece('safe');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"output": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected findings from unmatched switch case: %#v", result.Payload.Results)
	}
}

func TestBuildEngineAttachesCoreSQLClauseFilterEntryPointOnlyForSQLScans(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "posts-where-filter-entrypoint.php"), `<?php
class DemoQuery {
    public function __construct() {
        add_filter('posts_where', array($this, 'redirect_posts_where'), 10, 2);
    }

    public function redirect_posts_where($posts_where, $query) {
        return $posts_where;
    }
}

new DemoQuery();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}

	sqlEngine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(sql): %v", err)
	}
	deleteFiles, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(delete): %v", err)
	}
	deleteEngine, err := buildEngine(root, deleteFiles, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(delete): %v", err)
	}

	methodKey := sqlEngine.lookupMethodKey(`\DemoQuery`, "redirect_posts_where")
	if methodKey == "" {
		t.Fatalf("missing DemoQuery::redirect_posts_where")
	}
	if _, ok := sqlEngine.directPublicCallables[methodKey]; !ok {
		t.Fatalf("sql scan should treat %s as direct public via posts_where filter", methodKey)
	}
	foundSQLFilter := false
	for _, entry := range sqlEngine.contexts[methodKey].EntryPoints {
		if entry.Kind == "filter" && entry.Name == "posts_where" {
			foundSQLFilter = true
			break
		}
	}
	if !foundSQLFilter {
		t.Fatalf("sql context entrypoints = %#v, want filter posts_where", sqlEngine.contexts[methodKey].EntryPoints)
	}
	if _, ok := deleteEngine.directPublicCallables[methodKey]; ok {
		t.Fatalf("delete scan should not treat %s as direct public via posts_where filter", methodKey)
	}
	for _, entry := range deleteEngine.contexts[methodKey].EntryPoints {
		if entry.Kind == "filter" && entry.Name == "posts_where" {
			t.Fatalf("delete context unexpectedly attached posts_where filter entrypoint: %#v", deleteEngine.contexts[methodKey].EntryPoints)
		}
	}
}

func TestBuildEngineSkipsStorageWriterHelperForDirectSQLScans(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-storage-noise.php"), `<?php
class DB {
    public function get_col($sql) {}
}

class LiveSQL {
    public function __construct() {
        add_action('wp_ajax_nopriv_live_sql', array($this, 'run'));
    }

    public function save_meta($value) {
        update_option('demo_sort', $value);
    }

    public function run() {
        $this->save_meta($_GET['noise']);
        $order = $_GET['orderby'];
        $db = new DB();
        $db->get_col("SELECT ID FROM wp_users ORDER BY " . $order);
    }
}

new LiveSQL();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`method::\LiveSQL::run`]; !ok {
		t.Fatalf("LiveSQL::run should stay relevant for direct sql scans: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[`method::\LiveSQL::save_meta`]; ok {
		t.Fatalf("storage-writer side helper should not stay relevant for direct sql scans: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsCallRelevanceIndexesForPureSQLBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-only-indexes.php"), `<?php
class DB {
    public function query($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_sql', array($this, 'run'));
    }

    public function run() {
        $order = $_GET['orderby'];
        $db = new DB();
        $db->query("SELECT * FROM wp_users ORDER BY " . $order);
    }
}

new DemoSQL();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if len(engine.callSinkRelevantUseOrders) != 0 {
		t.Fatalf("pure sql build should skip call relevance indexes: %#v", engine.callSinkRelevantUseOrders)
	}
	if len(engine.callInputConsumingCallables) != 0 {
		t.Fatalf("pure sql build should skip call input-consuming index: %#v", engine.callInputConsumingCallables)
	}
	if len(engine.sqlSinkRelevantUseOrders) == 0 {
		t.Fatalf("pure sql build should still populate sql relevance indexes")
	}
}

func TestBuildEngineSkipsPublicStaticSQLSinkSeedWithoutRequestData(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "public-static-sql.php"), `<?php
class DB {
    public function query($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_sql', array($this, 'run'));
    }

    public function run() {
        $db = new DB();
        $db->query("SELECT * FROM wp_users ORDER BY ID");
    }
}

new DemoSQL();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\DemoSQL`, "run")
	if methodKey == "" {
		t.Fatal("missing DemoSQL::run")
	}
	if _, ok := engine.directPublicCallables[methodKey]; !ok {
		t.Fatalf("DemoSQL::run should still be marked direct public: %#v", engine.directPublicCallables)
	}
	if _, ok := engine.relevantCallables[methodKey]; ok {
		t.Fatalf("public static SQL sink without request data should not stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsCapabilityCheckedSQLSinkSeed(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "cap-checked-sql.php"), `<?php
class DB {
    public function get_col($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_demo_sql', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('manage_options') ) {
            return;
        }
        $db = new DB();
        $db->get_col("SELECT ID FROM wp_users ORDER BY " . $_GET['orderby']);
    }
}

new DemoSQL();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\DemoSQL`, "run")
	if methodKey == "" {
		t.Fatal("missing DemoSQL::run")
	}
	if ctx := engine.contexts[methodKey]; ctx.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", ctx.Access)
	}
	if _, ok := engine.relevantCallables[methodKey]; ok {
		t.Fatalf("capability-checked sql sink should not stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsSQLSinkSeedWhenRequestInputIsNotSQLRelevant(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-irrelevant-request.php"), `<?php
class DB {
    public function get_col($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_sql', array($this, 'run'));
    }

    public function run() {
        $noise = $_GET['noise'];
        if ($noise) {
            $seen = true;
        }
        $db = new DB();
        $db->get_col("SELECT ID FROM wp_users ORDER BY ID");
    }
}

new DemoSQL();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\DemoSQL`, "run")
	if methodKey == "" {
		t.Fatal("missing DemoSQL::run")
	}
	if _, ok := engine.relevantCallables[methodKey]; ok {
		t.Fatalf("sql sink with only irrelevant request input should not stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineKeepsSQLSinkSeedWhenRequestInputFeedsSQLRelevantRoot(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-relevant-request.php"), `<?php
class DB {
    public function get_col($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_sql', array($this, 'run'));
    }

    public function run() {
        $order = $_GET['orderby'];
        $db = new DB();
        $db->get_col("SELECT ID FROM wp_users ORDER BY " . $order);
    }
}

new DemoSQL();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\DemoSQL`, "run")
	if methodKey == "" {
		t.Fatal("missing DemoSQL::run")
	}
	if _, ok := engine.relevantCallables[methodKey]; !ok {
		t.Fatalf("sql sink with relevant request input should stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsSQLReverseCallerWithoutRelevantUse(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-reverse-caller-irrelevant.php"), `<?php
function clause_sink($orderby) {
    return " ORDER BY " . $orderby;
}

function wrapper() {
    clause_sink("ID");
}

add_filter('posts_orderby', 'clause_sink', 10, 1);
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	sinkKey := engine.lookupFunctionKey("", "clause_sink")
	if sinkKey == "" {
		t.Fatal("missing clause_sink")
	}
	wrapperKey := engine.lookupFunctionKey("", "wrapper")
	if wrapperKey == "" {
		t.Fatal("missing wrapper")
	}
	if _, ok := engine.relevantCallables[sinkKey]; !ok {
		t.Fatalf("clause sink should stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[wrapperKey]; ok {
		t.Fatalf("wrapper without SQL-relevant use should not stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsLowValueNonDataSQLHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-nondata-helper.php"), `<?php
class DB {
    public function query($sql) {}
}

function side_effect_helper() {
    update_option('demo_flag', '1');
}

function run_query() {
    side_effect_helper();
    $order = $_GET['orderby'];
    $db = new DB();
    $db->query("SELECT * FROM wp_users ORDER BY " . $order);
}

add_action('wp_ajax_nopriv_demo_sql', 'run_query');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := engine.lookupFunctionKey("", "side_effect_helper")
	if helperKey == "" {
		t.Fatal("missing side_effect_helper")
	}
	for _, key := range engine.relevantCallOrder() {
		if key == helperKey {
			t.Fatalf("non-data side-effect helper should not stay in sql-only relevant call order: %#v", engine.relevantCallOrder())
		}
	}
}

func TestBuildEngineSkipsLowValueNonPublicDirectSQLHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-nonpublic-direct-helper.php"), `<?php
class DB {
    public function get_var($sql) {}
}

function hidden_sql_helper() {
    $db = new DB();
    return $db->get_var("SELECT option_value FROM wp_options");
}

function run_query() {
    $order = $_GET['orderby'];
    $db = new DB();
    $db->get_var("SELECT * FROM wp_users ORDER BY " . $order);
}

add_action('wp_ajax_nopriv_demo_sql', 'run_query');
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	helperKey := engine.lookupFunctionKey("", "hidden_sql_helper")
	if helperKey == "" {
		t.Fatal("missing hidden_sql_helper")
	}
	for _, key := range engine.relevantCallOrder() {
		if key == helperKey {
			t.Fatalf("nonpublic direct sql helper should not stay in sql-only relevant call order: %#v", engine.relevantCallOrder())
		}
	}
}

func TestBuildEngineSkipsInternalSQLDirectSinkWithoutSQLRelevantCallerInput(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-internal-helper-no-sql-input.php"), `<?php
class DB {
    public function query($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_demo_sql', array($this, 'save'));
    }

    protected function cleanup_meta($event_id) {
        $doing_preview = isset($_REQUEST['wp-preview']) && $_REQUEST['wp-preview'] === 'dopreview';
        if ($doing_preview) {
            $seen = true;
        }
        $db = new DB();
        $db->query("DELETE FROM wp_postmeta WHERE meta_key = '_preview_venue_id'");
    }

    public function save() {
        check_admin_referer('demo');
        $event_id = $_POST['post_ID'];
        $this->cleanup_meta($event_id);
        $order = $_POST['orderby'];
        $db = new DB();
        $db->query("SELECT * FROM wp_users ORDER BY " . $order);
    }
}

new DemoSQL();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	saveKey := engine.lookupMethodKey(`\DemoSQL`, "save")
	if saveKey == "" {
		t.Fatal("missing DemoSQL::save")
	}
	if _, ok := engine.relevantCallables[saveKey]; !ok {
		t.Fatalf("public save handler should stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
	helperKey := engine.lookupMethodKey(`\DemoSQL`, "cleanup_meta")
	if helperKey == "" {
		t.Fatal("missing DemoSQL::cleanup_meta")
	}
	if _, ok := engine.relevantCallables[helperKey]; ok {
		t.Fatalf("internal sql helper without SQL-relevant caller input should not stay relevant in sql-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsInternalWriteDirectSinkWithoutFileRelevantCallerInput(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "write-internal-helper-no-file-input.php"), `<?php
class DemoWrite {
    public function __construct() {
        add_action('wp_ajax_demo_write', array($this, 'save'));
    }

    protected function cleanup_tmp($event_id) {
        $doing_preview = isset($_REQUEST['preview']) && $_REQUEST['preview'] === 'yes';
        if ($doing_preview) {
            $seen = true;
        }
        file_put_contents('/tmp/fixed.txt', 'x');
    }

    public function save() {
        check_admin_referer('demo');
        $event_id = $_POST['post_ID'];
        $this->cleanup_tmp($event_id);
        $path = $_FILES['file']['tmp_name'];
        file_put_contents($path, 'ok');
    }
}

new DemoWrite();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"write": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	saveKey := engine.lookupMethodKey(`\DemoWrite`, "save")
	if saveKey == "" {
		t.Fatal("missing DemoWrite::save")
	}
	if _, ok := engine.relevantCallables[saveKey]; !ok {
		t.Fatalf("public save handler should stay relevant in write-only analysis: %#v", engine.relevantCallables)
	}
	helperKey := engine.lookupMethodKey(`\DemoWrite`, "cleanup_tmp")
	if helperKey == "" {
		t.Fatal("missing DemoWrite::cleanup_tmp")
	}
	if _, ok := engine.relevantCallables[helperKey]; ok {
		t.Fatalf("internal write helper without file-relevant caller input should not stay relevant in write-only analysis: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineDoesNotTreatHelperAsDirectSQLClauseSinkFromMergedFilterContext(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sql-clause-helper-context.php"), `<?php
function normalize_order($order) {
    return strtoupper(trim($order)) === 'DESC' ? 'DESC' : 'ASC';
}

function clause_sink($orderby) {
    return normalize_order($orderby);
}

add_filter('posts_orderby', 'clause_sink', 10, 1);
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	sinkKey := engine.lookupFunctionKey("", "clause_sink")
	if sinkKey == "" {
		t.Fatal("missing clause_sink")
	}
	helperKey := engine.lookupFunctionKey("", "normalize_order")
	if helperKey == "" {
		t.Fatal("missing normalize_order")
	}
	if !engine.callableHasDirectSink(engine.callables[sinkKey]) {
		t.Fatalf("registered posts_orderby callback should stay a direct sql clause sink")
	}
	if engine.callableHasDirectSink(engine.callables[helperKey]) {
		t.Fatalf("helper should not inherit direct sql clause sink from merged filter context")
	}
}

func TestBuildEngineKeepsCapabilityCheckedSQLSinkSeedWhenEntrypointIsNoprivAjax(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "cap-checked-sql-nopriv.php"), `<?php
class DB {
    public function get_col($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_sql', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('manage_options') ) {
            return;
        }
        $db = new DB();
        $db->get_col("SELECT ID FROM wp_users ORDER BY " . $_GET['orderby']);
    }
}

new DemoSQL();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	methodKey := engine.lookupMethodKey(`\DemoSQL`, "run")
	if methodKey == "" {
		t.Fatal("missing DemoSQL::run")
	}
	if ctx := engine.contexts[methodKey]; ctx.Access != "capability_checked" {
		t.Fatalf("access = %q, want capability_checked", ctx.Access)
	}
	if _, ok := engine.relevantCallables[methodKey]; !ok {
		t.Fatalf("nopriv ajax sql sink should stay relevant despite merged capability_checked context: %#v", engine.relevantCallables)
	}
}

func TestAnalyzeRootFindsWeakCapabilityAuthenticatedAjaxSQLSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "weak-cap-sql-ajax.php"), `<?php
class DB {
    public function get_results($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_demo_sql', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('read') ) {
            return;
        }
        $value = sanitize_text_field($_POST['ptype']);
        $db = new DB();
        $db->get_results("SELECT * FROM wp_posts WHERE post_type LIKE '%" . $value . "%'");
    }
}

new DemoSQL();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootSkipsStrongCapabilityAuthenticatedAjaxSQLSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "strong-cap-sql-ajax.php"), `<?php
class DB {
    public function get_results($sql) {}
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_demo_sql', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('manage_options') ) {
            return;
        }
        $value = sanitize_text_field($_POST['ptype']);
        $db = new DB();
        $db->get_results("SELECT * FROM wp_posts WHERE post_type LIKE '%" . $value . "%'");
    }
}

new DemoSQL();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootFindsWeakCapabilityAuthenticatedAjaxSQLSinkThroughInlineConstructedReceiver(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "weak-cap-sql-inline-receiver.php"), `<?php
class DB {
    public function get_results($sql) {}
}

class QueryBuilder {
    protected $post_type;

    public function __construct($post_type) {
        $this->post_type = $post_type;
    }

    public function run() {
        $db = new DB();
        $db->get_results("SELECT * FROM wp_posts WHERE post_type LIKE '%" . $this->post_type . "%'");
    }
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_demo_sql', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('read') ) {
            return;
        }
        $value = sanitize_text_field($_POST['ptype']);
        (new QueryBuilder($value))->run();
    }
}

new DemoSQL();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsWeakCapabilityAuthenticatedAjaxSQLSinkThroughNestedReceiverMethod(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "weak-cap-sql-nested-receiver.php"), `<?php
class DB {
    public function get_results($sql) {}
}

class QueryBuilder {
    protected $post_type;

    public function __construct($post_type) {
        $this->post_type = $post_type;
    }

    protected function run_query() {
        $db = new DB();
        $db->get_results("SELECT * FROM wp_posts WHERE post_type LIKE '%" . $this->post_type . "%'");
    }

    public function render() {
        $this->run_query();
        return '';
    }
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_demo_sql', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('read') ) {
            return;
        }
        $value = sanitize_text_field($_POST['ptype']);
        $qb = new QueryBuilder($value);
        $qb->render();
    }
}

new DemoSQL();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootFindsWeakCapabilityAuthenticatedAjaxSQLSinkThroughReceiverBackedLocalFragment(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "weak-cap-sql-receiver-local-fragment.php"), `<?php
class DB {
    public function get_results($sql) {}
}

class QueryBuilder {
    protected $post_type;

    public function __construct($post_type) {
        $this->post_type = $post_type;
    }

    public function run() {
        $fragment = " post_type LIKE '%" . $this->post_type . "%' ";
        $db = new DB();
        $db->get_results("SELECT * FROM wp_posts WHERE 1=1 AND " . $fragment);
    }
}

class DemoSQL {
    public function __construct() {
        add_action('wp_ajax_demo_sql', array($this, 'run'));
    }

    public function run() {
        if ( ! current_user_can('read') ) {
            return;
        }
        $value = sanitize_text_field($_POST['ptype']);
        $qb = new QueryBuilder($value);
        $qb->run();
    }
}

new DemoSQL();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1; findings=%#v", len(result.Payload.Results), result.Payload.Results)
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "tainted-sql-string" {
		t.Fatalf("check_id = %q, want tainted-sql-string", finding.CheckID)
	}
	if finding.Extra.Context.Access != "authenticated" {
		t.Fatalf("access = %q, want authenticated", finding.Extra.Context.Access)
	}
}

func TestAnalyzeRootMarksBlockRenderCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "block.php"), `<?php
function demo_block_render() {
    $path = $_GET['template'];
    require_once $path;
}

register_block_type('demo/block', array(
    'render_callback' => 'demo_block_render',
));
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Kind != "block" {
		t.Fatalf("entrypoint kind = %q, want block", finding.Extra.Context.EntryPoints[0].Kind)
	}
	if finding.Extra.Context.EntryPoints[0].Name != "demo/block" {
		t.Fatalf("entrypoint name = %q, want demo/block", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootMarksFrontControllerHook(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "front-hook.php"), `<?php
function demo_template_redirect() {
    $path = $_GET['template'];
    require_once $path;
}

add_action('template_redirect', 'demo_template_redirect');
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Kind != "front_hook" {
		t.Fatalf("entrypoint kind = %q, want front_hook", finding.Extra.Context.EntryPoints[0].Kind)
	}
	if finding.Extra.Context.EntryPoints[0].Name != "template_redirect" {
		t.Fatalf("entrypoint name = %q, want template_redirect", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootMarksPluginsLoadedLifecycleHook(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "plugins-loaded-hook.php"), `<?php
class DemoPluginsLoaded {
    public function __construct() {
        add_action('plugins_loaded', array($this, 'handle'));
    }

    public function handle() {
        $path = $_GET['template'];
        require_once $path;
    }
}

new DemoPluginsLoaded();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Kind != "front_hook" {
		t.Fatalf("entrypoint kind = %q, want front_hook", finding.Extra.Context.EntryPoints[0].Kind)
	}
	if finding.Extra.Context.EntryPoints[0].Name != "plugins_loaded" {
		t.Fatalf("entrypoint name = %q, want plugins_loaded", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootFindsWriteSinkAfterDecodeDecryptChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "decode-decrypt-write.php"), `<?php
class ExternalCipher {
    public function decrypt($value) {}
}

class DemoDecodeDecrypt {
    public function handle() {
        $cipher = new ExternalCipher();
        $body = base64_decode($_POST['payload']);
        $data = $cipher->decrypt($body);
        $params = json_decode($data, true);
        rename('/tmp/demo.tmp', $params['name']);
    }
}

$demo = new DemoDecodeDecrypt();
$demo->handle();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{AllowedSinkOps: map[string]struct{}{"write": {}}})
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 12 {
		t.Fatalf("sink line = %d, want 12", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 9 {
		t.Fatalf("source line = %d, want 9", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootMarksDirectFileEntryPoint(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "direct.php"), `<?php
$path = $_GET['template'];
require_once $path;
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if len(finding.Extra.Context.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(finding.Extra.Context.EntryPoints))
	}
	if finding.Extra.Context.EntryPoints[0].Kind != "file" {
		t.Fatalf("entrypoint kind = %q, want file", finding.Extra.Context.EntryPoints[0].Kind)
	}
	if finding.Extra.Context.EntryPoints[0].Name != "direct.php" {
		t.Fatalf("entrypoint name = %q, want direct.php", finding.Extra.Context.EntryPoints[0].Name)
	}
}

func TestAnalyzeRootDispatchesDoActionToRegisteredCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-dispatch.php"), `<?php
class ActionDispatchDemo {
    public function __construct() {
        add_action('demo_delete', array($this, 'handle'));
    }

    public function handle($path) {
        unlink($path);
    }
}

$demo = new ActionDispatchDemo();
do_action('demo_delete', $_POST['path']);
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "request-path-read-delete" {
		t.Fatalf("check_id = %q, want request-path-read-delete", finding.CheckID)
	}
	if finding.Start.Line != 8 {
		t.Fatalf("sink line = %d, want 8", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 13 {
		t.Fatalf("source line = %d, want 13", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootDispatchesApplyFiltersToRegisteredCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "filter-dispatch.php"), `<?php
function demo_filter($path) {
    return $path;
}

add_filter('demo_filter', 'demo_filter');
$path = apply_filters('demo_filter', $_GET['path']);
unlink($path);
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.CheckID != "request-path-read-delete" {
		t.Fatalf("check_id = %q, want request-path-read-delete", finding.CheckID)
	}
	if finding.Start.Line != 8 {
		t.Fatalf("sink line = %d, want 8", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 7 {
		t.Fatalf("source line = %d, want 7", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsActionSinkInsideApplyFiltersCallbackUsingRequestGetter(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "filter-action-callback.php"), `<?php
add_action('rest_api_init', function () {
    register_rest_route('demo/v1', '/x', [
        'methods' => 'POST',
        'callback' => 'demo_handle',
        'permission_callback' => '__return_true',
    ]);
});

add_filter('demo_payload', 'demo_filter_sink');

function demo_handle($request) {
    return apply_filters('demo_payload', array(), array(), $request);
}

function demo_filter_sink($payload, $args, $request) {
    $value = $request->get_param('payload');
    update_option('demo_value', $value);
    return $payload;
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
			continue
		}
		if finding.Start.Line != 18 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 17 {
			continue
		}
		if finding.Extra.Trace.Callable != `\demo_filter_sink` {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find action sink inside apply_filters callback using request getter: %#v", result.Payload.Results)
	}
}

func TestBuildEngineSkipsLiteralOnlyFilterCallbackForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "filter-call-literal.php"), `<?php
function demo_filter_sink($payload) {
    unserialize($payload);
}

class FilterCallLiteralDemo {
    public function __construct() {
        add_action('wp_ajax_demo_filter_call_literal', array($this, 'run'));
        add_filter('demo_payload', 'demo_filter_sink');
    }

    public function run() {
        $payload = array('safe' => 'value');
        apply_filters('demo_payload', $payload);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`function::\demo_filter_sink`]; ok {
		t.Fatalf("literal-only filter callback should not stay relevant for call sinks: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineKeepsRuntimeFilterCallbackForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "filter-call-runtime.php"), `<?php
function demo_filter_sink($payload) {
    unserialize($payload);
}

class FilterCallRuntimeDemo {
    public function __construct() {
        add_action('wp_ajax_demo_filter_call_runtime', array($this, 'run'));
        add_filter('demo_payload', 'demo_filter_sink');
    }

    public function run() {
        apply_filters('demo_payload', $_POST['payload']);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables[`function::\demo_filter_sink`]; !ok {
		t.Fatalf("runtime filter callback should stay relevant for call sinks: %#v", engine.relevantCallables)
	}
}

func TestBuildEngineSkipsUnregisteredFilterPayloadForCallBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "filter-call-unregistered.php"), `<?php
class FilterCallUnregisteredDemo {
    public function __construct() {
        add_action('wp_ajax_demo_filter_call_unregistered', array($this, 'run'));
    }

    public function run() {
        apply_filters('demo_payload', $_POST['payload']);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	runKey := `method::\FilterCallUnregisteredDemo::run`
	if engine.callInputConsumingCallables[runKey] {
		t.Fatalf("unregistered filter payload should not mark caller as consuming call input: %#v", engine.callInputConsumingCallables)
	}
	if _, ok := engine.relevantCallables[runKey]; ok {
		t.Fatalf("caller with unregistered filter payload should not stay relevant in pure call analysis: %#v", engine.relevantCallables)
	}
}

func TestAnalyzeCallableSkipsIrrelevantActionHookCallbacksInActionBatch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "action-hook-relevant-only.php"), `<?php
function demo_relevant_action($payload) {
    update_option('demo_value', $payload);
}

function demo_irrelevant_action() {
    file_get_contents('/tmp/demo.txt');
}

class ActionHookDemo {
    public function __construct() {
        add_action('wp_ajax_nopriv_demo_action_hook', array($this, 'run'));
        add_action('demo_admin_page', 'demo_relevant_action');
        add_action('demo_admin_page', 'demo_irrelevant_action');
    }

    public function run() {
        do_action('demo_admin_page', $_POST['value']);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	relevantKey := `function::\demo_relevant_action`
	irrelevantKey := `function::\demo_irrelevant_action`
	runKey := `method::\ActionHookDemo::run`
	if _, ok := engine.relevantCallables[relevantKey]; !ok {
		t.Fatalf("relevant action hook callback should stay relevant: %#v", engine.relevantCallables)
	}
	if _, ok := engine.relevantCallables[irrelevantKey]; ok {
		t.Fatalf("irrelevant action hook callback should not stay relevant: %#v", engine.relevantCallables)
	}

	if !summaryHasNoEffects(engine.summaries[irrelevantKey]) {
		t.Fatalf("expected irrelevant callback summary to start empty, got %#v", engine.summaries[irrelevantKey])
	}
	summary := engine.analyzeCallable(engine.callables[runKey])
	if len(summary.SourceFindings) == 0 {
		t.Fatalf("dispatcher should still replay relevant action callback: %#v", summary)
	}
	if !summaryHasNoEffects(engine.summaries[irrelevantKey]) {
		t.Fatalf("irrelevant callback should not be warmed by action-hook dispatch: %#v", engine.summaries[irrelevantKey])
	}
}

func TestAnalyzeRootDispatchesCallUserFuncInstanceCallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-user-func.php"), `<?php
class DispatchHelperDemo {
    public function run() {
        call_user_func(array($this, 'handle'), $_GET['path']);
    }

    public function handle($path) {
        unlink($path);
    }
}

(new DispatchHelperDemo())->run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 8 {
		t.Fatalf("sink line = %d, want 8", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 4 {
		t.Fatalf("source line = %d, want 4", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootDispatchesForwardStaticCall(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "forward-static-call.php"), `<?php
class StaticDispatchDemo {
    public static function handle($path) {
        unlink($path);
    }
}

forward_static_call(array(StaticDispatchDemo::class, 'handle'), $_GET['path']);
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 4 {
		t.Fatalf("sink line = %d, want 4", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 8 {
		t.Fatalf("source line = %d, want 8", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootDispatchesDynamicStaticCallWithLiteralPrefix(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "dynamic-static-call.php"), `<?php
class DynamicStaticDispatchDemo {
    public static function perform() {
        $action = strtolower($_GET['mode']);
        $action = 'action__' . $action;
        if (method_exists(__CLASS__, $action)) {
            self::$action($_GET['plugin']);
        }
    }

    public static function action__activate_plugin($plugin) {
        activate_plugin($plugin);
    }
}

DynamicStaticDispatchDemo::perform();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 12 {
		t.Fatalf("sink line = %d, want 12", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 7 {
		t.Fatalf("source line = %d, want 7", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsInstallerLikeInstallAction(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "installer-like-install.php"), `<?php
class DemoUpgrader {
    public function install($plugin) {
    }
}

function run_install() {
    $installer = new DemoUpgrader();
    $installer->install($_GET['plugin']);
}

run_install();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 9 {
		t.Fatalf("sink line = %d, want 9", finding.Start.Line)
	}
}

func TestAnalyzeRootDoesNotFlagNonInstallerInstallMethod(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "non-installer-install.php"), `<?php
class WidgetDemo {
    public function install($plugin) {
    }
}

function run_widget_install() {
    $widget = new WidgetDemo();
    $widget->install($_GET['plugin']);
}

run_widget_install();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0", len(result.Payload.Results))
	}
}

func TestAnalyzeRootFindsInstallerLikeInstallViaAssignedPropertyFetch(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "installer-property-fetch.php"), `<?php
class Request {
    public static function get($key) {
    }
}

class TT {
    public static function toString($value) {
        return $value;
    }
}

class DemoUpgrader {
    public function install($package) {
    }
}

function plugins_api($type, $args) {
    return (object) array('download_link' => $args['slug']);
}

function run_install() {
    $plugin = Request::get('plugin') ? Request::get('plugin') : '';
    $plugin = TT::toString($plugin);
    if (!empty($plugin)) {
        $plugin_slug = preg_replace('@([a-zA-Z-\d]+)[\\/].*@', '$1', $plugin);
        $result = plugins_api('plugin_information', array('slug' => $plugin_slug));
        $installer = new DemoUpgrader();
        $download_link = is_object($result) ? $result->download_link : false;
        if ($download_link) {
            $installer->install($download_link);
        }
    }
}

run_install();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 31 {
		t.Fatalf("sink line = %d, want 31", finding.Start.Line)
	}
}

func TestAnalyzeRootDispatchesCallUserFuncArray(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "call-user-func-array.php"), `<?php
class DispatchArrayDemo {
    public function run() {
        call_user_func_array(array($this, 'handle'), array($_GET['path']));
    }

    public function handle($path) {
        unlink($path);
    }
}

(new DispatchArrayDemo())->run();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 8 {
		t.Fatalf("sink line = %d, want 8", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 4 {
		t.Fatalf("source line = %d, want 4", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootFindsUnsafeUseForTaintedArrayCallbackTarget(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "tainted-array-callback.php"), `<?php
function controller() {
    $callback = array(
        'class' => $_GET['class'],
        'method' => $_GET['method'],
    );
    $class = $callback['class'];
    $method = $callback['method'];
    if (is_callable(array($class, $method))) {
        call_user_func(array($class, $method), $_GET['arg']);
    }
}

controller();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"call": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "unsafe-use" {
			continue
		}
		if finding.Start.Line != 10 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 4 && finding.Extra.Trace.Source.Line != 5 {
			continue
		}
		found = true
	}
	if !found {
		t.Fatalf("results = %#v, want unsafe-use at line 10 from line 4 or 5", result.Payload.Results)
	}
}

func TestAnalyzeRootPreservesStructuredReturnThroughArrayMerge(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "array-merge-structural.php"), `<?php
function merge_fields($current_entry_fields, $additional_fields_data) {
    return array_merge($current_entry_fields, $additional_fields_data);
}

function delete_uploads($fields) {
    foreach ($fields as $field) {
        $path = $field['value']['file']['file_path'];
        unlink($path);
    }
}

$extra = array(
    array('value' => array('file' => array('file_path' => $_POST['path']))),
    array('value' => array('text' => $_POST['text'])),
);
delete_uploads(merge_fields(array(), $extra));
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line == 9 && finding.Extra.Trace.Source.Line == 14 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not preserve merged file-path carrier; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootTracksStaticStorageReloadDeleteChain(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "storage.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

class Entry {
    public $meta_data = array();

    public function __construct($entry_id = 0) {
        if ($entry_id) {
            $this->load_meta();
        }
    }

    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
            $this->meta_data[] = array('value' => $value);
        }
    }

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['tmp_name']);
        }
    }
}

class Demo {
    public static $info = array();

    public function run() {
        $upload = $_FILES['file'];
        self::$info['field_data_array'][] = array(
            'name' => 'upload',
            'value' => array('file' => $upload),
        );
        $entry = new Entry();
        $entry->set_fields(self::$info['field_data_array']);
        $reloaded = new Entry(1);
        Entry::delete_files($reloaded);
    }
}

(new Demo())->run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 34 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 43 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find storage reload delete trace at sink line 34 from source line 43: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootReportsStoredWriteContextForCrossRequestDelete(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "stored-delete.php"), `<?php
function save_demo() {
    if ( ! is_user_logged_in() ) {
        update_option('demo_path', $_POST['path']);
    }
}

function delete_demo() {
    if ( current_user_can('manage_options') ) {
        unlink(get_option('demo_path'));
    }
}

save_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	var finding Finding
	found := false
	for _, item := range result.Payload.Results {
		if strings.HasSuffix(item.Path, "stored-delete.php") && item.Start.Line == 10 && item.Extra.Trace.Source.Path == "stored-delete.php" && item.Extra.Trace.Source.Line == 4 {
			finding = item
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not find stored delete trace from stored-delete.php:4 to stored-delete.php:10: %#v", result.Payload.Results)
	}
	if finding.Extra.Context.Access != "capability_checked" {
		t.Fatalf("trigger access = %q, want capability_checked", finding.Extra.Context.Access)
	}
	if len(finding.Extra.Context.CapabilityChecks) != 1 {
		t.Fatalf("trigger capability checks = %d, want 1", len(finding.Extra.Context.CapabilityChecks))
	}
	if finding.Extra.StoredWriteContext.Access != "unauthenticated" {
		t.Fatalf("stored write access = %q, want unauthenticated", finding.Extra.StoredWriteContext.Access)
	}
	if len(finding.Extra.StoredWriteContext.UnauthChecks) != 1 {
		t.Fatalf("stored write unauth checks = %d, want 1", len(finding.Extra.StoredWriteContext.UnauthChecks))
	}
}

func TestAnalyzeRootTracksWrapperColumnCrossRequestDelete(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "wrapper-column-delete.php"), `<?php
class DB {
    public function insert($table, $row) {}
    public function get_results($query) {}
}

class Base {
    protected $db;

    public function __construct() {
        $this->db = new DB();
    }

    public function use_insert($data) {
        $prepared = array(
            'data' => $data,
            'format' => array('%s'),
        );
        $this->db->insert('entries', $prepared['data']);
    }

    public function get_results($where = array(), $columns = '*') {
        return $this->db->get_results("SELECT " . $columns . " FROM entries");
    }
}

class Entries extends Base {
    public function get_schema() {
        return array(
            'form_data' => array('type' => 'array'),
        );
    }

    public static function add($data) {
        $instance = new Entries();
        return $instance->use_insert($data);
    }

    public static function get_form_data($entry_id) {
        $rows = (new Entries())->get_results(array('ID' => $entry_id), 'form_data');
        return $rows[0]['form_data'];
    }
}

function submit_demo() {
    if ( ! is_user_logged_in() ) {
        $submission = array(
            'file' => array('url' => $_POST['path']),
        );
        $entries_data = array(
            'form_data' => $submission,
        );
        Entries::add($entries_data);
    }
}

function delete_demo() {
    if ( current_user_can('manage_options') ) {
        $form_data = Entries::get_form_data(1);
        unlink($form_data['file']['url']);
    }
}

submit_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, item := range result.Payload.Results {
		if !strings.HasSuffix(item.Path, "wrapper-column-delete.php") || item.Start.Line != 60 {
			continue
		}
		if item.Extra.Trace.Source.Path != "wrapper-column-delete.php" || item.Extra.Trace.Source.Line != 48 {
			continue
		}
		if item.Extra.Context.Access != "capability_checked" {
			t.Fatalf("trigger access = %q, want capability_checked", item.Extra.Context.Access)
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find wrapper-column cross-request trace: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "json-wrapper-dynamic-delete.php"), `<?php
class DB {
    public function insert($table, $row) {}
    public function get_results($query) {}
}

class Helper {
    public static function get_array_value($data) {
        if (is_array($data)) {
            return $data;
        }
        if (is_null($data)) {
            return array();
        }
        return (array) $data;
    }

    public static function encode_json($data) {
        return json_encode($data);
    }
}

class Base {
    protected $db;
    protected $table_name = 'entries';

    public function __construct() {
        $this->db = new DB();
    }

    public function get_tablename() {
        return $this->table_name;
    }

    public function get_schema() {
        return array(
            'form_id' => array('type' => 'number'),
            'form_data' => array('type' => 'array'),
        );
    }

    protected function encode_by_datatype($value, $type) {
        switch ($type) {
            case 'array':
                return Helper::encode_json(Helper::get_array_value($value));
            default:
                return $value;
        }
    }

    protected function decode_by_datatype($data) {
        $_data = array();
        foreach ($this->get_schema() as $key => $schema) {
            if (!array_key_exists($key, $data)) {
                continue;
            }
            $_data[$key] = 'array' === $schema['type']
                ? Helper::get_array_value(json_decode($data[$key], true))
                : $data[$key];
        }
        return $_data;
    }

    protected function prepare_data($data) {
        $_data = array();
        foreach ($this->get_schema() as $key => $schema) {
            if (!isset($data[$key])) {
                continue;
            }
            $_data[$key] = $this->encode_by_datatype($data[$key], $schema['type']);
        }
        return array('data' => $_data);
    }

    public function use_insert($data) {
        $prepared = $this->prepare_data($data);
        return $this->db->insert('entries', $prepared['data']);
    }

    public function get_results($where = array(), $columns = '*') {
        $rows = $this->db->get_results("SELECT " . $columns . " FROM entries");
        return array_map(array($this, 'decode_by_datatype'), $rows);
    }
}

class Entries extends Base {
    public static function add($data) {
        $instance = new Entries();
        return $instance->use_insert($data);
    }

    public static function get_form_data($entry_id) {
        $result = (new Entries())->get_results(array('ID' => $entry_id), 'form_data');
        return isset($result[0]) && is_array($result[0]) ? Helper::get_array_value($result[0]['form_data']) : array();
    }
}

function submit_demo() {
    if ( ! is_user_logged_in() ) {
        $form_data = array(
            'srfm-upload-lbl-demo' => array($_POST['path']),
        );
        $submission_data = array();
        $form_data_keys = array_keys($form_data);
        $form_data_count = count($form_data);
        for ($i = 0; $i < $form_data_count; $i++) {
            $key = strval($form_data_keys[$i]);
            $value = $form_data[$key];
            if (is_array($value)) {
                $submission_data[$key] = array_map(
                    static function ($val) {
                        return rawurlencode($val);
                    },
                    $value
                );
            } else {
                $submission_data[$key] = $value;
            }
        }
        Entries::add(array(
            'form_id' => 1,
            'form_data' => $submission_data,
        ));
    }
}

function delete_demo() {
    if ( current_user_can('manage_options') ) {
        $form_data = Entries::get_form_data(1);
        foreach ($form_data as $field_name => $value) {
            if (false === strpos($field_name, 'srfm-upload') && ! is_array($value)) {
                continue;
            }
            foreach ($value as $file_url) {
                unlink(urldecode($file_url));
            }
        }
    }
}

submit_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, item := range result.Payload.Results {
		if !strings.HasSuffix(item.Path, "json-wrapper-dynamic-delete.php") || item.Start.Line != 135 {
			continue
		}
		if item.CheckID != "request-path-read-delete" {
			t.Fatalf("check_id = %q, want request-path-read-delete", item.CheckID)
		}
		if item.Extra.Trace.Source.Path != "json-wrapper-dynamic-delete.php" || item.Extra.Trace.Source.Line != 101 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find json-wrapper-dynamic cross-request delete trace: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootTracksURLToPathHelperCrossRequestDelete(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "url-to-path-delete.php"), `<?php
function wp_normalize_path($path) {
    return $path;
}

function wp_json_encode($data, $flags = 0) {
    return json_encode($data);
}

class DB {
    public function insert($table, $row) {}
    public function get_results($query) {}
}

class Helper {
    public static function get_array_value($data) {
        if (is_array($data)) {
            return $data;
        }
        if (is_null($data)) {
            return array();
        }
        return (array) $data;
    }

    public static function encode_json($data) {
        return wp_json_encode($data);
    }

    public static function convert_fileurl_to_filepath($file_url) {
        return wp_normalize_path(str_replace('https://example.test/wp-content/uploads', '/var/www/wp-content/uploads', $file_url));
    }
}

class Base {
    protected $db;

    public function __construct() {
        $this->db = new DB();
    }

    public function get_schema() {
        return array(
            'form_id' => array('type' => 'number'),
            'form_data' => array('type' => 'array'),
        );
    }

    protected function encode_by_datatype($value, $type) {
        switch ($type) {
            case 'array':
                return Helper::encode_json(Helper::get_array_value($value));
            default:
                return $value;
        }
    }

    protected function decode_by_datatype($data) {
        $_data = array();
        foreach ($this->get_schema() as $key => $schema) {
            if (!array_key_exists($key, $data)) {
                continue;
            }
            $_data[$key] = 'array' === $schema['type']
                ? Helper::get_array_value(json_decode($data[$key], true))
                : $data[$key];
        }
        return $_data;
    }

    protected function prepare_data($data) {
        $_data = array();
        foreach ($this->get_schema() as $key => $schema) {
            if (!isset($data[$key])) {
                continue;
            }
            $_data[$key] = $this->encode_by_datatype($data[$key], $schema['type']);
        }
        return array('data' => $_data);
    }

    public function use_insert($data) {
        $prepared = $this->prepare_data($data);
        return $this->db->insert('entries', $prepared['data']);
    }

    public function get_results($where = array(), $columns = '*') {
        $rows = $this->db->get_results("SELECT " . $columns . " FROM entries");
        return array_map(array($this, 'decode_by_datatype'), $rows);
    }
}

class Entries extends Base {
    public static function add($data) {
        $instance = new Entries();
        return $instance->use_insert($data);
    }

    public static function get_form_data($entry_id) {
        $result = (new Entries())->get_results(array('ID' => $entry_id), 'form_data');
        return isset($result[0]) && is_array($result[0]) ? Helper::get_array_value($result[0]['form_data']) : array();
    }
}

function submit_demo() {
    if ( ! is_user_logged_in() ) {
        $form_data = array(
            'srfm-upload-lbl-demo' => array(rawurlencode($_POST['path'])),
        );
        Entries::add(array(
            'form_id' => 1,
            'form_data' => $form_data,
        ));
    }
}

function delete_demo() {
    if ( current_user_can('manage_options') ) {
        $form_data = Entries::get_form_data(1);
        foreach ($form_data as $field_name => $value) {
            if (false === strpos($field_name, 'srfm-upload') && ! is_array($value)) {
                continue;
            }
            foreach ($value as $file_url) {
                $file_path = Helper::convert_fileurl_to_filepath(urldecode($file_url));
                unlink($file_path);
            }
        }
    }
}

submit_demo();
delete_demo();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, item := range result.Payload.Results {
		if !strings.HasSuffix(item.Path, "url-to-path-delete.php") || item.Start.Line != 126 {
			continue
		}
		if item.Extra.Trace.Source.Path != "url-to-path-delete.php" || item.Extra.Trace.Source.Line != 108 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find helper-wrapped url-to-path delete trace: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootInfersFactoryReturnClassFromLiteralProperty(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "factory.php"), `<?php
class UploadField {
    public $slug = 'upload';

    public function resolve($path) {
        return $path;
    }
}

class DemoCore {
    public static function get_field_object($type) {
        return null;
    }
}

class Demo {
    public function run() {
        $field = DemoCore::get_field_object('upload');
        require_once $field->resolve($_GET['template']);
    }
}

(new Demo())->run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 19 {
		t.Fatalf("sink line = %d, want 19", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 19 {
		t.Fatalf("source line = %d, want 19", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootTracksStaticPropertyWritesAcrossMethodCalls(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "static-flow.php"), `<?php
class Entry {
    public $meta_data = array();

    public function set_fields($meta_array) {
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $this->meta_data[] = array('value' => $value);
        }
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['tmp_name']);
        }
    }
}

class Demo {
    public static $info = array();

    public static function stash() {
        self::$info['field_data_array'][] = array(
            'value' => array(
                'file' => $_FILES['upload'],
            ),
        );
    }

    public static function save() {
        $entry = new Entry();
        $entry->set_fields(self::$info['field_data_array']);
        Entry::delete_files($entry);
    }

    public static function run() {
        self::stash();
        self::save();
    }
}

Demo::run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 15 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 26 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find static property write trace to sink line 15 from source line 26: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootKeepsArrayKeysSeparate(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "keys.php"), `<?php
class Demo {
    public function run() {
        $state = array();
        $state['tainted'] = $_GET['template'];
        $state['safe'] = '/tmp/safe.php';
        require_once $state['safe'];
    }
}

(new Demo())->run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("findings = %d, want 0: %#v", len(result.Payload.Results), result.Payload.Results)
	}
}

func TestAnalyzeRootPreservesNestedArrayPathsAcrossAssignmentAndParamReturn(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "copy-return.php"), `<?php
class Entry {
    public $meta_data = array();

    public function set_fields($meta_array) {
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $this->meta_data[] = array('value' => $value);
        }
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['tmp_name']);
        }
    }
}

class Demo {
    public static $info = array();

    private static function passthrough($data) {
        return $data;
    }

    public static function run() {
        self::$info['field_data_array'][] = array(
            'name' => 'upload',
            'value' => array(
                'file' => $_FILES['upload'],
            ),
        );
        $added_data_array = self::$info['field_data_array'];
        $added_data_array = self::passthrough($added_data_array);
        $entry = new Entry();
        $entry->set_fields($added_data_array);
        Entry::delete_files($entry);
    }
}

Demo::run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 15 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 31 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not preserve nested array path through assignment and return: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootTracksMethodReturnClassIntoReceiverCall(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "return-class.php"), `<?php
class Entry {
    public $meta_data = array();

    public function set_fields($meta_array) {
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $this->meta_data[] = array('value' => $value);
        }
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['tmp_name']);
        }
    }
}

class Demo {
    private static function get_entry() {
        return new Entry();
    }

    public static function run() {
        $fields = array(
            array(
                'value' => array(
                    'file' => $_FILES['upload'],
                ),
            ),
        );
        $entry = self::get_entry();
        $entry->set_fields($fields);
        Entry::delete_files($entry);
    }
}

Demo::run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 15 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 29 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not keep method return class across receiver call: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSharesInheritedStaticPropertiesAcrossClasses(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "inherited-static.php"), `<?php
abstract class BaseDemo {
    public static $prepared = array();

    protected static function seed() {
        self::$prepared['file'] = $_GET['template'];
    }
}

class ChildDemo extends BaseDemo {
    public static function run() {
        self::seed();
        require_once self::$prepared['file'];
    }
}

ChildDemo::run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Payload.Results))
	}
	finding := result.Payload.Results[0]
	if finding.Start.Line != 13 {
		t.Fatalf("sink line = %d, want 13", finding.Start.Line)
	}
	if finding.Extra.Trace.Source.Line != 6 {
		t.Fatalf("source line = %d, want 6", finding.Extra.Trace.Source.Line)
	}
}

func TestAnalyzeRootKeepsStructuredStorageNarrowAtDeleteSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "structured-storage.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

class Entry {
    public $meta_data = array();

    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
        }
    }

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path']);
        }
    }
}

class Demo {
    public static function run() {
        $entry = new Entry();
        $entry->set_fields(array(
            array('value' => array('file' => array('file_path' => $_FILES['upload']))),
            array('value' => array('text' => $_SERVER['HTTP_USER_AGENT'])),
        ));
        $reloaded = new Entry();
        $reloaded->load_meta();
        Entry::delete_files($reloaded);
    }
}

Demo::run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 27 {
			continue
		}
		if finding.Extra.Trace.Source.Line == 37 {
			t.Fatalf("unrelated scalar storage value reached file_path sink: %#v", result.Payload.Results)
		}
		if finding.Extra.Trace.Source.Line == 36 {
			return
		}
	}
	t.Fatalf("did not find structured storage trace from upload source: %#v", result.Payload.Results)
}

func TestAnalyzeRootDoesNotTreatSiblingArrayKeyAsTainted(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sibling-array.php"), `<?php
function run() {
    $payload = array();
    $payload['file']['file_path'] = $_GET['path'];
    unlink($payload['text']);
}

run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected sibling-key finding(s): %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootDoesNotTreatSiblingPropertyAsTainted(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "sibling-property.php"), `<?php
class Demo {
    public $safe;
    public $other;
}

function run() {
    $entry = new Demo();
    $entry->safe = $_GET['path'];
    unlink($entry->other);
}

run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected sibling-property finding(s): %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootDoesNotTreatAliasedSiblingArrayKeyAsTainted(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "aliased-sibling-array.php"), `<?php
function run() {
    $payload = array();
    $payload['file']['file_path'] = $_GET['path'];
    $copy = $payload;
    unlink($copy['text']);
}

run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected aliased sibling-key finding(s): %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootDoesNotTreatAliasedSiblingPropertyAsTainted(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "aliased-sibling-property.php"), `<?php
class Demo {
    public $safe;
    public $other;
}

function run() {
    $entry = new Demo();
    $entry->safe = $_GET['path'];
    $copy = $entry;
    unlink($copy->other);
}

run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected aliased sibling-property finding(s): %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootDoesNotTreatAliasedNestedPropertyContainerSiblingAsTainted(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "aliased-nested-property-container.php"), `<?php
class Demo {
    public $meta = array();
}

function run() {
    $entry = new Demo();
    $entry->meta['file']['file_path'] = $_GET['path'];
    $copy = $entry->meta;
    unlink($copy['text']);
}

run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) != 0 {
		t.Fatalf("unexpected aliased nested property sibling finding(s): %#v", result.Payload.Results)
	}
}

func TestResolveArgumentPathOriginsStaticUsesCurrentStructuralState(t *testing.T) {
	uploadOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 14}})
	textOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 15}})

	state := analysisState{
		engine:  &engine{},
		current: callable{SourcePath: "demo.php"},
		propTaint: map[string]originSet{
			"post_data[upload_hidden][file][file_path]": uploadOrigin,
			"post_data[text]": textOrigin,
		},
	}

	node := &ast.ExprVariable{Name: "post_data"}
	got := state.resolveArgumentPathOriginsStatic(node, "[upload_hidden][file][file_path]", nil)
	if len(got) != 1 {
		t.Fatalf("origins = %d, want 1", len(got))
	}
	for _, item := range got.sorted() {
		if item.source.Line != 14 {
			t.Fatalf("source line = %d, want 14", item.source.Line)
		}
	}
}

func TestEvalExprTreatsMissingStructuredArrayKeyAsEmpty(t *testing.T) {
	requestOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 7}})
	state := analysisState{
		engine:  &engine{},
		current: callable{SourcePath: "demo.php"},
		varTaint: map[string]originSet{
			"membership_detail": requestOrigin,
		},
		propTaint: map[string]originSet{
			"membership_detail[id]":         makeOriginSet(origin{kind: originSource, source: Location{Path: "db.php", Line: 10}, persistentRead: true}),
			"membership_detail[meta_value]": makeOriginSet(origin{kind: originSource, source: Location{Path: "db.php", Line: 11}, persistentRead: true}),
		},
	}

	fetch := &ast.ExprArrayDimFetch{
		Var: &ast.ExprVariable{Name: "membership_detail"},
		Dim: &ast.ScalarString{Value: "role"},
	}

	if got := state.evalExpr(fetch); len(got) != 0 {
		t.Fatalf("missing structured key should be empty, got %#v", got)
	}
}

func TestEvalExprKeepsWildcardStructuredArrayKeyFallback(t *testing.T) {
	requestOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 7}})
	state := analysisState{
		engine:  &engine{},
		current: callable{SourcePath: "demo.php"},
		varTaint: map[string]originSet{
			"membership_detail": requestOrigin,
		},
		propTaint: map[string]originSet{
			"membership_detail[*]": requestOrigin,
		},
	}

	fetch := &ast.ExprArrayDimFetch{
		Var: &ast.ExprVariable{Name: "membership_detail"},
		Dim: &ast.ScalarString{Value: "role"},
	}

	if got := state.evalExpr(fetch); len(got) == 0 {
		t.Fatal("wildcard structured key should stay reachable")
	}
}

func TestApplyPostAssignEffectsReplaysConstructorReceiverStructure(t *testing.T) {
	engine := &engine{
		methods: map[string]map[string]string{
			`\Entry`: {
				"__construct": `method::\Entry::__construct`,
			},
		},
		classParents: map[string]string{},
		summaries: map[string]summary{
			`method::\Entry::__construct`: {
				ReceiverWrites: map[string]taintSummary{},
				ReceiverPathWrites: map[string]taintSummary{
					"meta_data[file][file_path]": {
						Sources: []Location{{Path: "ctor.php", Line: 7}},
					},
				},
				ReceiverStorageLinks: map[string]string{
					"meta_data[]": "meta_value",
				},
			},
		},
		storagePaths: map[string]originSet{
			"meta_value[file][file_path]": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "store.php", Line: 11},
			}),
		},
	}
	state := analysisState{
		engine:            engine,
		current:           callable{Class: `\Demo`},
		propTaint:         map[string]originSet{},
		storagePathWrites: map[string]originSet{},
	}

	target := &ast.ExprVariable{Name: "entry"}
	expr := &ast.ExprNew{
		Class: &ast.Name{Name: "Entry"},
		Args: []ast.Node{
			&ast.Arg{Value: &ast.ExprVariable{Name: "id"}},
		},
	}

	state.applyPostAssignEffects(target, expr)

	if got := state.propTaint["entry.meta_data[file][file_path]"]; len(got) != 1 {
		t.Fatalf("constructor receiver path writes = %d, want 1", len(got))
	}
	if got := state.propTaint["entry.meta_data[][file][file_path]"]; len(got) != 1 {
		t.Fatalf("constructor storage-linked paths = %d, want 1", len(got))
	}
	for _, item := range state.propTaint["entry.meta_data[][file][file_path]"] {
		if !item.persistentRead {
			t.Fatal("constructor storage-linked paths should keep persistent-read state")
		}
	}
}

func TestInstantiateSummaryReturnMarksReceiverStorageLinksAsPersistentRead(t *testing.T) {
	const helperKey = `method::\Demo::load_profile`
	engine := &engine{
		callables: map[string]callable{
			helperKey: {Key: helperKey, Class: `\Demo`},
		},
		summaries: map[string]summary{
			helperKey: {
				ReceiverStorageLinks: map[string]string{
					"profile": "user_meta_value",
				},
			},
		},
		storagePaths: map[string]originSet{
			"user_meta_value[display_name]": makeOriginSet(origin{
				kind:   originSource,
				source: Location{Path: "store.php", Line: 17},
			}),
		},
	}
	state := &analysisState{
		engine:               engine,
		current:              callable{Key: `method::\Demo::render`, Class: `\Demo`},
		propTaint:            map[string]originSet{},
		receiverStorageLinks: map[string]string{},
		storagePathWrites:    map[string]originSet{},
		sourceHits:           map[string]findingRecord{},
		paramSinks:           map[int]map[string]sinkTemplate{},
		receiverSinks:        map[string]sinkTemplate{},
	}

	state.instantiateSummaryReturnWithOptions(helperKey, nil, nil, "this", true, true, 0)

	got := state.propTaint["this.profile[display_name]"]
	if len(got) != 1 {
		t.Fatalf("receiver storage-linked paths = %d, want 1", len(got))
	}
	for _, item := range got {
		if !item.persistentRead {
			t.Fatal("receiver storage-linked paths should keep persistent-read state")
		}
	}
}

func TestCopyForeachValueStructurePropagatesStorageLinksThroughLocalRoots(t *testing.T) {
	engine := &engine{
		storagePaths: map[string]originSet{
			"user_meta_value[display_name]": makeOriginSet(origin{
				kind:           originSource,
				source:         Location{Path: "store.php", Line: 9},
				persistentRead: true,
			}),
		},
	}
	state := &analysisState{
		engine:                 engine,
		current:                callable{Key: `method::\Demo::render`, Class: `\Demo`},
		propTaint:              map[string]originSet{},
		receiverStorageLinks:   map[string]string{},
		structuralStorageLinks: map[string]string{},
		storagePathWrites:      map[string]originSet{},
	}

	state.copyStoragePathsToTarget(structuralRoot{key: "this.usermeta"}, "user_meta_value")

	src := &ast.ExprPropertyFetch{
		Var:  &ast.ExprVariable{Name: "this"},
		Name: &ast.Identifier{Name: "usermeta"},
	}
	dst := &ast.ExprVariable{Name: "entry"}
	state.copyForeachValueStructure(dst, src)

	if got := state.structuralStorageLinks["entry"]; got != "user_meta_value" {
		t.Fatalf("entry storage link = %q, want user_meta_value", got)
	}
	for _, item := range state.propTaint["entry[display_name]"] {
		if !item.persistentRead {
			t.Fatal("foreach value paths should keep persistent-read state")
		}
	}

	state.copyStructuralFromExpr(
		structuralRoot{key: "this.profile[*]"},
		&ast.ExprArrayDimFetch{
			Var: &ast.ExprVariable{Name: "entry"},
			Dim: &ast.ScalarInt{Value: 0},
		},
	)

	if got := state.receiverStorageLinks["profile[*]"]; got != "user_meta_value" {
		t.Fatalf("profile storage link = %q, want user_meta_value", got)
	}
	for _, item := range state.propTaint["this.profile[*][display_name]"] {
		if !item.persistentRead {
			t.Fatal("receiver paths copied through local storage links should keep persistent-read state")
		}
	}
}

func TestFilterSummaryReceiverEffectsCoveredByStorageLinksDropsPersistentReceiverPaths(t *testing.T) {
	item := summary{
		ReceiverWrites: map[string]taintSummary{
			"profile[*]": summarizeOriginsCompacted(makeOriginSet(origin{
				kind:           originSource,
				source:         Location{Path: "store.php", Line: 1},
				persistentRead: true,
			})),
		},
		ReceiverPathWrites: map[string]taintSummary{
			"profile[*][display_name]": summarizeOriginsCompacted(makeOriginSet(origin{
				kind:           originSource,
				source:         Location{Path: "store.php", Line: 2},
				persistentRead: true,
			})),
		},
		ReceiverStorageLinks: map[string]string{
			"profile[*]": "user_meta_value",
		},
	}

	filtered := filterSummaryReceiverEffectsCoveredByStorageLinks(item)
	if len(filtered.ReceiverWrites) != 0 || len(filtered.ReceiverPathWrites) != 0 {
		t.Fatalf("receiver effects should be covered by storage links: %+v", filtered)
	}
}

func TestResolveReceiverPathOriginsFallsBackToNearestSeededPrefix(t *testing.T) {
	seeded := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 18}})
	state := analysisState{
		engine:  &engine{},
		current: callable{SourcePath: "demo.php"},
		propTaint: map[string]originSet{
			"this.meta[file]": seeded,
		},
	}

	got := state.resolveReceiverPathOrigins("this", "meta[file][path]")
	if len(got) != 1 {
		t.Fatalf("fallback origins = %#v, want seeded prefix origin", got)
	}
	for _, item := range got.sorted() {
		if item.source.Line != 18 {
			t.Fatalf("fallback source line = %d, want 18", item.source.Line)
		}
	}
}

func TestCollectExprStructuralPathsTreatsApplyFiltersAsStructurePreserving(t *testing.T) {
	pathOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})
	state := analysisState{
		engine:  &engine{},
		current: callable{SourcePath: "demo.php"},
		propTaint: map[string]originSet{
			"payload[file][path]": pathOrigin,
		},
	}

	call := &ast.ExprFuncCall{
		Name: &ast.Name{Name: "apply_filters"},
		Args: []ast.Node{
			&ast.Arg{Value: &ast.ScalarString{Value: "demo_payload"}},
			&ast.Arg{Value: &ast.ExprVariable{Name: "payload"}},
		},
	}

	got := state.collectExprStructuralPaths(call)
	if origins := got["[file][path]"]; len(origins) != 1 {
		t.Fatalf("apply_filters structural paths = %#v, want [file][path]", got)
	}
}

func TestCollectExprStructuralPathsTreatsApplyFiltersRefArrayAsStructurePreserving(t *testing.T) {
	pathOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 12}})
	state := analysisState{
		engine:  &engine{},
		current: callable{SourcePath: "demo.php"},
		propTaint: map[string]originSet{
			"payload[file][path]": pathOrigin,
		},
	}

	call := &ast.ExprFuncCall{
		Name: &ast.Name{Name: "apply_filters_ref_array"},
		Args: []ast.Node{
			&ast.Arg{Value: &ast.ScalarString{Value: "demo_payload"}},
			&ast.Arg{Value: &ast.ExprArray{Items: []ast.Node{
				&ast.ArrayItem{Value: &ast.ExprVariable{Name: "payload"}},
				&ast.ArrayItem{Value: &ast.ExprVariable{Name: "module"}},
			}}},
		},
	}

	got := state.collectExprStructuralPaths(call)
	if origins := got["[file][path]"]; len(origins) != 1 {
		t.Fatalf("apply_filters_ref_array structural paths = %#v, want [file][path]", got)
	}
}

func TestApplyPostAssignEffectsPrunesCoveredStaticRootAfterFilterReturnAssignment(t *testing.T) {
	pathOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 14}})
	state := analysisState{
		engine: &engine{
			classParents: map[string]string{},
		},
		current: callable{Class: `\Demo`, SourcePath: "demo.php"},
		propTaint: map[string]originSet{
			"payload[file][path]": pathOrigin,
		},
		staticPropTaint: map[string]originSet{},
	}

	call := &ast.ExprFuncCall{
		Name: &ast.Name{Name: "apply_filters"},
		Args: []ast.Node{
			&ast.Arg{Value: &ast.ScalarString{Value: "demo_payload"}},
			&ast.Arg{Value: &ast.ExprVariable{Name: "payload"}},
		},
	}
	target := &ast.ExprStaticPropertyFetch{
		Class: &ast.Name{Name: "Demo"},
		Name:  &ast.Identifier{Name: "prepared_data"},
	}

	origins := state.evalAssignedExpr(call)
	state.assignToNode(target, origins, "")
	state.applyPostAssignEffects(target, call)

	if got := state.staticPropTaint[`\Demo.$prepared_data[file][path]`]; len(got) != 1 {
		t.Fatalf("static child paths = %#v, want file[path] child", state.staticPropTaint)
	}
	if _, ok := state.staticPropTaint[`\Demo.$prepared_data`]; ok {
		t.Fatalf("unexpected covered static root in %#v", state.staticPropTaint)
	}
}

func TestAssignToNodeUsesCopyOnWriteOriginSets(t *testing.T) {
	origins := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})
	state := analysisState{
		engine:          &engine{},
		current:         callable{Class: `\Demo`, SourcePath: "demo.php"},
		varTaint:        map[string]originSet{},
		propTaint:       map[string]originSet{},
		staticPropTaint: map[string]originSet{},
		classEnv:        map[string]string{},
		receiverWrites:  map[string]originSet{},
	}

	target := &ast.ExprPropertyFetch{
		Var:  &ast.ExprVariable{Name: "this"},
		Name: &ast.Identifier{Name: "field"},
	}
	state.assignToNode(target, origins, "")

	extra := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 20}})
	unionMapEntry(state.propTaint, "this.field", extra)

	if got := len(origins); got != 1 {
		t.Fatalf("source origins mutated through state aliasing: len(origins)=%d origins=%#v", got, origins)
	}
	if got := len(state.propTaint["this.field"]); got != 2 {
		t.Fatalf("assigned prop origins = %d, want 2 (%#v)", got, state.propTaint["this.field"])
	}
}

func TestCompactStaticPropsByRootCollapsesExplodingNestedKeys(t *testing.T) {
	oldLimit := maxNestedStaticPathsPerRoot
	maxNestedStaticPathsPerRoot = 1
	defer func() {
		maxNestedStaticPathsPerRoot = oldLimit
	}()

	raw := map[string]originSet{
		"Demo::$prepared[first][file][file_path]":  makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"Demo::$prepared[second][file][file_path]": makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}}),
	}

	got := compactStaticPropsByRoot(raw)
	if len(got) != 1 {
		t.Fatalf("len(compacted) = %d, want 1 (%#v)", len(got), got)
	}
	origins, ok := got["Demo::$prepared[*][file][file_path]"]
	if !ok {
		t.Fatalf("missing collapsed wildcard key in %#v", got)
	}
	if len(origins) != 2 {
		t.Fatalf("collapsed origins = %d, want 2", len(origins))
	}
}

func TestCompactStaticPropsByRootPreservesDistinctStableBucketsAfterDynamicCollapse(t *testing.T) {
	oldLimit := maxNestedStaticPathsPerRoot
	maxNestedStaticPathsPerRoot = 1
	defer func() {
		maxNestedStaticPathsPerRoot = oldLimit
	}()

	raw := map[string]originSet{
		"Demo::$prepared[answers][question_42][file][file_path]": makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"Demo::$prepared[uploads][upload_1][file][file_path]":    makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}}),
	}

	got := compactStaticPropsByRoot(raw)
	if len(got) != 2 {
		t.Fatalf("len(compacted) = %d, want 2 (%#v)", len(got), got)
	}
	if origins := got["Demo::$prepared[answers][*][file][file_path]"]; len(origins) != 1 {
		t.Fatalf("answers bucket origins = %d, want 1 (%#v)", len(origins), got)
	}
	if origins := got["Demo::$prepared[uploads][*][file][file_path]"]; len(origins) != 1 {
		t.Fatalf("uploads bucket origins = %d, want 1 (%#v)", len(origins), got)
	}
	if _, ok := got["Demo::$prepared[*][*][file][file_path]"]; ok {
		t.Fatalf("unexpected merged wildcard bucket in %#v", got)
	}
}

func TestCompactStaticPropsByRootPrunesCoveredParentPath(t *testing.T) {
	shared := makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}})
	raw := map[string]originSet{
		"Demo::$prepared[*]":                 shared.clone(),
		"Demo::$prepared[first][file][path]": shared.clone(),
	}

	got := compactStaticPropsByRoot(raw)
	if _, ok := got["Demo::$prepared[*]"]; ok {
		t.Fatalf("unexpected covered parent path in %#v", got)
	}
	if origins := got["Demo::$prepared[first][file][path]"]; len(origins) != 1 {
		t.Fatalf("child path origins = %d, want 1 (%#v)", len(origins), got)
	}
}

func TestCompactStoragePathsByRootCollapsesExplodingNestedKeys(t *testing.T) {
	oldLimit := maxNestedStoragePathsPerRoot
	maxNestedStoragePathsPerRoot = 1
	defer func() {
		maxNestedStoragePathsPerRoot = oldLimit
	}()

	raw := map[string]originSet{
		"option_value[first][file][file_path]":  makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"option_value[second][file][file_path]": makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}}),
	}

	got := compactStoragePathsByRoot(raw)
	if len(got) != 1 {
		t.Fatalf("len(compacted) = %d, want 1 (%#v)", len(got), got)
	}
	origins, ok := got["option_value[*][file][file_path]"]
	if !ok {
		t.Fatalf("missing collapsed wildcard key in %#v", got)
	}
	if len(origins) != 2 {
		t.Fatalf("collapsed origins = %d, want 2", len(origins))
	}
}

func TestCompactStoragePathsByRootPreservesDistinctStableBucketsAfterDynamicCollapse(t *testing.T) {
	oldLimit := maxNestedStoragePathsPerRoot
	maxNestedStoragePathsPerRoot = 1
	defer func() {
		maxNestedStoragePathsPerRoot = oldLimit
	}()

	raw := map[string]originSet{
		"option_value[answers][question_42][file][file_path]": makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"option_value[uploads][upload_1][file][file_path]":    makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}}),
	}

	got := compactStoragePathsByRoot(raw)
	if len(got) != 2 {
		t.Fatalf("len(compacted) = %d, want 2 (%#v)", len(got), got)
	}
	if origins := got["option_value[answers][*][file][file_path]"]; len(origins) != 1 {
		t.Fatalf("answers bucket origins = %d, want 1 (%#v)", len(origins), got)
	}
	if origins := got["option_value[uploads][*][file][file_path]"]; len(origins) != 1 {
		t.Fatalf("uploads bucket origins = %d, want 1 (%#v)", len(origins), got)
	}
	if _, ok := got["option_value[*][*][file][file_path]"]; ok {
		t.Fatalf("unexpected merged wildcard bucket in %#v", got)
	}
}

func TestCompactStoragePathsByRootPreservesStableKeysAfterWildcardPrefix(t *testing.T) {
	oldLimit := maxNestedStoragePathsPerRoot
	maxNestedStoragePathsPerRoot = 1
	defer func() {
		maxNestedStoragePathsPerRoot = oldLimit
	}()

	raw := map[string]originSet{
		"post_meta_value[*][demo_upload][file][file_path]": makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"post_meta_value[*][demo_text][value]":             makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}}),
	}

	got := compactStoragePathsByRoot(raw)
	if len(got) != 2 {
		t.Fatalf("len(compacted) = %d, want 2 (%#v)", len(got), got)
	}
	if _, ok := got["post_meta_value[*][*]"]; ok {
		t.Fatalf("unexpected broad wildcard bucket in %#v", got)
	}
	if origins := got["post_meta_value[*][demo_upload][file][file_path]"]; len(origins) != 1 {
		t.Fatalf("demo_upload origins = %d, want 1 (%#v)", len(origins), got)
	}
	if origins := got["post_meta_value[*][demo_text][value]"]; len(origins) != 1 {
		t.Fatalf("demo_text origins = %d, want 1 (%#v)", len(origins), got)
	}
}

func TestCompactStoragePathsByRootPrunesCoveredWildcardPath(t *testing.T) {
	raw := map[string]originSet{
		"post_meta_value[*][*]":                     makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"post_meta_value[*][_srfm_block_config][*]": makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
	}

	got := compactStoragePathsByRoot(raw)
	if _, ok := got["post_meta_value[*][*]"]; ok {
		t.Fatalf("unexpected covered wildcard path preserved in %#v", got)
	}
	if _, ok := got["post_meta_value[*][_srfm_block_config][*]"]; !ok {
		t.Fatalf("expected specific child path in %#v", got)
	}
}

func TestCompactStoragePathsByRootCollapsesDeepStableBucketAfterWildcardPrefix(t *testing.T) {
	oldLimit := maxNestedStoragePathsPerRoot
	maxNestedStoragePathsPerRoot = 1
	defer func() {
		maxNestedStoragePathsPerRoot = oldLimit
	}()

	raw := map[string]originSet{
		"_default_settings[*][callback][]._default_settings[orders][callback][]._default_settings":  makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"_default_settings[*][callback][]._default_settings[quizzes][callback][]._default_settings": makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}}),
	}

	got := compactStoragePathsByRoot(raw)
	if len(got) != 1 {
		t.Fatalf("len(compacted) = %d, want 1 (%#v)", len(got), got)
	}
	if origins := got["_default_settings[*][callback]"]; len(origins) != 2 {
		t.Fatalf("collapsed origins = %d, want 2 (%#v)", len(origins), got)
	}
}

func TestCompactRelativeStructuralPathsByRootCollapsesExplodingNestedKeys(t *testing.T) {
	oldLimit := maxNestedParamPathsPerRoot
	maxNestedParamPathsPerRoot = 1
	defer func() {
		maxNestedParamPathsPerRoot = oldLimit
	}()

	raw := map[string]originSet{
		"[first][file][file_path]":  makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"[second][file][file_path]": makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}}),
	}

	got := compactRelativeStructuralPathsByRoot(raw)
	if len(got) != 1 {
		t.Fatalf("len(compacted) = %d, want 1 (%#v)", len(got), got)
	}
	if origins := got["[*][file][file_path]"]; len(origins) != 2 {
		t.Fatalf("collapsed origins = %d, want 2 (%#v)", len(origins), got)
	}
}

func TestCompactRelativeStructuralPathsByRootPreservesStableBucketsAfterWildcardPrefix(t *testing.T) {
	oldLimit := maxNestedParamPathsPerRoot
	maxNestedParamPathsPerRoot = 1
	defer func() {
		maxNestedParamPathsPerRoot = oldLimit
	}()

	raw := map[string]originSet{
		"[*][demo_upload][file][file_path]": makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
		"[*][demo_text][value]":             makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}}),
	}

	got := compactRelativeStructuralPathsByRoot(raw)
	if len(got) != 2 {
		t.Fatalf("len(compacted) = %d, want 2 (%#v)", len(got), got)
	}
	if _, ok := got["[*][*]"]; ok {
		t.Fatalf("unexpected broad wildcard bucket in %#v", got)
	}
	if origins := got["[*][demo_upload][file][file_path]"]; len(origins) != 1 {
		t.Fatalf("demo_upload origins = %d, want 1 (%#v)", len(origins), got)
	}
	if origins := got["[*][demo_text][value]"]; len(origins) != 1 {
		t.Fatalf("demo_text origins = %d, want 1 (%#v)", len(origins), got)
	}
}

func TestInstantiateSummaryReturnPathsCompactsExplodingRelativePaths(t *testing.T) {
	oldLimit := maxNestedParamPathsPerRoot
	maxNestedParamPathsPerRoot = 1
	defer func() {
		maxNestedParamPathsPerRoot = oldLimit
	}()

	first := makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}})
	second := makeOriginSet(origin{kind: originSource, source: Location{Path: "b.php", Line: 11}})
	state := analysisState{
		engine:  &engine{},
		current: callable{SourcePath: "demo.php"},
		propTaint: map[string]originSet{
			"payload[first][file][file_path]":  first,
			"payload[second][file][file_path]": second,
		},
	}

	got := state.instantiateSummaryReturnPaths(summary{ReturnParams: []int{0}}, []ast.Node{
		&ast.ExprVariable{Name: "payload"},
	}, nil)

	if len(got) != 1 {
		t.Fatalf("len(paths) = %d, want 1 (%#v)", len(got), got)
	}
	if origins := got["[*][file][file_path]"]; len(origins) != 2 {
		t.Fatalf("compacted origins = %d, want 2 (%#v)", len(origins), got)
	}
}

func TestCompactParamPathRefsByRootCollapsesExplodingNestedKeys(t *testing.T) {
	oldLimit := maxNestedParamPathsPerRoot
	maxNestedParamPathsPerRoot = 1
	defer func() {
		maxNestedParamPathsPerRoot = oldLimit
	}()

	raw := map[string]paramPathRef{
		paramPathSyntheticPrefix(0) + "[first][file][file_path]": {
			Index: 0,
			Path:  "[first][file][file_path]",
		},
		paramPathSyntheticPrefix(0) + "[second][file][file_path]": {
			Index: 0,
			Path:  "[second][file][file_path]",
		},
	}

	got := compactParamPathRefsByRoot(raw)
	if len(got) != 1 {
		t.Fatalf("len(compacted) = %d, want 1 (%#v)", len(got), got)
	}
	ref, ok := got[paramPathSyntheticPrefix(0)+"[*][file][file_path]"]
	if !ok {
		t.Fatalf("missing collapsed wildcard key in %#v", got)
	}
	if ref.Path != "[*][file][file_path]" {
		t.Fatalf("collapsed path = %q, want wildcard path", ref.Path)
	}
}

func TestCompactParamPathRefsByRootCollapsesDeepPropertyTrees(t *testing.T) {
	oldLimit := maxNestedParamPathsPerRoot
	maxNestedParamPathsPerRoot = 1
	defer func() {
		maxNestedParamPathsPerRoot = oldLimit
	}()

	raw := map[string]paramPathRef{
		paramPathSyntheticPrefix(0) + ".field_count.fields.order_by": {
			Index: 0,
			Path:  ".field_count.fields.order_by",
		},
		paramPathSyntheticPrefix(0) + ".field_count.fields.where": {
			Index: 0,
			Path:  ".field_count.fields.where",
		},
	}

	got := compactParamPathRefsByRoot(raw)
	if len(got) != 1 {
		t.Fatalf("len(compacted) = %d, want 1 (%#v)", len(got), got)
	}
	ref, ok := got[paramPathSyntheticPrefix(0)+".field_count"]
	if !ok {
		t.Fatalf("missing collapsed property bucket in %#v", got)
	}
	if ref.Path != ".field_count" {
		t.Fatalf("collapsed path = %q, want %q", ref.Path, ".field_count")
	}
}

func TestCompactParamPathRefsByRootPreservesStablePropertyAfterWildcardPrefix(t *testing.T) {
	oldLimit := maxNestedParamPathsPerRoot
	maxNestedParamPathsPerRoot = 1
	defer func() {
		maxNestedParamPathsPerRoot = oldLimit
	}()

	raw := map[string]paramPathRef{
		paramPathSyntheticPrefix(0) + "[123].field_count.fields.order_by": {
			Index: 0,
			Path:  "[123].field_count.fields.order_by",
		},
		paramPathSyntheticPrefix(0) + "[456].field_count.fields.where": {
			Index: 0,
			Path:  "[456].field_count.fields.where",
		},
	}

	got := compactParamPathRefsByRoot(raw)
	if len(got) != 1 {
		t.Fatalf("len(compacted) = %d, want 1 (%#v)", len(got), got)
	}
	ref, ok := got[paramPathSyntheticPrefix(0)+"[*].field_count"]
	if !ok {
		t.Fatalf("missing wildcard property bucket in %#v", got)
	}
	if ref.Path != "[*].field_count" {
		t.Fatalf("collapsed path = %q, want %q", ref.Path, "[*].field_count")
	}
}

func TestCompactReceiverPathRefsByRootCollapsesExplodingNestedKeys(t *testing.T) {
	oldLimit := maxNestedParamPathsPerRoot
	maxNestedParamPathsPerRoot = 1
	defer func() {
		maxNestedParamPathsPerRoot = oldLimit
	}()

	raw := map[string]receiverPathRef{
		"[first][file][file_path]": {
			Path: "[first][file][file_path]",
		},
		"[second][file][file_path]": {
			Path: "[second][file][file_path]",
		},
	}

	got := compactReceiverPathRefsByRoot(raw)
	if len(got) != 1 {
		t.Fatalf("len(compacted) = %d, want 1 (%#v)", len(got), got)
	}
	ref, ok := got["__receiver[*][file][file_path]"]
	if !ok {
		t.Fatalf("missing collapsed wildcard key in %#v", got)
	}
	if ref.Path != "[*][file][file_path]" {
		t.Fatalf("collapsed path = %q, want wildcard path", ref.Path)
	}
}

func TestCompactStoragePathsByRootKeepsWildcardPathWithDistinctContext(t *testing.T) {
	raw := map[string]originSet{
		"post_meta_value[*][*]": makeOriginSet(origin{
			kind:   originSource,
			source: Location{Path: "a.php", Line: 10},
			storedWriteContext: FlowContext{
				Access: "nonce_only",
				EntryPoints: []EntryPoint{
					{Kind: "ajax", Name: "wp_ajax_demo"},
				},
			},
		}),
		"post_meta_value[*][_srfm_block_config][*]": makeOriginSet(origin{kind: originSource, source: Location{Path: "a.php", Line: 10}}),
	}

	got := compactStoragePathsByRoot(raw)
	if _, ok := got["post_meta_value[*][*]"]; !ok {
		t.Fatalf("distinct wildcard path context should be preserved in %#v", got)
	}
}

func TestPruneStructuralRootOriginsCoveredByChildrenDropsRedundantStorageRoot(t *testing.T) {
	rootOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})
	paths := map[string]originSet{
		"form_data[file][url]": rootOrigin,
	}
	roots := map[string]originSet{
		"form_data": rootOrigin,
	}

	got := pruneStructuralRootOriginsCoveredByChildren(roots, paths)
	if _, ok := got["form_data"]; ok {
		t.Fatalf("unexpected redundant root preserved in %#v", got)
	}
}

func TestPruneStructuralRootOriginsCoveredByChildrenKeepsDistinctRootContext(t *testing.T) {
	childOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})
	rootOrigin := makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 10},
		storedWriteContext: FlowContext{
			Access: "nonce_only",
			EntryPoints: []EntryPoint{
				{Kind: "ajax", Name: "wp_ajax_demo"},
			},
		},
	})
	paths := map[string]originSet{
		"form_data[file][url]": childOrigin,
	}
	roots := map[string]originSet{
		"form_data": rootOrigin,
	}

	got := pruneStructuralRootOriginsCoveredByChildren(roots, paths)
	if _, ok := got["form_data"]; !ok {
		t.Fatalf("distinct root context should be preserved in %#v", got)
	}
}

func TestSummarizeStorageEffectsPrunesCoveredRootSummary(t *testing.T) {
	rootOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})
	roots := map[string]originSet{
		"form_data": rootOrigin,
	}
	paths := map[string]originSet{
		"form_data[file][url]": rootOrigin,
	}

	rootSummaries, pathSummaries := summarizeStorageEffects(roots, paths)
	if _, ok := rootSummaries["form_data"]; ok {
		t.Fatalf("unexpected redundant storage root summary preserved in %#v", rootSummaries)
	}
	if _, ok := pathSummaries["form_data[file][url]"]; !ok {
		t.Fatalf("expected child storage path summary to be preserved in %#v", pathSummaries)
	}
}

func TestSummarizeStorageEffectsKeepsDistinctRootContextSummary(t *testing.T) {
	childOrigin := makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})
	rootOrigin := makeOriginSet(origin{
		kind:   originSource,
		source: Location{Path: "demo.php", Line: 10},
		storedWriteContext: FlowContext{
			Access: "nonce_only",
			EntryPoints: []EntryPoint{
				{Kind: "ajax", Name: "wp_ajax_demo"},
			},
		},
	})
	roots := map[string]originSet{
		"form_data": rootOrigin,
	}
	paths := map[string]originSet{
		"form_data[file][url]": childOrigin,
	}

	rootSummaries, _ := summarizeStorageEffects(roots, paths)
	if _, ok := rootSummaries["form_data"]; !ok {
		t.Fatalf("distinct storage root context should be preserved in %#v", rootSummaries)
	}
}

func TestFilterDeleteStoragePathWritesSkipsUserMetaScalarPaths(t *testing.T) {
	origins := makeOriginSet(origin{kind: originParam, paramIdx: 0})
	filtered := filterDeleteStoragePathWrites(map[string]originSet{
		"user_meta_value[*][full_name]": origins,
	})
	if len(filtered) != 0 {
		t.Fatalf("unexpected delete scalar user_meta path retained: %#v", filtered)
	}
}

func TestFilterDeleteStoragePathWritesKeepsUserMetaFilePaths(t *testing.T) {
	origins := makeOriginSet(origin{kind: originParam, paramIdx: 0})
	filtered := filterDeleteStoragePathWrites(map[string]originSet{
		"user_meta_value[*][avatar][file_path]": origins,
	})
	if _, ok := filtered["user_meta_value[*][avatar][file_path]"]; !ok {
		t.Fatalf("expected delete file-like user_meta path to be retained: %#v", filtered)
	}
}

func TestRecomputeGlobalStaticPropsDropsRedundantCoveredRoot(t *testing.T) {
	e := &engine{
		summaries: map[string]summary{
			"demo": {
				StaticWrites: map[string]taintSummary{
					`Demo::$script`:                summarizeOrigins(makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})),
					`Demo::$script[header][css]`:   summarizeOrigins(makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})),
					`Demo::$script[footer][style]`: summarizeOrigins(makeOriginSet(origin{kind: originSource, source: Location{Path: "demo.php", Line: 10}})),
				},
			},
		},
	}

	e.recomputeGlobalStaticProps()
	if _, ok := e.staticProps[`Demo::$script`]; ok {
		t.Fatalf("redundant static root preserved in %#v", e.staticProps)
	}
}

func TestSummarizeOriginsMergesStoredWriteContextForDuplicateSource(t *testing.T) {
	source := Location{Path: "form-submit.php", Line: 213}
	routeLoc := Location{Path: "routes.php", Line: 10}
	nonceLoc := Location{Path: "nonce.php", Line: 11}

	summary := summarizeOrigins(makeOriginSet(
		origin{
			kind:           originSource,
			source:         source,
			persistentRead: true,
			outputSafeHTML: true,
			storedWriteContext: FlowContext{
				EntryPoints: []EntryPoint{{
					Kind:     "rest",
					Route:    "/submit-form",
					Location: routeLoc,
				}},
			},
		},
		origin{
			kind:   originSource,
			source: source,
			storedWriteContext: FlowContext{
				NonceChecks: []Location{nonceLoc},
			},
		},
	))

	if len(summary.SourceOrigins) != 1 {
		t.Fatalf("source origins = %d, want 1", len(summary.SourceOrigins))
	}
	if !summary.SourceOrigins[0].PersistentRead {
		t.Fatalf("summary persistent_read = false, want true")
	}
	if !summary.SourceOrigins[0].OutputSafeHTML {
		t.Fatalf("summary output_safe_html = false, want true")
	}
	ctx := summary.SourceOrigins[0].StoredWriteContext
	if len(ctx.EntryPoints) != 1 {
		t.Fatalf("entrypoints = %d, want 1", len(ctx.EntryPoints))
	}
	if ctx.EntryPoints[0].Route != "/submit-form" {
		t.Fatalf("entrypoint route = %q, want /submit-form", ctx.EntryPoints[0].Route)
	}
	if len(ctx.NonceChecks) != 1 {
		t.Fatalf("nonce checks = %d, want 1", len(ctx.NonceChecks))
	}
	if ctx.NonceChecks[0].Path != nonceLoc.Path || ctx.NonceChecks[0].Line != nonceLoc.Line {
		t.Fatalf("nonce check = %#v, want %#v", ctx.NonceChecks[0], nonceLoc)
	}

	roundTrip := originsFromTaintSummary(summary)
	item, ok := roundTrip[originKey(origin{kind: originSource, source: source})]
	if !ok {
		t.Fatalf("round-trip origin missing for %s", locationKey(source))
	}
	if len(item.storedWriteContext.EntryPoints) != 1 {
		t.Fatalf("round-trip entrypoints = %d, want 1", len(item.storedWriteContext.EntryPoints))
	}
	if len(item.storedWriteContext.NonceChecks) != 1 {
		t.Fatalf("round-trip nonce checks = %d, want 1", len(item.storedWriteContext.NonceChecks))
	}
	if !item.persistentRead {
		t.Fatalf("round-trip persistent_read = false, want true")
	}
	if !item.outputSafeHTML {
		t.Fatalf("round-trip output_safe_html = false, want true")
	}
}

func TestAnalyzeRootTracksUploadHelperReturnThroughFieldDataArrayKeyedWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "upload-helper-keyed-write.php"), `<?php
class UploadField {
    public function handle_submission_multifile_upload() {
        return array(
            'success' => true,
            'file_url' => array('/uploads/demo.txt'),
            'file_path' => array($_FILES['upload']['tmp_name']),
        );
    }
}

class Entry {
    public $meta_data = array();

    public function __construct($entry_id = 0) {
        if ($entry_id) {
            $this->load_meta();
        }
    }

    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
            $this->meta_data[] = array('value' => $value);
        }
    }

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path'][0]);
        }
    }
}

class DB {
    public function insert($table, $row) {}
}

class Action {
    public static $info = array();

    public static function seed() {
        self::$info['field_data_array'][] = array(
            'name' => 'upload',
            'field_type' => 'upload',
            'value' => array(),
        );
    }

    public static function process_uploads() {
        $fields = self::$info['field_data_array'];
        foreach ($fields as $key => $field) {
            $field_obj = new UploadField();
            $upload_data = $field_obj->handle_submission_multifile_upload();
            if ($upload_data['success']) {
                self::$info['field_data_array'][$key]['value']['file'] = $upload_data;
            }
        }
    }

    public static function run() {
        self::seed();
        self::process_uploads();
        $entry = new Entry();
        $entry->set_fields(self::$info['field_data_array']);
        $reloaded = new Entry(1);
        Entry::delete_files($reloaded);
    }
}

Action::run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 40 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 7 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not preserve upload helper return through keyed field_data_array write: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootTracksTwoHopUploadHelperReturnThroughFieldDataArrayKeyedWrite(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "upload-helper-two-hop-keyed-write.php"), `<?php
class UploadField {
    public function handle_file_upload() {
        return array(
            'success' => true,
            'file_url' => '/uploads/demo.txt',
            'file_path' => $_FILES['upload']['tmp_name'],
        );
    }

    public function handle_submission_multifile_upload() {
        $file_path_arr = array();
        $file_url_arr = array();
        $response = $this->handle_file_upload();
        if (isset($response['success']) && $response['success']) {
            $file_path_arr[] = $response['file_path'];
            $file_url_arr[] = $response['file_url'];
        }
        return array(
            'success' => true,
            'file_url' => $file_url_arr,
            'file_path' => $file_path_arr,
        );
    }
}

class Entry {
    public $meta_data = array();

    public function __construct($entry_id = 0) {
        if ($entry_id) {
            $this->load_meta();
        }
    }

    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
            $this->meta_data[] = array('value' => $value);
        }
    }

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path'][0]);
        }
    }
}

class DB {
    public function insert($table, $row) {}
}

class Action {
    public static $info = array();

    public static function seed() {
        self::$info['field_data_array'][] = array(
            'name' => 'upload',
            'field_type' => 'upload',
            'value' => array(),
        );
    }

    public static function process_uploads() {
        $fields = self::$info['field_data_array'];
        foreach ($fields as $key => $field) {
            $field_obj = new UploadField();
            $upload_data = $field_obj->handle_submission_multifile_upload();
            if ($upload_data['success']) {
                self::$info['field_data_array'][$key]['value']['file'] = $upload_data;
            }
        }
    }

    public static function run() {
        self::seed();
        self::process_uploads();
        $entry = new Entry();
        $entry->set_fields(self::$info['field_data_array']);
        $reloaded = new Entry(1);
        Entry::delete_files($reloaded);
    }
}

Action::run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 55 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 7 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not preserve two-hop upload helper return through keyed field_data_array write: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootTracksFactoryResolvedTwoHopUploadHelperReturn(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "factory-two-hop-upload.php"), `<?php
class UploadField {
    public $slug = 'upload';

    public function handle_file_upload() {
        return array(
            'success' => true,
            'file_url' => '/uploads/demo.txt',
            'file_path' => $_FILES['upload']['tmp_name'],
        );
    }

    public function handle_submission_multifile_upload() {
        $file_path_arr = array();
        $file_url_arr = array();
        $response = $this->handle_file_upload();
        if (isset($response['success']) && $response['success']) {
            $file_path_arr[] = $response['file_path'];
            $file_url_arr[] = $response['file_url'];
        }
        return array(
            'success' => true,
            'file_url' => $file_url_arr,
            'file_path' => $file_path_arr,
        );
    }
}

class Core {
    public static function get_field_object($type) {
        return null;
    }
}

class Entry {
    public $meta_data = array();

    public function __construct($entry_id = 0) {
        if ($entry_id) {
            $this->load_meta();
        }
    }

    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
            $this->meta_data[] = array('value' => $value);
        }
    }

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path'][0]);
        }
    }
}

class DB {
    public function insert($table, $row) {}
}

class Action {
    public static $info = array();

    public static function seed() {
        self::$info['field_data_array'][] = array(
            'name' => 'upload',
            'field_type' => 'upload',
            'value' => array(),
        );
    }

    public static function process_uploads() {
        $fields = self::$info['field_data_array'];
        foreach ($fields as $key => $field) {
            $field_obj = Core::get_field_object('upload');
            $upload_data = $field_obj->handle_submission_multifile_upload();
            if ($upload_data['success']) {
                self::$info['field_data_array'][$key]['value']['file'] = $upload_data;
            }
        }
    }

    public static function run() {
        self::seed();
        self::process_uploads();
        $entry = new Entry();
        $entry->set_fields(self::$info['field_data_array']);
        $reloaded = new Entry(1);
        Entry::delete_files($reloaded);
    }
}

Action::run();
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 63 {
			continue
		}
		if finding.Extra.Trace.Source.Line != 9 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not preserve factory-resolved two-hop upload helper return: %#v", result.Payload.Results)
	}
}

func TestAnalyzeRootKeepsCrossRequestMetaWriterRelevantForDeleteSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "cross-request-meta-writer.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

class Entry {
    public $meta_data = array();

    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
        }
    }

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path']);
        }
    }
}

class SubmitController {
    public function handle_submit() {
        $entry = new Entry();
        $fields = array(
            array(
                'value' => array(
                    'file' => array(
                        'file_path' => $_FILES['upload']['tmp_name'],
                    ),
                ),
            ),
        );
        $entry->set_fields($fields);
    }
}

class DeleteController {
    public function handle_delete() {
        $entry = new Entry();
        $entry->load_meta();
        Entry::delete_files($entry);
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 27 {
			continue
		}
		if finding.Extra.Trace.Source.Line == 39 {
			return
		}
	}
	t.Fatalf("did not keep cross-request meta writer relevant for delete sink: %#v", result.Payload.Results)
}

func TestAnalyzeRootKeepsSmallForeignCrossRequestMetaWriterRelevantForDeleteSink(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "cross-request-meta-writer-foreign.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

class EntryReader {
    public $meta_data = array();

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path']);
        }
    }
}

class EntryWriter {
    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
        }
    }
}

class SubmitController {
    public function handle_submit() {
        $entry = new EntryWriter();
        $fields = array(
            array(
                'value' => array(
                    'file' => array(
                        'file_path' => $_FILES['upload']['tmp_name'],
                    ),
                ),
            ),
        );
        $entry->set_fields($fields);
    }
}

class DeleteController {
    public function handle_delete() {
        $entry = new EntryReader();
        $entry->load_meta();
        EntryReader::delete_files($entry);
    }
}
`)

	result, err := AnalyzeRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("AnalyzeRoot(): %v", err)
	}
	if len(result.Payload.Results) == 0 {
		t.Fatalf("findings = 0, want at least 1")
	}
	for _, finding := range result.Payload.Results {
		if finding.Start.Line != 17 {
			continue
		}
		if finding.Extra.Trace.Source.Line == 41 {
			return
		}
	}
	t.Fatalf("did not keep small foreign cross-request meta writer relevant for delete sink: %#v", result.Payload.Results)
}

func TestBuildEngineSkipsLargeFamilyWideCrossRequestWriterFallback(t *testing.T) {
	root := t.TempDir()
	var builder strings.Builder
	builder.WriteString("<?php\n")
	builder.WriteString(`
class DB {
    public function insert($table, $row) {}
}

class Reader {
    public $meta_data = array();

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path']);
        }
    }
}
`)
	for i := 0; i < maxCrossRequestFamilyWideWriterFallback+2; i++ {
		builder.WriteString(fmt.Sprintf(`
class Writer%d {
    public function run() {
        $db = new DB();
        $db->insert('entry_meta', array(
            'meta_value' => maybe_serialize($_FILES['upload']['tmp_name']),
        ));
    }
}
`, i))
	}
	builder.WriteString(`
class DeleteController {
    public function handle_delete() {
        $entry = new Reader();
        $entry->load_meta();
        Reader::delete_files($entry);
    }
}
`)
	writePHP(t, filepath.Join(root, "large-family-fallback.php"), builder.String())

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	if _, ok := engine.relevantCallables["method::Writer0::run"]; ok {
		t.Fatalf("Writer0::run should not be pulled in by large family-wide fallback")
	}
}

func TestBuildEngineCapsLargeSameClassCrossRequestWriterSetToReachableWriters(t *testing.T) {
	root := t.TempDir()
	var builder strings.Builder
	builder.WriteString("<?php\n")
	builder.WriteString(`
class DB {
    public function insert($table, $row) {}
}

class EntryService {
    public $meta_data = array();

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path']);
        }
    }

    public function write0($value) {
        $db = new DB();
        $db->insert('entry_meta', array(
            'meta_value' => maybe_serialize($value),
        ));
    }
`)
	for i := 1; i < maxCrossRequestFamilyWideWriterFallback+3; i++ {
		builder.WriteString(fmt.Sprintf(`
    public function write%d($value) {
        $db = new DB();
        $db->insert('entry_meta', array(
            'meta_value' => maybe_serialize($value),
        ));
    }
`, i))
	}
	builder.WriteString(`
}

class SubmitController {
    public function handle_submit() {
        $entry = new EntryService();
        $entry->write0(array(
            'file' => array(
                'file_path' => $_FILES['upload']['tmp_name'],
            ),
        ));
    }
}

class DeleteController {
    public function handle_delete() {
        $entry = new EntryService();
        $entry->load_meta();
        EntryService::delete_files($entry);
    }
}
`)
	writePHP(t, filepath.Join(root, "same-class-writers.php"), builder.String())

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	write0Relevant := false
	write1Relevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "EntryService::write0") {
			write0Relevant = true
		}
		if strings.HasSuffix(key, "EntryService::write1") {
			write1Relevant = true
		}
	}
	if !write0Relevant {
		t.Fatalf("EntryService::write0 should stay relevant because it is request-reachable")
	}
	if write1Relevant {
		t.Fatalf("EntryService::write1 should not be pulled in by a large same-class writer set")
	}
}

func TestBuildEnginePrefersCrossRequestWriterPathBucketsBeforeFamilyFallback(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "cross-request-path-buckets.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

class Reader {
    public function load_path() {
        $result = (object) array('meta_value' => array(
            'file' => array(
                'file_path' => 'placeholder',
            ),
        ));
        return $result->meta_value['file']['file_path'];
    }

    public function delete_file() {
        $path = $this->load_path();
        unlink($path);
    }
}

class FileWriter {
    public function run() {
        $db = new DB();
        $db->insert('entry_meta', array(
            'meta_value' => maybe_serialize(array(
                'file' => array(
                    'file_path' => $_FILES['upload']['tmp_name'],
                ),
            )),
        ));
    }
}

class PaymentWriter {
    public function run() {
        $db = new DB();
        $db->insert('entry_meta', array(
            'meta_value' => maybe_serialize(array(
                'payment' => array(
                    'intent' => $_POST['payment_intent'],
                ),
            )),
        ));
    }
}

class DeleteController {
    public function handle_delete() {
        $reader = new Reader();
        $reader->delete_file();
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	fileWriterRelevant := false
	paymentWriterRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "FileWriter::run") {
			fileWriterRelevant = true
		}
		if strings.HasSuffix(key, "PaymentWriter::run") {
			paymentWriterRelevant = true
		}
	}
	if !fileWriterRelevant {
		t.Fatalf("FileWriter::run should stay relevant for the exact delete path bucket")
	}
	if paymentWriterRelevant {
		t.Fatalf("PaymentWriter::run should not be pulled in when only a sibling storage path differs")
	}
}

func TestBuildEngineCrossRequestWriterReverseExpansionPrefersRequestReachableCallers(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "request-reachable-writer-callers.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

class Entry {
    public $meta_data = array();

    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
        }
    }

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path']);
        }
    }
}

class SubmitController {
    public function handle_submit() {
        $entry = new Entry();
        $entry->set_fields(array(
            array(
                'value' => array(
                    'file' => array(
                        'file_path' => $_FILES['upload']['tmp_name'],
                    ),
                ),
            ),
        ));
    }
}

class ImportController {
    public function run_batch($payload) {
        $entry = new Entry();
        $entry->set_fields($payload);
    }
}

class DeleteController {
    public function handle_delete() {
        $entry = new Entry();
        $entry->load_meta();
        Entry::delete_files($entry);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	submitRelevant := false
	importRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "SubmitController::handle_submit") {
			submitRelevant = true
		}
		if strings.HasSuffix(key, "ImportController::run_batch") {
			importRelevant = true
		}
	}
	if !submitRelevant {
		t.Fatalf("SubmitController::handle_submit should stay relevant")
	}
	if importRelevant {
		t.Fatalf("ImportController::run_batch should not be pulled in without request reachability")
	}
}

func TestBuildEngineCrossRequestWriterReverseExpansionKeepsCallerOfRequestHelper(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "request-helper-caller.php"), `<?php
class DB {
    public function insert($table, $row) {}
}

class Entry {
    public $meta_data = array();

    public function set_fields($meta_array) {
        $db = new DB();
        foreach ($meta_array as $meta) {
            $value = $meta['value'];
            $db->insert('entry_meta', array(
                'meta_value' => maybe_serialize($value),
            ));
        }
    }

    public function load_meta() {
        $result = (object) array('meta_value' => 'placeholder');
        $this->meta_data[] = array('value' => maybe_unserialize($result->meta_value));
    }

    public static function delete_files($entry_model) {
        foreach ($entry_model->meta_data as $meta_data) {
            $meta_value = $meta_data['value'];
            unlink($meta_value['file']['file_path']);
        }
    }
}

class SubmitController {
    private function get_post_data() {
        return array(
            array(
                'value' => array(
                    'file' => array(
                        'file_path' => $_POST['upload_path'],
                    ),
                ),
            ),
        );
    }

    public function handle_submit() {
        $entry = new Entry();
        $entry->set_fields($this->get_post_data());
    }
}

class DeleteController {
    public function handle_delete() {
        $entry = new Entry();
        $entry->load_meta();
        Entry::delete_files($entry);
    }
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"delete": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	submitRelevant := false
	for key := range engine.relevantCallables {
		if strings.HasSuffix(key, "SubmitController::handle_submit") {
			submitRelevant = true
		}
	}
	if !submitRelevant {
		t.Fatalf("SubmitController::handle_submit should stay relevant when the request source is in a helper callee")
	}
}

func TestLookupStructuralSelfOriginsFallsBackToWildcardStaticPath(t *testing.T) {
	store := map[string]originSet{
		"Demo::$prepared[*][file][file_path]": makeOriginSet(origin{kind: originSource, source: Location{Path: "seed.php", Line: 21}}),
	}

	got := lookupStructuralSelfOrigins(store, "Demo::$prepared[entry_42][file][file_path]")
	if len(got) != 1 {
		t.Fatalf("lookupStructuralSelfOrigins() = %d origins, want 1", len(got))
	}
	for _, item := range got {
		if item.source.Path != "seed.php" || item.source.Line != 21 {
			t.Fatalf("unexpected origin: %#v", item)
		}
	}
}

func TestCollapseFirstDynamicArraySegmentPreservesStableTopLevelKeys(t *testing.T) {
	got := collapseFirstDynamicArraySegment("Demo::$prepared[answers][question_42][file][file_path]")
	want := "Demo::$prepared[answers][*][file][file_path]"
	if got != want {
		t.Fatalf("collapseFirstDynamicArraySegment() = %q, want %q", got, want)
	}
}

func TestCollapseFirstDynamicArraySegmentPreservesHyphenatedStableKeys(t *testing.T) {
	got := collapseFirstDynamicArraySegment("Demo::$prepared[forminator-multifile-hidden][upload_1][file][file_path]")
	want := "Demo::$prepared[forminator-multifile-hidden][*][file][file_path]"
	if got != want {
		t.Fatalf("collapseFirstDynamicArraySegment() = %q, want %q", got, want)
	}
}

func TestStructuralCollapseBucketPreservesStablePrefixBeforeWildcard(t *testing.T) {
	got := structuralCollapseBucket("Demo::$prepared[answers][*][file][file_path]")
	want := "Demo::$prepared[answers]"
	if got != want {
		t.Fatalf("structuralCollapseBucket() = %q, want %q", got, want)
	}
}

func TestStorageStablePathBucketPreservesStableMetaKeyAfterDynamicID(t *testing.T) {
	got := storageStablePathBucket("post_meta_value[123][demo_upload][file][file_path]")
	want := "post_meta_value[*][demo_upload]"
	if got != want {
		t.Fatalf("storageStablePathBucket() = %q, want %q", got, want)
	}
}

func TestStorageWriteBucketsAvoidRecursiveLocalFetchOverflow(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "recursive-storage.php"), `<?php
function demo() {
    $args = array(
        'foo' => $args['foo'],
    );
    update_option('demo', $args['foo']);
}
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}

	callableKey := engine.lookupFunctionKey("", "demo")
	if callableKey == "" {
		t.Fatal("missing demo callable")
	}
	current := engine.callables[callableKey]

	var fetch *ast.ExprArrayDimFetch
	walkNodes(current.Stmts, func(node ast.Node) {
		if fetch != nil {
			return
		}
		typed, ok := node.(*ast.ExprArrayDimFetch)
		if !ok {
			return
		}
		fetch = typed
	})
	if fetch == nil {
		t.Fatal("missing recursive array fetch")
	}

	buckets := storageWriteBucketsFromLocalValueFetch(fetch, "option_value[demo]", current, fetch.StartLine())
	if len(buckets) != 1 {
		t.Fatalf("bucket count = %d, want 1 (%#v)", len(buckets), buckets)
	}
	if _, ok := buckets["option_value[demo]"]; !ok {
		t.Fatalf("missing broad root fallback bucket: %#v", buckets)
	}
}

func TestAnalyzeRootFindsDynamicStaticDispatchFromRequestGetter(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "remote-calls.php"), `<?php
class Request {
    public static function get($key) {
        return $_GET[$key];
    }
}

class RemoteCallsDemo {
    public static function perform() {
        $action = strtolower(Request::get('spbc_remote_call_action'));
        $action = 'action__' . $action;
        if (method_exists(__CLASS__, $action)) {
            self::$action();
        }
    }

    public static function action__install_plugin() {
        activate_plugin($_GET['plugin']);
    }
}

RemoteCallsDemo::perform();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
			continue
		}
		if strings.HasSuffix(finding.Path, "remote-calls.php") && finding.Start.Line == 18 {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find dynamic static dispatch action sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsPredictableIdentifierExportSurface(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "snapshot-export.php"), `<?php
class Demo {
    function generate_snapshot_uid() {
        return substr(str_shuffle(str_repeat('abcdefghijklmnopqrstuvwxyz', 6)), 0, 6);
    }

    function do_export_snapshot($uid = '') {
        return 'wp-reset-snapshot-' . md5($uid) . '.sql.gz';
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "predictable-security-identifier-surface" {
			continue
		}
		if strings.HasSuffix(finding.Path, "snapshot-export.php") && finding.Start.Line == 8 {
			found = true
		}
	}
	if !found {
		t.Fatalf("did not find predictable identifier export surface; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsDynamicControllerDispatchThroughFactoryCallbacks(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "dynamic-controller-dispatch.php"), `<?php
class ControllerBase {
    final public function doAction($actionName, $args = array()) {
        if (method_exists($this, 'action' . $actionName)) {
            call_user_func_array(array($this, 'action' . $actionName), $args);
        }
    }
}

class SlidersController extends ControllerBase {
    protected function actionExportAll() {
        activate_plugin($_GET['plugin']);
    }
}

class DemoApp {
    public function dispatch($defaultControllerName, $defaultActionName, $ajax = false, $args = array()) {
        $controllerName = trim($_GET['controller']);
        if (empty($controllerName)) {
            $controllerName = $defaultControllerName;
        }
        $actionName = trim($_GET['action']);
        if (empty($actionName)) {
            $actionName = $defaultActionName;
        }
        $this->process($controllerName, $actionName, $ajax, $args);
    }

    public function process($controllerName, $actionName, $ajax = false, $args = array()) {
        $controller = $this->getController($controllerName, $ajax);
        $controller->doAction($actionName, $args);
    }

    protected function getController($controllerName, $ajax = false) {
        $methodName = 'getController' . ($ajax ? 'Ajax' : '') . $controllerName;
        if (method_exists($this, $methodName)) {
            return call_user_func(array($this, $methodName));
        }
    }

    protected function getControllerSliders() {
        return new SlidersController();
    }
}

(new DemoApp())->dispatch('sliders', 'index');
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
			continue
		}
		if strings.HasSuffix(finding.Path, "dynamic-controller-dispatch.php") && finding.Start.Line == 12 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not find dynamic controller dispatch action sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootFindsAdminPageDynamicControllerDispatch(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "admin-page-controller-dispatch.php")
	writePHP(t, path, `<?php
function add_action($hook, $callback) {}
function add_menu_page($page_title, $menu_title, $capability, $menu_slug, $callback = '') {}

class ControllerBase {
    final public function doAction($actionName, $args = array()) {
        if (method_exists($this, 'action' . $actionName)) {
            call_user_func_array(array($this, 'action' . $actionName), $args);
        }
    }
}

class SlidersController extends ControllerBase {
    protected function actionExportAll() {
        activate_plugin($_GET['plugin']);
    }
}

class DemoApp {
    public function processRequest($defaultControllerName, $defaultActionName, $ajax = false, $args = array()) {
        $controllerName = trim($_GET['nextendcontroller']);
        if (empty($controllerName)) {
            $controllerName = $defaultControllerName;
        }
        $actionName = trim($_GET['nextendaction']);
        if (empty($actionName)) {
            $actionName = $defaultActionName;
        }
        $this->process($controllerName, $actionName, $ajax, $args);
    }

    public function process($controllerName, $actionName, $ajax = false, $args = array()) {
        $controller = $this->getController($controllerName, $ajax);
        $controller->doAction($actionName, $args);
    }

    protected function getController($controllerName, $ajax = false) {
        $methodName = 'getController' . ($ajax ? 'Ajax' : '') . $controllerName;
        if (method_exists($this, $methodName)) {
            return call_user_func(array($this, $methodName));
        }
    }

    protected function getControllerSliders() {
        return new SlidersController();
    }
}

class AdminHelper {
    public function __construct() {
        add_action('admin_menu', array($this, 'register_menu'));
    }

    public function register_menu() {
        add_menu_page('Smart Slider', 'Smart Slider', 'read', 'smart-slider', array($this, 'display_admin'));
    }

    public function display_admin() {
        $app = new DemoApp();
        $app->processRequest('sliders', 'index');
    }
}

new AdminHelper();
`)

	manifest, err := parsetree.BuildManifestForRoot(root, nil, 1)
	if err != nil {
		t.Fatalf("BuildManifestForRoot(): %v", err)
	}
	files, err := loadFiles(manifest, 1)
	if err != nil {
		t.Fatalf("loadFiles(): %v", err)
	}
	engine, err := buildEngine(root, files, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("buildEngine(): %v", err)
	}
	displayAdminKey := engine.lookupMethodKey(`\AdminHelper`, "display_admin")
	if displayAdminKey == "" {
		t.Fatalf("missing AdminHelper::display_admin")
	}
	if _, ok := engine.directPublicCallables[displayAdminKey]; !ok {
		t.Fatalf("display_admin should be direct public via admin page registration")
	}
	foundEntrypoint := false
	for _, entry := range engine.contexts[displayAdminKey].EntryPoints {
		if entry.Kind == "admin_page" && entry.Name == "smart-slider" && entry.Access == "authenticated" {
			foundEntrypoint = true
			break
		}
	}
	if !foundEntrypoint {
		t.Fatalf("display_admin entrypoints = %#v, want admin_page smart-slider", engine.contexts[displayAdminKey].EntryPoints)
	}
	actionKey := engine.lookupMethodKey(`\SlidersController`, "actionexportall")
	if actionKey == "" {
		t.Fatalf("missing SlidersController::actionExportAll")
	}
	foundActionEntrypoint := false
	for _, entry := range engine.contexts[actionKey].EntryPoints {
		if entry.Kind == "admin_page" && entry.Name == "smart-slider" {
			foundActionEntrypoint = true
			break
		}
	}
	if !foundActionEntrypoint {
		t.Fatalf("actionExportAll entrypoints = %#v, want inherited admin_page smart-slider", engine.contexts[actionKey].EntryPoints)
	}

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"action": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID != "wp-request-sensitive-action-without-cap-check" {
			continue
		}
		if !strings.HasSuffix(finding.Path, "admin-page-controller-dispatch.php") || finding.Start.Line != 15 {
			continue
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("did not find admin-page controller dispatch action sink; findings=%#v", result.Payload.Results)
	}
}

func TestAnalyzeRootSuppressesPredictableIdentifierExportSurfaceAfterLongerIdentifier(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "snapshot-export-safe.php"), `<?php
class Demo {
    function generate_snapshot_uid($length) {
        return substr(str_shuffle(str_repeat('abcdefghijklmnopqrstuvwxyz', $length)), 0, $length);
    }

    function do_export_snapshot($uid = '') {
        $snapshot_file_uid = md5($this->generate_snapshot_uid(10));
        return 'wp-reset-snapshot-' . $snapshot_file_uid . '.sql.gz';
    }
}
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"surface": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	for _, finding := range result.Payload.Results {
		if finding.CheckID == "predictable-security-identifier-surface" {
			t.Fatalf("unexpected predictable identifier surface finding: %#v", result.Payload.Results)
		}
	}
}

func TestAnalyzeRootSuppressesLiteralPreparedSelectWithClassTableProperty(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "prepared-literal-select.php"), `<?php
function add_action($hook, $callback) {}

class WPDB {
    public $prefix = 'wp_';
    public function prepare($query, ...$args) { return $query; }
    public function get_row($query) {}
}

$wpdb = new WPDB();

class Repo {
    private $table;

    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'ur_subscription_orders';
    }

    public function get_order_by_subscription($subscription_id) {
        global $wpdb;
        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * from $this->table WHERE subscription_id = %d ORDER BY ID DESC LIMIT 1",
                $subscription_id
            )
        );
    }
}

class Handler {
    public function __construct() {
        add_action('wp_ajax_nopriv_get_order', array($this, 'handle'));
    }

    public function handle() {
        $repo = new Repo();
        echo json_encode($repo->get_order_by_subscription($_POST['id']));
    }
}

new Handler();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	for _, finding := range result.Payload.Results {
		if finding.CheckID == "tainted-sql-string" {
			t.Fatalf("unexpected SQL injection finding on literal prepared SELECT: %#v", result.Payload.Results)
		}
	}
}

func TestAnalyzeRootStillFlagsConcatenatedSelectThroughPrepare(t *testing.T) {
	root := t.TempDir()
	writePHP(t, filepath.Join(root, "prepared-concat-unsafe.php"), `<?php
function add_action($hook, $callback) {}

class WPDB {
    public function prepare($query, ...$args) { return $query; }
    public function get_results($query) {}
}

$wpdb = new WPDB();

class Handler {
    public function __construct() {
        add_action('wp_ajax_nopriv_bad', array($this, 'handle'));
    }

    public function handle() {
        global $wpdb;
        $order = $_GET['order'];
        $sql = "SELECT * FROM wp_posts ORDER BY " . $order;
        $wpdb->get_results($wpdb->prepare($sql));
    }
}

new Handler();
`)

	result, err := AnalyzeRootWithOptions(root, nil, 1, Options{
		AllowedSinkOps: map[string]struct{}{"sql": {}},
	})
	if err != nil {
		t.Fatalf("AnalyzeRootWithOptions(): %v", err)
	}
	found := false
	for _, finding := range result.Payload.Results {
		if finding.CheckID == "tainted-sql-string" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected tainted-sql-string finding on ORDER BY concat; got %d results", len(result.Payload.Results))
	}
}

func writePHP(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
