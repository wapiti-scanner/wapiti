<?php
/**
 * Endpoint class definitions are located inside the files that require these endpoint classes.
 * file ordering matters
 *
 * @package automattic/jetpack
 */

$json_endpoints_dir = __DIR__ . '/json-endpoints/';

// abstract endpoints
require_once $json_endpoints_dir . 'class.wpcom-json-api-post-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-post-v1-1-endpoint.php'; // v1.1
require_once $json_endpoints_dir . 'class.wpcom-json-api-comment-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-taxonomy-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-render-endpoint.php';

// **********
// v1
// **********

require_once $json_endpoints_dir . 'class.wpcom-json-api-delete-media-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-comment-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-comments-tree-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-media-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-post-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-render-shortcode-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-shortcodes-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-render-embed-reversal-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-render-embed-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-embeds-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-site-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-taxonomies-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-taxonomy-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-term-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-comments-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-dropdown-pages-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-media-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-post-types-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-post-type-taxonomies-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-posts-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-roles-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-terms-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-users-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-site-user-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-bulk-update-comments-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-comment-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-media-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-post-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-taxonomy-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-term-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-user-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-upload-media-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-site-settings-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-sharing-buttons-endpoint.php';

// **********
// v1.1
// **********

// Comments
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-comments-tree-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-comment-counts-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-comment-history-endpoint.php';

// Media
require_once $json_endpoints_dir . 'class.wpcom-json-api-delete-media-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-media-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-media-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-media-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-upload-media-v1-1-endpoint.php';

// Posts
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-post-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-posts-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-post-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-autosave-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-autosave-post-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-post-counts-v1-1-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-bulk-delete-post-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-bulk-restore-post-endpoint.php';

// Custom Menus
require_once $json_endpoints_dir . 'class.wpcom-json-api-menus-v1-1-endpoint.php';

// Custom CSS
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-customcss.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-customcss.php';

// Logo Settings
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-site-logo-endpoint.php';

// Homepage Settings
require_once $json_endpoints_dir . 'class.wpcom-json-api-update-site-homepage-endpoint.php';

// Widgets
require_once $json_endpoints_dir . 'class.wpcom-json-api-add-widget-endpoint.php';

// **********
// v1.2
// **********

// Comments
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-comments-tree-v1-2-endpoint.php';

// Media
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-media-v1-2-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-media-v1-2-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-edit-media-v1-2-endpoint.php';

require_once $json_endpoints_dir . 'class.wpcom-json-api-update-post-v1-2-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-site-settings-v1-2-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-get-site-v1-2-endpoint.php';
require_once $json_endpoints_dir . 'class.wpcom-json-api-list-posts-v1-2-endpoint.php';

// Jetpack Only Endpoints
if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	$json_jetpack_endpoints_dir = ABSPATH . 'public.api/rest/json-endpoints/jetpack/';
} else {
	$json_jetpack_endpoints_dir = __DIR__ . '/json-endpoints/jetpack/';
}

// This files instantiates the endpoints
require_once $json_jetpack_endpoints_dir . 'json-api-jetpack-endpoints.php';

// **********
// v1.3
// **********

require_once $json_endpoints_dir . 'class.wpcom-json-api-site-settings-v1-3-endpoint.php';

// **********
// v1.4
// **********

require_once $json_endpoints_dir . 'class.wpcom-json-api-site-settings-v1-4-endpoint.php';

