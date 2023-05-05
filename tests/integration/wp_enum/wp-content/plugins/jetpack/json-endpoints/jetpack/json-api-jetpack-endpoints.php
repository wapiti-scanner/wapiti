<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

$json_jetpack_endpoints_dir = __DIR__ . '/';

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-endpoint.php';

// THEMES
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-themes-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-themes-active-endpoint.php';

new Jetpack_JSON_API_Themes_Active_Endpoint(
	array(
		'description'             => 'Get the active theme of your blog',
		'stat'                    => 'themes:mine',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/themes/mine',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'         => Jetpack_JSON_API_Themes_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes/mine',
	)
);

new Jetpack_JSON_API_Themes_Active_Endpoint(
	array(
		'description'             => 'Change the active theme of your blog',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/themes/mine',
		'stat'                    => 'themes:mine',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'query_parameters'        => array(
			'context' => false,
		),
		'request_format'          => array(
			'theme'                => '(string) The ID of the theme that should be activated',
			'dont_change_homepage' => '(bool) Whether the homepage of the site should be replaced with the theme homepage',
		),
		'response_format'         => Jetpack_JSON_API_Themes_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'theme' => 'twentytwelve',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes/mine',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-themes-list-endpoint.php';

new Jetpack_JSON_API_Themes_List_Endpoint(
	array(
		'description'             => 'Get WordPress.com Themes allowed on your blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'themes',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/themes',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'         => array(
			'found'  => '(int) The total number of themes found.',
			'themes' => '(array) An array of theme objects.',
		),
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-themes-get-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-themes-new-endpoint.php';

// POST /sites/%s/themes/%new
new Jetpack_JSON_API_Themes_New_Endpoint(
	array(
		'description'             => 'Install a theme to your jetpack blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'themes:new',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/themes/new',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'zip' => '(zip) Theme package zip file. multipart/form-data encoded. ',
		),
		'response_format'         => Jetpack_JSON_API_Themes_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes/new',
	)
);

new Jetpack_JSON_API_Themes_Get_Endpoint(
	array(
		'description'             => 'Get a single theme on a jetpack blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'themes:get:1',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/themes/%s',
		'path_labels'             => array(
			'$site'  => '(int|string) The site ID, The site domain',
			'$theme' => '(string) The theme slug',
		),
		'response_format'         => Jetpack_JSON_API_Themes_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes/twentyfourteen',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-themes-modify-endpoint.php';
new Jetpack_JSON_API_Themes_Modify_Endpoint(
	array(
		'description'             => 'Modify a single theme on a jetpack blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'themes:modify:1',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/themes/%s',
		'path_labels'             => array(
			'$site'  => '(int|string) The site ID, The site domain',
			'$theme' => '(string) The theme slug',
		),
		'request_format'          => array(
			'action'     => '(string) Only possible value is \'update\'. More to follow.',
			'autoupdate' => '(bool) Whether or not to automatically update the theme.',
		),
		'response_format'         => Jetpack_JSON_API_Themes_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'action' => 'update',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes/twentyfourteen',
	)
);

new Jetpack_JSON_API_Themes_Modify_Endpoint(
	array(
		'description'             => 'Modify a list of themes on a jetpack blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'themes:modify',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/themes',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'action'     => '(string) Only possible value is \'update\'. More to follow.',
			'autoupdate' => '(bool) Whether or not to automatically update the theme.',
			'themes'     => '(array) A list of theme slugs',
		),
		'response_format'         => array(
			'themes' => '(array:theme) A list of theme objects',
		),
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'action' => 'autoupdate_on',
				'themes' => array(
					'twentytwelve',
					'twentyfourteen',
				),
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-themes-install-endpoint.php';
// POST /sites/%s/themes/%s/install
new Jetpack_JSON_API_Themes_Install_Endpoint(
	array(
		'description'             => 'Install a theme to your jetpack blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'themes:1:install',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/themes/%s/install',
		'path_labels'             => array(
			'$site'  => '(int|string) The site ID, The site domain',
			'$theme' => '(int|string) The theme slug to install',
		),
		'response_format'         => Jetpack_JSON_API_Themes_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes/twentyfourteen/install',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-themes-delete-endpoint.php';
// POST /sites/%s/themes/%s/delete
new Jetpack_JSON_API_Themes_Delete_Endpoint(
	array(
		'description'             => 'Delete/Uninstall a theme from your jetpack blog',
		'group'                   => '__do_not_document',
		'stat'                    => 'themes:1:delete',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/themes/%s/delete',
		'path_labels'             => array(
			'$site'  => '(int|string) The site ID, The site domain',
			'$theme' => '(string) The slug of the theme to delete',
		),
		'response_format'         => Jetpack_JSON_API_Themes_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/themes/twentyfourteen/delete',
	)
);

// PLUGINS
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-plugins-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-plugins-get-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-plugins-list-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-plugins-new-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-plugins-install-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-plugins-delete-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-plugins-modify-endpoint.php';

// PLUGINS V1.2
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-plugins-modify-v1-2-endpoint.php';

// Jetpack Modules
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-modules-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-modules-get-endpoint.php';

new Jetpack_JSON_API_Modules_Get_Endpoint(
	array(
		'description'             => 'Get the info about a Jetpack Module on your Jetpack Site',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/jetpack/modules/%s/',
		'stat'                    => 'jetpack:modules:1',
		'path_labels'             => array(
			'$site'   => '(int|string) The site ID, The site domain',
			'$module' => '(string) The module name',
		),
		'response_format'         => Jetpack_JSON_API_Modules_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/jetpack/modules/stats',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-modules-modify-endpoint.php';

new Jetpack_JSON_API_Modules_Modify_Endpoint(
	array(
		'description'             => 'Modify the status of a Jetpack Module on your Jetpack Site',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/jetpack/modules/%s/',
		'stat'                    => 'jetpack:modules:1',
		'path_labels'             => array(
			'$site'   => '(int|string) The site ID, The site domain',
			'$module' => '(string) The module name',
		),
		'request_format'          => array(
			'active' => '(bool) The module activation status',
		),
		'response_format'         => Jetpack_JSON_API_Modules_Endpoint::$_response_format,
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'active' => true,
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/jetpack/modules/stats',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-modules-list-endpoint.php';

new Jetpack_JSON_API_Modules_List_Endpoint(
	array(
		'description'             => 'Get the list of available Jetpack modules on your site',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/jetpack/modules',
		'stat'                    => 'jetpack:modules',
		'min_version'             => '1',
		'max_version'             => '1.1',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'         => array(
			'found'   => '(int) The total number of modules found.',
			'modules' => '(array) An array of module objects.',
		),
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/jetpack/modules',
	)
);

require_once $json_jetpack_endpoints_dir . 'class-jetpack-json-api-modules-list-v1-2-endpoint.php';

new Jetpack_JSON_API_Modules_List_V1_2_Endpoint(
	array(
		'description'             => 'Get the list of available Jetpack modules on your site',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/jetpack/modules',
		'stat'                    => 'jetpack:modules',
		'min_version'             => '1.2',
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'         => array(
			'modules' => '(array) An array of module objects.',
		),
		'allow_jetpack_site_auth' => true,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.2/sites/example.wordpress.org/jetpack/modules',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-updates-status-endpoint.php';

new Jetpack_JSON_API_Updates_Status(
	array(
		'description'          => 'Get counts for available updates',
		'method'               => 'GET',
		'path'                 => '/sites/%s/updates',
		'stat'                 => 'updates',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'      => array(
			'plugins'           => '(int) The total number of plugins updates.',
			'themes'            => '(int) The total number of themes updates.',
			'wordpress'         => '(int) The total number of core updates.',
			'translations'      => '(int) The total number of translation updates.',
			'total'             => '(int) The total number of updates.',
			'wp_version'        => '(safehtml) The wp_version string.',
			'wp_update_version' => '(safehtml) The wp_version to update string.',
			'jp_version'        => '(safehtml) The site Jetpack version.',
		),
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/updates',
	)
);

// Jetpack Extras

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-check-capabilities-endpoint.php';

new Jetpack_JSON_API_Check_Capabilities_Endpoint(
	array(
		'description'          => 'Check if the current user has a certain capability over a Jetpack site',
		'method'               => 'GET',
		'path'                 => '/sites/%s/me/capability',
		'stat'                 => 'me:capabulity',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'      => '(bool) True if the user has the queried capability.',
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'capability' => 'A single capability or an array of capabilities',
			),
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/me/capability',
	)
);

// CORE
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-core-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-core-modify-endpoint.php';

new Jetpack_JSON_API_Core_Endpoint(
	array(
		'description'          => 'Gets info about a Jetpack blog\'s core installation',
		'method'               => 'GET',
		'path'                 => '/sites/%s/core',
		'stat'                 => 'core',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'      => array(
			'version'    => '(string) The current version',
			'autoupdate' => '(bool) Whether or not we automatically update core',
		),
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/core',
	)
);

new Jetpack_JSON_API_Core_Modify_Endpoint(
	array(
		'description'          => 'Update WordPress installation on a Jetpack blog',
		'method'               => 'POST',
		'path'                 => '/sites/%s/core/update',
		'stat'                 => 'core:update',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'       => array(
			'version' => '(string) The core version to update',
		),
		'response_format'      => array(
			'version' => '(string) The core version after the upgrade has run.',
			'log'     => '(array:safehtml) An array of log strings.',
		),
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/core/update',
	)
);

new Jetpack_JSON_API_Core_Endpoint(
	array(
		'description'          => 'Toggle automatic core updates for a Jetpack blog',
		'method'               => 'POST',
		'path'                 => '/sites/%s/core',
		'stat'                 => 'core',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'       => array(
			'autoupdate' => '(bool) Whether or not we automatically update core',
		),
		'response_format'      => array(
			'version'    => '(string) The current version',
			'autoupdate' => '(bool) Whether or not we automatically update core',
		),
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'autoupdate' => true,
			),
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/core',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-sync-endpoint.php';

// POST /sites/%s/sync
new Jetpack_JSON_API_Sync_Endpoint(
	array(
		'description'             => 'Force sync of all options and constants',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/sync',
		'stat'                    => 'sync',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'modules'  => '(string) Comma-delimited set of sync modules to use (default: all of them)',
			'posts'    => '(string) Comma-delimited list of post IDs to sync',
			'comments' => '(string) Comma-delimited list of comment IDs to sync',
			'users'    => '(string) Comma-delimited list of user IDs to sync',
		),
		'response_format'         => array(
			'scheduled' => '(bool) Whether or not the synchronisation was started',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync',
	)
);

// GET /sites/%s/sync/status
new Jetpack_JSON_API_Sync_Status_Endpoint(
	array(
		'description'             => 'Status of the current full sync or the previous full sync',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/sync/status',
		'stat'                    => 'sync-status',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'query_parameters'        => array(
			'fields' => '(string|null) List of comma-separated fields to return (see `response_format`).',
		),
		'response_format'         => array(
			'posts_checksum'        => '(string|null) Posts checksum. Needs to be requested using the filter parameter.',
			'comments_checksum'     => '(string|null) Comments checksum. Needs to be requested using the filter parameter.',
			'post_meta_checksum'    => '(string|null) Post Meta checksum. Needs to be requested using the filter parameter.',
			'comment_meta_checksum' => '(string|null) Comment Meta checksum. Needs to be requested using the filter parameter.',
			'started'               => '(int|null) The unix timestamp when the last sync started',
			'queue_finished'        => '(int|null) The unix timestamp when the enqueuing was done for the last sync',
			'send_started'          => '(int|null) The unix timestamp when the last send process started',
			'finished'              => '(int|null) The unix timestamp when the last sync finished',
			'total'                 => '(array) Count of actions that could be sent',
			'queue'                 => '(array) Count of actions that have been added to the queue',
			'sent'                  => '(array) Count of actions that have been sent',
			'config'                => '(array) Configuration of the last full sync',
			'queue_size'            => '(int) Number of items in the sync queue',
			'queue_lag'             => '(float) Time delay of the oldest item in the sync queue',
			'queue_next_sync'       => '(float) Time in seconds before trying to sync again',
			'full_queue_size'       => '(int) Number of items in the full sync queue',
			'full_queue_lag'        => '(float) Time delay of the oldest item in the full sync queue',
			'full_queue_next_sync'  => '(float) Time in seconds before trying to sync the full sync queue again',
			'cron_size'             => '(int) Size of the current cron array',
			'next_cron'             => '(int) The number of seconds till the next item in cron.',
			'progress'              => '(array) Full Sync status by module',
			'debug_details'         => '(array) Details as to why Sync is disabled.',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/status',
	)
);

// GET /sites/%s/data-checksums
new Jetpack_JSON_API_Sync_Check_Endpoint(
	array(
		'description'             => 'Check that cacheable data on the site is in sync with wordpress.com',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/data-checksums',
		'stat'                    => 'data-checksums',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'         => array(
			'posts'    => '(string) Posts checksum',
			'comments' => '(string) Comments checksum',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/data-checksums',
	)
);

// GET /sites/%s/data-histogram
new Jetpack_JSON_API_Sync_Histogram_Endpoint(
	array(
		'description'             => 'Get a histogram of checksums for certain synced data',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/data-histogram',
		'stat'                    => 'data-histogram',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'query_parameters'        => array(
			'object_type'        => '(string=posts) The type of object to checksum - posts, comments or options',
			'buckets'            => '(int=10) The number of buckets for the checksums',
			'start_id'           => '(int=0) Starting ID for the range',
			'end_id'             => '(int=null) Ending ID for the range',
			'columns'            => '(string) Columns to checksum',
			'strip_non_ascii'    => '(bool=true) Strip non-ascii characters from all columns',
			'shared_salt'        => '(string) Salt to reduce the collision and improve validation',
			'only_range_edges'   => '(bool=false) Only return the edges of the specified range',
			'detailed_drilldown' => '(bool=false) Return a detailed drilldown in `key => checksum` format',
		),
		'response_format'         => array(
			'histogram' => '(array) Associative array of histograms by ID range, e.g. "500-999" => "abcd1234"',
			'type'      => '(string) Type of checksum algorithm',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/data-histogram',
	)
);

// POST /sites/%s/sync/health .
new Jetpack_JSON_API_Sync_Modify_Health_Endpoint(
	array(
		'description'             => 'Update sync health',
		'method'                  => 'POST',
		'group'                   => '__do_not_document',
		'path'                    => '/sites/%s/sync/health',
		'stat'                    => 'write-sync-health',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'status' => '(string) Sync Health Status of site',
		),
		'response_format'         => array(
			'response' => '(string) Current Sync Health ',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/health',
	)
);

$sync_settings_response = array(
	'dequeue_max_bytes'        => '(int|bool=false) Maximum bytes to read from queue in a single request',
	'sync_wait_time'           => '(int|bool=false) Wait time between requests in seconds if sync threshold exceeded',
	'sync_wait_threshold'      => '(int|bool=false) If a request to WPCOM exceeds this duration, wait sync_wait_time seconds before sending again',
	'upload_max_bytes'         => '(int|bool=false) Maximum bytes to send in a single request',
	'upload_max_rows'          => '(int|bool=false) Maximum rows to send in a single request',
	'max_queue_size'           => '(int|bool=false) Maximum queue size that that the queue is allowed to expand to in DB rows to prevent the DB from filling up. Needs to also meet the max_queue_lag limit.',
	'max_queue_lag'            => '(int|bool=false) Maximum queue lag in seconds used to prevent the DB from filling up. Needs to also meet the max_queue_size limit.',
	'queue_max_writes_sec'     => '(int|bool=false) Maximum writes per second to allow to the queue during full sync.',
	'post_types_blacklist'     => '(array|string|bool=false) List of post types to exclude from sync. Send "empty" to unset.',
	'post_meta_whitelist'      => '(array|string|bool=false) List of post meta to be included in sync. Send "empty" to unset.',
	'comment_meta_whitelist'   => '(array|string|bool=false) List of comment meta to be included in sync. Send "empty" to unset.',
	'disable'                  => '(int|bool=false) Set to 1 or true to disable sync entirely.',
	'checksum_disable'         => '(int|bool=false) Set to 1 or true to disable checksums entirely.',
	'render_filtered_content'  => '(int|bool=true) Set to 1 or true to render filtered content.',
	'max_enqueue_full_sync'    => '(int|bool=false) Maximum number of rows to enqueue during each full sync process',
	'max_queue_size_full_sync' => '(int|bool=false) Maximum queue size that full sync is allowed to use',
	'full_sync_send_duration'  => '(float) Max full sync duration per request',
	'sync_via_cron'            => '(int|bool=false) Set to 1 or true to avoid using cron for sync.',
	'cron_sync_time_limit'     => '(int|bool=false) Limit cron jobs to number of seconds',
	'enqueue_wait_time'        => '(int|bool=false) Wait time in seconds between attempting to continue a full sync, via requests',
	'sync_sender_enabled'      => '(int|bool=false) Set to 1 or true to enable the default sender for the incremental queue.',
	'full_sync_sender_enabled' => '(int|bool=false) Set to 1 or true to enable the default sender for the "full sync" queue.',
);

// GET /sites/%s/sync/settings
new Jetpack_JSON_API_Sync_Get_Settings_Endpoint(
	array(
		'description'             => 'Update sync settings',
		'method'                  => 'GET',
		'group'                   => '__do_not_document',
		'path'                    => '/sites/%s/sync/settings',
		'stat'                    => 'write-sync-settings',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'         => $sync_settings_response,
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/settings',
	)
);

// POST /sites/%s/sync/settings
new Jetpack_JSON_API_Sync_Modify_Settings_Endpoint(
	array(
		'description'             => 'Update sync settings',
		'method'                  => 'POST',
		'group'                   => '__do_not_document',
		'path'                    => '/sites/%s/sync/settings',
		'stat'                    => 'write-sync-settings',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => $sync_settings_response,
		'response_format'         => $sync_settings_response,
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/settings',
	)
);

// GET /sites/%s/sync/object
new Jetpack_JSON_API_Sync_Object(
	array(
		'description'             => 'Get an object by ID from one of the sync modules, in the format it would be synced in',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/sync/object',
		'stat'                    => 'sync-object',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'query_parameters'        => array(
			'module_name' => '(string) The sync module ID, e.g. "posts"',
			'object_type' => '(string) An identified for the object type, e.g. "post"',
			'object_ids'  => '(array) The IDs of the objects',
		),
		'response_format'         => array(
			'objects' => '(string) The encoded objects',
			'codec'   => '(string) The codec used to encode the objects, deflate-json-array or simple',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/object?module_name=posts&object_type=post&object_ids[]=1&object_ids[]=2&object_ids[]=3',
	)
);

// POST /sites/%s/sync/now
new Jetpack_JSON_API_Sync_Now_Endpoint(
	array(
		'description'             => 'Force immediate sync of top items on a queue',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/sync/now',
		'stat'                    => 'sync-now',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'queue' => '(string) sync or full_sync',
		),
		'response_format'         => array(
			'response' => '(array) The response from the server',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/now?queue=full_sync',
	)
);

// POST /sites/%s/sync/unlock
new Jetpack_JSON_API_Sync_Unlock_Endpoint(
	array(
		'description'             => 'Unlock the queue in case it gets locked by a process.',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/sync/unlock',
		'group'                   => '__do_not_document',
		'stat'                    => 'sync-unlock',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'queue' => '(string) sync or full_sync',
		),
		'response_format'         => array(
			'success' => '(bool) Unlocking the queue successful?',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/unlock',
	)
);

// GET /sites/%s/sync/object-id-range
new Jetpack_JSON_API_Sync_Object_Id_Range(
	array(
		'description'             => 'Gets minimum and maximum object ids for each batch of given batch size.',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/sync/object-id-range',
		'group'                   => '__do_not_document',
		'stat'                    => 'sync-object-id-range',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'query_parameters'        => array(
			'batch_size'  => '(int=1000) The amount of objects per batch.',
			'sync_module' => '(string=posts) The sync module used to enumerate the ranges.',
		),
		'response_format'         => array(
			'ranges' => '(array) An array of range objects with min and max properties for each batch.',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/object-id-range?batch_size=100&sync_module=comments',
	)
);

// POST /sites/%s/sync/checkout
new Jetpack_JSON_API_Sync_Checkout_Endpoint(
	array(
		'description'             => 'Locks the queue and returns items and the buffer ID.',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/sync/checkout',
		'group'                   => '__do_not_document',
		'stat'                    => 'sync-checkout',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'queue'           => '(string) sync or full_sync',
			'number_of_items' => '(int=10) Maximum number of items from the queue to be returned',
			'encode'          => '(bool=true) Use the default encode method',
			'force'           => '(bool=false) Force unlock the queue',
			'pop'             => '(bool=false) Pop from the queue without checkout, use carefully 😱',
		),
		'response_format'         => array(
			'buffer_id'      => '(string) Buffer ID that we are using',
			'items'          => '(array) Items from the queue that are ready to be processed by the sync server',
			'skipped_items'  => '(array) Skipped item ids',
			'codec'          => '(string) The name of the codec used to encode the data',
			'sent_timestamp' => '(int) Current timestamp of the server',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/checkout',
	)
);

// POST /sites/%s/sync/close
new Jetpack_JSON_API_Sync_Close_Endpoint(
	array(
		'description'             => 'Closes the buffer and delete the processed items from the queue.',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/sync/close',
		'group'                   => '__do_not_document',
		'stat'                    => 'sync-close',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'item_ids'  => '(array) Item IDs to delete from the queue.',
			'queue'     => '(string) sync or full_sync',
			'buffer_id' => '(string) buffer ID that was opened during the checkout step.',
			'continue'  => '(bool=false) Perform another checkout from queue.',
		),
		'response_format'         => array(
			'success' => '(bool) Closed the buffer successfully?',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/sync/close',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-log-endpoint.php';

new Jetpack_JSON_API_Jetpack_Log_Endpoint(
	array(
		'description'     => 'Get the Jetpack log',
		'method'          => 'GET',
		'path'            => '/sites/%s/jetpack-log',
		'stat'            => 'log',
		'path_labels'     => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'  => array(
			'event' => '(string) The event to filter by, by default all entries are returned',
			'num'   => '(int) The number of entries to get, by default all entries are returned',
		),
		'response_format' => array(
			'log' => '(array) An array of jetpack log entries',
		),
		'example_request' => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/jetpack-log',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-maybe-auto-update-endpoint.php';

new Jetpack_JSON_API_Maybe_Auto_Update_Endpoint(
	array(
		'description'     => 'Maybe Auto Update Core, Plugins, Themes and Languages',
		'method'          => 'POST',
		'path'            => '/sites/%s/maybe-auto-update',
		'stat'            => 'maybe-auto-update',
		'path_labels'     => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format' => array(
			'log' => '(array) Results of running the update job',
		),
		'example_request' => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/maybe-auto-update',

	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-translations-endpoint.php';
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-translations-modify-endpoint.php';

new Jetpack_JSON_API_Translations_Endpoint(
	array(
		'description'          => 'Gets info about a Jetpack blog\'s core installation',
		'method'               => 'GET',
		'path'                 => '/sites/%s/translations',
		'stat'                 => 'translations',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'      => array(
			'translations' => '(array) A list of translations that are available',
			'autoupdate'   => '(bool) Whether or not we automatically update translations',
			'log'          => '(array:safehtml) An array of log strings.',
		),
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/translations',
	)
);

new Jetpack_JSON_API_Translations_Modify_Endpoint(
	array(
		'description'          => 'Toggle automatic core updates for a Jetpack blog',
		'method'               => 'POST',
		'path'                 => '/sites/%s/translations',
		'stat'                 => 'translations',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'       => array(
			'autoupdate' => '(bool) Whether or not we automatically update translations',
		),
		'response_format'      => array(
			'translations' => '(array) A list of translations that are available',
			'autoupdate'   => '(bool) Whether or not we automatically update translations',
		),
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'autoupdate' => true,
			),
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/translations',
	)
);

new Jetpack_JSON_API_Translations_Modify_Endpoint(
	array(
		'description'          => 'Update All Translations installation on a Jetpack blog',
		'method'               => 'POST',
		'path'                 => '/sites/%s/translations/update',
		'stat'                 => 'translations:update',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'      => array(
			'log'     => '(array:safehtml) An array of log strings.',
			'success' => '(bool) Was the operation successful',
		),
		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/translations/update',
	)
);

// Options
require_once $json_jetpack_endpoints_dir . 'class.wpcom-json-api-get-option-endpoint.php';

new WPCOM_JSON_API_Get_Option_Endpoint(
	array(
		'method'                  => 'GET',
		'description'             => 'Fetches an option.',
		'group'                   => '__do_not_document',
		'stat'                    => 'option',
		'allow_jetpack_site_auth' => true,
		'path'                    => '/sites/%s/option',
		'path_labels'             => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters'        => array(
			'option_name' => '(string) The name of the option to fetch.',
			'site_option' => '(bool=false) True if the option is a site option.',
		),
		'response_format'         => array(
			'option_value' => '(string|object) The value of the option.',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/option?option_name=blogname',
		'example_request_data'    => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
		),
	)
);

require_once $json_jetpack_endpoints_dir . 'class.wpcom-json-api-update-option-endpoint.php';

new WPCOM_JSON_API_Update_Option_Endpoint(
	array(
		'method'                  => 'POST',
		'description'             => 'Updates an option.',
		'group'                   => '__do_not_document',
		'stat'                    => 'option:update',
		'allow_jetpack_site_auth' => true,
		'path'                    => '/sites/%s/option',
		'path_labels'             => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters'        => array(
			'option_name' => '(string) The name of the option to fetch.',
			'site_option' => '(bool=false) True if the option is a site option.',
			'is_array'    => '(bool=false) True if the value should be converted to an array before saving.',
		),
		'request_format'          => array(
			'option_value' => '(string|object) The new value of the option.',
		),
		'response_format'         => array(
			'option_value' => '(string|object) The value of the updated option.',
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1.1/sites/82974409/option',
		'example_request_data'    => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
			'body'    => array(
				'option_value' => 'My new blog name',
			),
		),
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-cron-endpoint.php';

// GET /sites/%s/cron
new Jetpack_JSON_API_Cron_Endpoint(
	array(
		'description'          => 'Fetches the cron array',
		'group'                => '__do_not_document',
		'method'               => 'GET',
		'path'                 => '/sites/%s/cron',
		'stat'                 => 'cron-get',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'      => array(
			'cron_array'        => '(array) The cron array',
			'current_timestamp' => '(int) Current server timestamp',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/cron',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
		),
	)
);

// POST /sites/%s/cron
new Jetpack_JSON_API_Cron_Post_Endpoint(
	array(
		'description'          => 'Process items in the cron',
		'group'                => '__do_not_document',
		'method'               => 'POST',
		'path'                 => '/sites/%s/cron',
		'stat'                 => 'cron-run',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'       => array(
			'hooks' => '(array) List of hooks to run if they have been scheduled (optional)',
		),
		'response_format'      => array(
			'success' => '(array) Of processed hooks with their arguments',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/cron',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
			'body'    => array(
				'hooks' => array( 'jetpack_sync_cron' ),
			),
		),
	)
);

// POST /sites/%s/cron/schedule
new Jetpack_JSON_API_Cron_Schedule_Endpoint(
	array(
		'description'          => 'Schedule one or a recurring hook to fire at a particular time',
		'group'                => '__do_not_document',
		'method'               => 'POST',
		'path'                 => '/sites/%s/cron/schedule',
		'stat'                 => 'cron-schedule',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'       => array(
			'hook'       => '(string) Hook name that should run when the event is scheduled',
			'timestamp'  => '(int) Timestamp when the event should take place, has to be in the future',
			'arguments'  => '(string) JSON Object of arguments that the hook will use (optional)',
			'recurrence' => '(string) How often the event should take place. If empty only one event will be scheduled. Possible values 1min, hourly, twicedaily, daily (optional) ',
		),
		'response_format'      => array(
			'success' => '(bool) Was the event scheduled?',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/cron/schedule',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
			'body'    => array(
				'hook'       => 'jetpack_sync_cron',
				'arguments'  => '[]',
				'recurrence' => '1min',
				'timestamp'  => 1476385523,
			),
		),
	)
);

// POST /sites/%s/cron/unschedule
new Jetpack_JSON_API_Cron_Unschedule_Endpoint(
	array(
		'description'          => 'Unschedule one or all events with a particular hook and arguments',
		'group'                => '__do_not_document',
		'method'               => 'POST',
		'path'                 => '/sites/%s/cron/unschedule',
		'stat'                 => 'cron-unschedule',
		'path_labels'          => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'       => array(
			'hook'      => '(string) Name of the hook that should be unscheduled',
			'timestamp' => '(int) Timestamp of the hook that you want to unschedule. This will unschedule only 1 event. (optional)',
			'arguments' => '(string) JSON Object of arguments that the hook has been scheduled with (optional)',
		),
		'response_format'      => array(
			'success' => '(bool) Was the event unscheduled?',
		),
		'example_request'      => 'https://public-api.wordpress.com/rest/v1.1/sites/example.wordpress.org/cron/unschedule',
		'example_request_data' => array(
			'headers' => array( 'authorization' => 'Bearer YOUR_API_TOKEN' ),
			'body'    => array(
				'hook'      => 'jetpack_sync_cron',
				'arguments' => '[]',
				'timestamp' => 1476385523,
			),
		),
	)
);

// BACKUPS

// GET /sites/%s/database-object/backup
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-get-database-object-backup-endpoint.php';
new Jetpack_JSON_API_Get_Database_Object_Backup_Endpoint(
	array(
		'description'             => 'Fetch a backup of a database object, along with all of its metadata',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/database-object/backup',
		'stat'                    => 'database-objects:1:backup',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'query_parameters'        => array(
			'object_type' => '(string) Type of object to fetch from the database',
			'object_id'   => '(int) ID of the database object to fetch',
		),
		'response_format'         => array(
			'object'   => '(array) Database object row',
			'meta'     => '(array) Associative array of key/value metadata associated with the row',
			'children' => '(array) Where appropriate, child records associated with the object. eg: Woocommerce tax rate locations',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/database-object/backup',
	)
);

// GET /sites/%s/comments/%d/backup
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-get-comment-backup-endpoint.php';
new Jetpack_JSON_API_Get_Comment_Backup_Endpoint(
	array(
		'description'             => 'Fetch a backup of a comment, along with all of its metadata',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/comments/%d/backup',
		'stat'                    => 'comments:1:backup',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
			'$post' => '(int) The comment ID',
		),
		'response_format'         => array(
			'comment' => '(array) Comment table row',
			'meta'    => '(array) Associative array of key/value commentmeta data',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/comments/1/backup',
	)
);

// GET /sites/%s/options/backup
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-get-option-backup-endpoint.php';
new Jetpack_JSON_API_Get_Option_Backup_Endpoint(
	array(
		'description'             => 'Fetch a backup of an option',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/options/backup',
		'stat'                    => 'options:backup',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'query_parameters'        => array(
			'name' => '(string|array) One or more option names to include in the backup',
		),
		'response_format'         => array(
			'options' => '(array) Associative array of option_name => option_value entries',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/options/backup',
	)
);

// GET /sites/%s/posts/%d/backup
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-get-post-backup-endpoint.php';
new Jetpack_JSON_API_Get_Post_Backup_Endpoint(
	array(
		'description'             => 'Fetch a backup of a post, along with all of its metadata',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/posts/%d/backup',
		'stat'                    => 'posts:1:backup',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
			'$post' => '(int) The post ID',
		),
		'response_format'         => array(
			'post'  => '(array) Post table row',
			'meta'  => '(array) Associative array of key/value postmeta data',
			'terms' => '(array) List of terms attached to the post object',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/posts/1/backup',
	)
);

// GET /sites/%s/terms/%d/backup
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-get-term-backup-endpoint.php';
new Jetpack_JSON_API_Get_Term_Backup_Endpoint(
	array(
		'description'             => 'Fetch a backup of a term, along with all of its metadata',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/terms/%d/backup',
		'stat'                    => 'terms:1:backup',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
			'$term' => '(int) The term ID',
		),
		'response_format'         => array(
			'term' => '(array) Term table row',
			'meta' => '(array) Metadata associated with the term',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/terms/1/backup',
	)
);

// GET /sites/%s/users/%d/backup
require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-get-user-backup-endpoint.php';
new Jetpack_JSON_API_Get_User_Backup_Endpoint(
	array(
		'description'             => 'Fetch a backup of a user, along with all of its metadata',
		'group'                   => '__do_not_document',
		'method'                  => 'GET',
		'path'                    => '/sites/%s/users/%d/backup',
		'stat'                    => 'users:1:backup',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
			'$user' => '(int) The user ID',
		),
		'response_format'         => array(
			'user' => '(array) User table row',
			'meta' => '(array) Associative array of key/value usermeta data',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/users/1/backup',
	)
);

// USERS

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-user-connect-endpoint.php';

// POST /sites/%s/users/%d/connect
new Jetpack_JSON_API_User_Connect_Endpoint(
	array(
		'description'             => 'Creates or returns a new user given profile data',
		'group'                   => '__do_not_document',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/users/%d/connect',
		'stat'                    => 'users:connect',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site'    => '(int|string) The site ID, The site domain',
			'$user_id' => '(int) The site user ID to connect',
		),
		'request_format'          => array(
			'user_token' => '(string) The user token',
		),
		'response_format'         => array(
			'success' => '(bool) Was the user connected',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'user_token' => 'XDH55jndskjf3klh3',
			),
		),
		'example_response'        => '{
       "success" => true
    }',
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/users/6/connect',
	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-user-create-endpoint.php';

// POST /sites/%s/users/create
new Jetpack_JSON_API_User_Create_Endpoint(
	array(
		'description'             => 'Creates or returns a new user given profile data',
		'group'                   => '__do_not_document',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/users/create',
		'stat'                    => 'users:create',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'query_parameters'        => array(
			'invite_accepted' => '(bool=false) If the user is being created in the invite context',
		),
		'request_format'          => WPCOM_JSON_API_Site_User_Endpoint::$user_format,
		'response_format'         => WPCOM_JSON_API_Site_User_Endpoint::$user_format,
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'roles'      => array(
					array(
						'administrator',
					),
				),
				'first_name' => 'John',
				'last_name'  => 'Doe',
				'email'      => 'john.doe@example.wordpress.org',
			),
		),
		'example_response'        => '{
        "ID": 18342963,
        "login": "binarysmash"
        "email": false,
        "name": "binarysmash",
        "URL": "http:\/\/binarysmash.wordpress.com",
        "avatar_URL": "http:\/\/0.gravatar.com\/avatar\/a178ebb1731d432338e6bb0158720fcc?s=96&d=identicon&r=G",
        "profile_URL": "http:\/\/en.gravatar.com\/binarysmash",
        "roles": [ "administrator" ]
    }',
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/users/create',

	)
);

require_once $json_jetpack_endpoints_dir . 'class.jetpack-json-api-jps-woocommerce-connect-endpoint.php';

// POST /sites/%s/jps/woo-connect
new Jetpack_JSON_API_JPS_WooCommerce_Connect_Endpoint(
	array(
		'description'             => 'Attempts to connect the WooCommerce plugin for this site to WooCommerce.com.',
		'group'                   => '__do_not_document',
		'method'                  => 'POST',
		'path'                    => '/sites/%s/jps/woo-connect',
		'stat'                    => 'jps:woo-connect',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'access_token'        => '(string) The access token for WooCommerce to connect to WooCommerce.com',
			'access_token_secret' => '(string) The access token secret for WooCommerce to connect to WooCommerce.com',
			'user_id'             => '(int) The user\'s ID after registering for a host plan',
			'site_id'             => '(int) The site\'s ID after registering for a host plan',
		),
		'response_format'         => array(
			'success' => '(bool) Setting access token and access token secret successful?',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
			'body'    => array(
				'access_token'        => '123456789',
				'access_token_secret' => 'abcdefghiklmnop',
				'user_id'             => 1,
				'site_id'             => 2,
			),
		),
		'example_response'        => '{ "success": true }',
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/jps/woo-connect',
	)
);

// POST /sites/%s/install-backup-helper-script
require_once $json_jetpack_endpoints_dir . 'class-jetpack-json-api-install-backup-helper-script-endpoint.php';
new Jetpack_JSON_API_Install_Backup_Helper_Script_Endpoint(
	array(
		'description'             => 'Setup a Helper Script, to allow Jetpack Backup to connect to this site',
		'group'                   => '__do_not_document',
		'method'                  => 'POST',
		'stat'                    => 'install-backup-helper-script',
		'path'                    => '/sites/%s/install-backup-helper-script',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'request_format'          => array(
			'helper' => '(string) Base64-encoded Helper Script contents',
		),
		'response_format'         => array(
			'abspath' => '(string) WordPress install path',
			'path'    => '(string) Path of the helper script',
			'url'     => '(string) URL to access the helper script',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/install-backup-helper-script',
	)
);

// POST /sites/%s/delete-backup-helper-script
require_once $json_jetpack_endpoints_dir . 'class-jetpack-json-api-delete-backup-helper-script-endpoint.php';
new Jetpack_JSON_API_Delete_Backup_Helper_Script_Endpoint(
	array(
		'description'             => 'Delete a Helper Script',
		'group'                   => '__do_not_document',
		'method'                  => 'POST',
		'stat'                    => 'delete-backup-helper-script',
		'path'                    => '/sites/%s/delete-backup-helper-script',
		'allow_jetpack_site_auth' => true,
		'path_labels'             => array(
			'$site' => '(int|string) The site ID, The site domain',
		),
		'response_format'         => array(
			'success' => '(bool) Deleted the Helper Script successfully?',
		),
		'request_format'          => array(
			'path' => '(string) Path to Helper Script to delete',
		),
		'example_request_data'    => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
		'example_request'         => 'https://public-api.wordpress.com/rest/v1/sites/example.wordpress.org/delete-backup-helper-script',
	)
);
