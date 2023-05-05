<?php
/**
 * Config for the WP.com REST API
 *
 * @package automattic/jetpack
 */

define( 'WPCOM_JSON_API__CURRENT_VERSION', '1.1' );
global $wpcom_json_api_production_versions, $wpcom_json_api_dev_versions;

$wpcom_json_api_production_versions = array(
	'1',
	'1.1',
);

$wpcom_json_api_dev_versions = array(
	'1.2',
	'1.3',
	'1.4',
);
