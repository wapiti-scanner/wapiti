<?php
/**
 * Map block.
 *
 * @since 6.8.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Map;

use Automattic\Jetpack\Blocks;
use Automattic\Jetpack\Status\Host;
use Automattic\Jetpack\Tracking;
use Jetpack;
use Jetpack_Gutenberg;
use Jetpack_Mapbox_Helper;

const FEATURE_NAME = 'map';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

if ( ! class_exists( 'Jetpack_Mapbox_Helper' ) ) {
	require_once JETPACK__PLUGIN_DIR . '_inc/lib/class-jetpack-mapbox-helper.php';
}

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array(
			'render_callback' => __NAMESPACE__ . '\load_assets',
		)
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Record a Tracks event every time the Map block is loaded on WordPress.com and Atomic.
 *
 * @param string $access_token_source The Mapbox API access token source.
 */
function wpcom_load_event( $access_token_source ) {
	if ( 'wpcom' !== $access_token_source ) {
		return;
	}

	$event_name = 'map_block_mapbox_wpcom_key_load';
	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
		require_lib( 'tracks/client' );
		tracks_record_event( wp_get_current_user(), $event_name );
	} elseif ( ( new Host() )->is_woa_site() && Jetpack::is_connection_ready() ) {
		$tracking = new Tracking();
		$tracking->record_user_event( $event_name );
	}
}

/**
 * Map block registration/dependency declaration.
 *
 * @param array  $attr    Array containing the map block attributes.
 * @param string $content String containing the map block content.
 *
 * @return string
 */
function load_assets( $attr, $content ) {
	$access_token = Jetpack_Mapbox_Helper::get_access_token();

	wpcom_load_event( $access_token['source'] );

	if ( Blocks::is_amp_request() ) {
		static $map_block_counter = array();

		$id = get_the_ID();
		if ( ! isset( $map_block_counter[ $id ] ) ) {
			$map_block_counter[ $id ] = 0;
		}
		++$map_block_counter[ $id ];

		$iframe_url = add_query_arg(
			array(
				'map-block-counter' => absint( $map_block_counter[ $id ] ),
				'map-block-post-id' => $id,
			),
			get_permalink()
		);

		$placeholder = preg_replace( '/(?<=<div\s)/', 'placeholder ', $content );

		return sprintf(
			'<amp-iframe src="%s" width="%d" height="%d" layout="responsive" allowfullscreen sandbox="allow-scripts">%s</amp-iframe>',
			esc_url( $iframe_url ),
			4,
			3,
			$placeholder
		);
	}

	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	return preg_replace( '/<div /', '<div data-api-key="' . esc_attr( $access_token['key'] ) . '" ', $content, 1 );
}

/**
 * Render a page containing only a single Map block.
 */
function render_single_block_page() {
	// phpcs:ignore WordPress.Security.NonceVerification
	$map_block_counter = isset( $_GET, $_GET['map-block-counter'] ) ? absint( $_GET['map-block-counter'] ) : null;
	// phpcs:ignore WordPress.Security.NonceVerification
	$map_block_post_id = isset( $_GET, $_GET['map-block-post-id'] ) ? absint( $_GET['map-block-post-id'] ) : null;

	if ( ! $map_block_counter || ! $map_block_post_id ) {
		return;
	}

	/* Create an array of all root-level DIVs that are Map Blocks */
	$post = get_post( $map_block_post_id );

	if ( ! class_exists( 'DOMDocument' ) ) {
		return;
	}

	$post_html = new \DOMDocument();
	/** This filter is already documented in core/wp-includes/post-template.php */
	$content = apply_filters( 'the_content', $post->post_content );

	/* Suppress warnings */
	libxml_use_internal_errors( true );
	@$post_html->loadHTML( $content ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
	libxml_use_internal_errors( false );

	$xpath     = new \DOMXPath( $post_html );
	$container = $xpath->query( '//div[ contains( @class, "wp-block-jetpack-map" ) ]' )->item( $map_block_counter - 1 );

	/* Check that we have a block matching the counter position */
	if ( ! $container ) {
		return;
	}

	/* Compile scripts and styles */
	ob_start();

	add_filter( 'jetpack_is_amp_request', '__return_false' );

	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );
	wp_scripts()->do_items();
	wp_styles()->do_items();

	add_filter( 'jetpack_is_amp_request', '__return_true' );

	$head_content = ob_get_clean();

	/* Put together a new complete document containing only the requested block markup and the scripts/styles needed to render it */
	$block_markup = $post_html->saveHTML( $container );
	$access_token = Jetpack_Mapbox_Helper::get_access_token();
	$page_html    = sprintf(
		'<!DOCTYPE html><head><style>html, body { margin: 0; padding: 0; }</style>%s</head><body>%s</body>',
		$head_content,
		preg_replace( '/(?<=<div\s)/', 'data-api-key="' . esc_attr( $access_token['key'] ) . '" ', $block_markup, 1 )
	);
	echo $page_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	exit;
}
add_action( 'wp', __NAMESPACE__ . '\render_single_block_page' );

/**
 * Helper function to generate the markup of the block in PHP.
 *
 * @param Array $points - Array containing geo location points.
 *
 * @return string Markup for the jetpack/map block.
 */
function map_block_from_geo_points( $points ) {
	$map_block_data = array(
		'points'    => $points,
		'zoom'      => 8,
		'mapCenter' => array(
			'lng' => $points[0]['coordinates']['longitude'],
			'lat' => $points[0]['coordinates']['latitude'],
		),
	);

	$list_items = array_map(
		function ( $point ) {
			$link = add_query_arg(
				array(
					'api'   => 1,
					'query' => $point['coordinates']['latitude'] . ',' . $point['coordinates']['longitude'],
				),
				'https://www.google.com/maps/search/'
			);
			return sprintf( '<li><a href="%s">%s</a></li>', esc_url( $link ), $point['title'] );
		},
		$points
	);

	$map_block  = '<!-- wp:jetpack/map ' . wp_json_encode( $map_block_data ) . ' -->' . PHP_EOL;
	$map_block .= sprintf(
		'<div class="wp-block-jetpack-map" data-map-style="default" data-map-details="true" data-points="%1$s" data-zoom="%2$d" data-map-center="%3$s" data-marker-color="red" data-show-fullscreen-button="true">',
		esc_html( wp_json_encode( $map_block_data['points'] ) ),
		(int) $map_block_data['zoom'],
		esc_html( wp_json_encode( $map_block_data['mapCenter'] ) )
	);
	$map_block .= '<ul>' . implode( "\n", $list_items ) . '</ul>';
	$map_block .= '</div>' . PHP_EOL;
	$map_block .= '<!-- /wp:jetpack/map -->';

	return $map_block;
}
