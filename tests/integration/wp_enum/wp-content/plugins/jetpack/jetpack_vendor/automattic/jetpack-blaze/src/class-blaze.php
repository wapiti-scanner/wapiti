<?php
/**
 * Attract high-quality traffic to your site.
 *
 * @package automattic/jetpack-blaze
 */

namespace Automattic\Jetpack;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Initial_State as Connection_Initial_State;
use Automattic\Jetpack\Connection\Manager as Jetpack_Connection;
use Automattic\Jetpack\Sync\Settings as Sync_Settings;

/**
 * Class for promoting posts.
 */
class Blaze {

	const PACKAGE_VERSION = '0.5.11';

	/**
	 * Script handle for the JS file we enqueue in the post editor.
	 *
	 * @var string
	 */
	const SCRIPT_HANDLE = 'jetpack-promote-editor';

	/**
	 * Path of the JS file we enqueue in the post editor.
	 *
	 * @var string
	 */
	public static $script_path = '../build/editor.js';

	/**
	 * The configuration method that is called from the jetpack-config package.
	 *
	 * @return void
	 */
	public static function init() {
		// On the edit screen, add a row action to promote the post.
		add_action( 'load-edit.php', array( __CLASS__, 'add_post_links_actions' ) );
		// In the post editor, add a post-publish panel to allow promoting the post.
		add_action( 'enqueue_block_editor_assets', array( __CLASS__, 'enqueue_block_editor_assets' ) );
	}

	/**
	 * Add links under each published post in the wp-admin post list.
	 *
	 * @return void
	 */
	public static function add_post_links_actions() {
		if ( self::should_initialize() ) {
			add_filter( 'post_row_actions', array( __CLASS__, 'jetpack_blaze_row_action' ), 10, 2 );
			add_filter( 'page_row_actions', array( __CLASS__, 'jetpack_blaze_row_action' ), 10, 2 );
		}
	}

	/**
	 * Check the WordPress.com REST API
	 * to ensure that the site supports the Blaze feature.
	 * Results are cached for a day.
	 *
	 * @param int $blog_id The blog ID to check.
	 *
	 * @return bool
	 */
	public static function site_supports_blaze( $blog_id ) {
		/*
		 * On WordPress.com, we don't need to make an API request,
		 * we can query directly.
		 */
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM && function_exists( 'blaze_is_site_eligible' ) ) {
			return blaze_is_site_eligible( $blog_id );
		}

		$cached_result = get_transient( 'jetpack_blaze_site_supports_blaze_' . $blog_id );
		if ( false !== $cached_result ) {
			return $cached_result;
		}

		// Make the API request.
		$url      = sprintf( '/sites/%d/blaze/status', $blog_id );
		$response = Client::wpcom_json_api_request_as_blog(
			$url,
			'2',
			array( 'method' => 'GET' ),
			null,
			'wpcom'
		);

		// Bail if there was an error or malformed response.
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		// Decode the results.
		$result = json_decode( wp_remote_retrieve_body( $response ), true );

		// Bail if there were no results returned.
		if ( ! is_array( $result ) || empty( $result['approved'] ) ) {
			return false;
		}

		// Cache the result for 24 hours.
		set_transient( 'jetpack_blaze_site_supports_blaze_' . $blog_id, (bool) $result['approved'], DAY_IN_SECONDS );

		return (bool) $result['approved'];
	}

	/**
	 * Determines if criteria is met to enable Blaze features.
	 * Keep in mind that this makes remote requests, so we want to avoid calling it when unnecessary, like in the frontend.
	 *
	 * @return bool
	 */
	public static function should_initialize() {
		$should_initialize = true;
		$is_wpcom          = defined( 'IS_WPCOM' ) && IS_WPCOM;
		$connection        = new Jetpack_Connection();
		$site_id           = Jetpack_Connection::get_site_id();

		// Only admins should be able to Blaze posts on a site.
		if ( ! current_user_can( 'manage_options' ) ) {
			return false;
		}

		// On self-hosted sites, we must do some additional checks.
		if ( ! $is_wpcom ) {
			/*
			* These features currently only work on WordPress.com,
			* so the site must be connected to WordPress.com, and the user as well for things to work.
			*/
			if (
				is_wp_error( $site_id )
				|| ! $connection->is_connected()
				|| ! $connection->is_user_connected()
			) {
				$should_initialize = false;
			}

			// The whole thing is powered by Sync!
			if ( ! Sync_Settings::is_sync_enabled() ) {
				$should_initialize = false;
			}
		}

		// Check if the site supports Blaze.
		if ( is_numeric( $site_id ) && ! self::site_supports_blaze( $site_id ) ) {
			$should_initialize = false;
		}

		/**
		 * Filter to disable all Blaze functionality.
		 *
		 * @since 0.3.0
		 *
		 * @param bool $should_initialize Whether Blaze should be enabled. Default to true.
		 */
		return apply_filters( 'jetpack_blaze_enabled', $should_initialize );
	}

	/**
	 * Adds the Promote link to the posts list row action.
	 *
	 * @param array   $post_actions The current array of post actions.
	 * @param WP_Post $post The current post in the post list table.
	 *
	 * @return array
	 */
	public static function jetpack_blaze_row_action( $post_actions, $post ) {
		$post_id = $post->ID;

		// Bail if we are not looking at one of the supported post types (post, page, or product).
		if ( ! in_array( $post->post_type, array( 'post', 'page', 'product' ), true ) ) {
			return $post_actions;
		}

		// Bail if the post is not published.
		if ( $post->post_status !== 'publish' ) {
			return $post_actions;
		}

		// Bail if the post has a password.
		if ( '' !== $post->post_password ) {
			return $post_actions;
		}

		// Might be useful to wrap in a method call for general use without post_id.
		$blaze_url = Redirect::get_url(
			'jetpack-blaze',
			array(
				'query' => 'blazepress-widget=post-' . esc_attr( $post_id ),
			)
		);

		// Add the link, make sure to tooltip hover.
		$text  = _x( 'Blaze', 'Verb', 'jetpack-blaze' );
		$title = _draft_or_post_title( $post );
		/* translators: post title */
		$label                 = sprintf( __( 'Blaze &#8220;%s&#8221; to Tumblr and WordPress.com audiences.', 'jetpack-blaze' ), $title );
		$post_actions['blaze'] = sprintf(
			'<a href="%1$s" target="_blank" title="%2$s" aria-label="%2$s" rel="noopener noreferrer">%3$s</a>',
			esc_url( $blaze_url ),
			esc_attr( $label ),
			esc_html( $text )
		);

		return $post_actions;
	}

	/**
	 * Enqueue block editor assets.
	 */
	public static function enqueue_block_editor_assets() {
		/*
		 * We do not want (nor need) Blaze in the site editor, or the widget editor, or the classic editor.
		 * We only want it in the post editor.
		 * Enqueueing the script in those editors would cause a fatal error.
		 * See #20357 for more info.
		*/
		if ( ! function_exists( 'get_current_screen' ) ) { // When Gutenberg is loaded in the frontend.
			return;
		}
		$current_screen = get_current_screen();
		if (
			empty( $current_screen )
			|| $current_screen->base !== 'post'
			|| ! $current_screen->is_block_editor()
		) {
			return;
		}
		// Bail if criteria is not met to enable Blaze features.
		if ( ! self::should_initialize() ) {
			return;
		}

		Assets::register_script(
			self::SCRIPT_HANDLE,
			self::$script_path,
			__FILE__,
			array(
				'enqueue'    => true,
				'in_footer'  => true,
				'textdomain' => 'jetpack-blaze',
			)
		);

		// Adds Connection package initial state.
		wp_add_inline_script( self::SCRIPT_HANDLE, Connection_Initial_State::render(), 'before' );
	}
}
