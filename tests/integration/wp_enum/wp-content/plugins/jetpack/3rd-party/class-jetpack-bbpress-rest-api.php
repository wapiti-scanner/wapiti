<?php
/**
 * REST API Compatibility: bbPress & Jetpack
 * Enables bbPress to work with the Jetpack REST API
 *
 * @package automattic/jetpack
 */

/**
 * REST API Compatibility: bbPress.
 */
class Jetpack_BbPress_REST_API {

	/**
	 * Singleton
	 *
	 * @var Jetpack_BbPress_REST_API.
	 */
	private static $instance;

	/**
	 * Returns or creates the singleton.
	 *
	 * @return Jetpack_BbPress_REST_API
	 */
	public static function instance() {
		if ( isset( self::$instance ) ) {
			return self::$instance;
		}

		self::$instance = new self();
	}

	/**
	 * Jetpack_BbPress_REST_API constructor.
	 */
	private function __construct() {
		add_filter( 'rest_api_allowed_post_types', array( $this, 'allow_bbpress_post_types' ) );
		add_filter( 'bbp_map_meta_caps', array( $this, 'adjust_meta_caps' ), 10, 4 );
		add_filter( 'rest_api_allowed_public_metadata', array( $this, 'allow_bbpress_public_metadata' ) );
	}

	/**
	 * Adds the bbPress post types to the rest_api_allowed_post_types filter.
	 *
	 * @param array $allowed_post_types Allowed post types.
	 *
	 * @return array
	 */
	public function allow_bbpress_post_types( $allowed_post_types ) {
		$allowed_post_types[] = 'forum';
		$allowed_post_types[] = 'topic';
		$allowed_post_types[] = 'reply';
		return $allowed_post_types;
	}

	/**
	 * Adds the bbpress meta keys to the rest_api_allowed_public_metadata filter.
	 *
	 * @param array $allowed_meta_keys Allowed meta keys.
	 *
	 * @return array
	 */
	public function allow_bbpress_public_metadata( $allowed_meta_keys ) {
		$allowed_meta_keys[] = '_bbp_forum_id';
		$allowed_meta_keys[] = '_bbp_topic_id';
		$allowed_meta_keys[] = '_bbp_status';
		$allowed_meta_keys[] = '_bbp_forum_type';
		$allowed_meta_keys[] = '_bbp_forum_subforum_count';
		$allowed_meta_keys[] = '_bbp_reply_count';
		$allowed_meta_keys[] = '_bbp_total_reply_count';
		$allowed_meta_keys[] = '_bbp_topic_count';
		$allowed_meta_keys[] = '_bbp_total_topic_count';
		$allowed_meta_keys[] = '_bbp_topic_count_hidden';
		$allowed_meta_keys[] = '_bbp_last_topic_id';
		$allowed_meta_keys[] = '_bbp_last_reply_id';
		$allowed_meta_keys[] = '_bbp_last_active_time';
		$allowed_meta_keys[] = '_bbp_last_active_id';
		$allowed_meta_keys[] = '_bbp_sticky_topics';
		$allowed_meta_keys[] = '_bbp_voice_count';
		$allowed_meta_keys[] = '_bbp_reply_count_hidden';
		$allowed_meta_keys[] = '_bbp_anonymous_reply_count';

		return $allowed_meta_keys;
	}

	/**
	 * Adds the needed caps to the bbp_map_meta_caps filter.
	 *
	 * @param array  $caps Capabilities for meta capability.
	 * @param string $cap Capability name.
	 * @param int    $user_id User id.
	 * @param array  $args Arguments.
	 *
	 * @return array
	 */
	public function adjust_meta_caps( $caps, $cap, $user_id, $args ) {

		// Return early if not a REST request or if not meta bbPress caps.
		if ( $this->should_adjust_meta_caps_return_early( $caps, $cap, $user_id, $args ) ) {
			return $caps;
		}

		// $args[0] could be a post ID or a post_type string.
		if ( is_int( $args[0] ) ) {
			$_post = get_post( $args[0] );
			if ( ! empty( $_post ) ) {
				$post_type = get_post_type_object( $_post->post_type );
			}
		} elseif ( is_string( $args[0] ) ) {
			$post_type = get_post_type_object( $args[0] );
		}

		// no post type found, bail.
		if ( empty( $post_type ) ) {
			return $caps;
		}

		// reset the needed caps.
		$caps = array();

		// Add 'do_not_allow' cap if user is spam or deleted.
		if ( bbp_is_user_inactive( $user_id ) ) {
			$caps[] = 'do_not_allow';

			// Moderators can always edit meta.
		} elseif ( user_can( $user_id, 'moderate' ) ) { // phpcs:ignore WordPress.WP.Capabilities.Unknown
			$caps[] = 'moderate';

			// Unknown so map to edit_posts.
		} else {
			$caps[] = $post_type->cap->edit_posts;
		}

		return $caps;
	}

	/**
	 * Should adjust_meta_caps return early?
	 *
	 * @param array  $caps Capabilities for meta capability.
	 * @param string $cap Capability name.
	 * @param int    $user_id User id.
	 * @param array  $args Arguments.
	 *
	 * @return bool
	 */
	private function should_adjust_meta_caps_return_early( $caps, $cap, $user_id, $args ) {
		// only run for REST API requests.
		if ( ! defined( 'REST_API_REQUEST' ) || ! REST_API_REQUEST ) {
			return true;
		}

		// only modify caps for meta caps and for bbPress meta keys.
		if ( ! in_array( $cap, array( 'edit_post_meta', 'delete_post_meta', 'add_post_meta' ), true ) || empty( $args[1] ) || false === strpos( $args[1], '_bbp_' ) ) {
			return true;
		}

		return false;
	}
}
