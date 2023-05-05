<?php
/**
 * Helper functions to work with licenses, permissions and capabilities.
 *
 * @since 1.8.0
 */

/**
 * Determine if the plugin/addon installations are allowed.
 *
 * @since 1.6.2.3
 *
 * @param string $type Should be `plugin` or `addon`.
 *
 * @return bool
 */
function wpforms_can_install( $type ) {

	return wpforms_can_do( 'install', $type );
}

/**
 * Determine if the plugin/addon activations are allowed.
 *
 * @since 1.7.3
 *
 * @param string $type Should be `plugin` or `addon`.
 *
 * @return bool
 */
function wpforms_can_activate( $type ) {

	return wpforms_can_do( 'activate', $type );
}

/**
 * Determine if the plugin/addon installations/activations are allowed.
 *
 * @since 1.7.3
 *
 * @internal Use wpforms_can_activate() or wpforms_can_install() instead.
 *
 * @param string $what Should be 'activate' or 'install'.
 * @param string $type Should be `plugin` or `addon`.
 *
 * @return bool
 */
function wpforms_can_do( $what, $type ) {

	if ( ! in_array( $what, [ 'install', 'activate' ], true ) ) {
		return false;
	}

	if ( ! in_array( $type, [ 'plugin', 'addon' ], true ) ) {
		return false;
	}

	$capability = $what . '_plugins';

	if ( ! current_user_can( $capability ) ) {
		return false;
	}

	// Determine whether file modifications are allowed and it is activation permissions checking.
	if ( $what === 'install' && ! wp_is_file_mod_allowed( 'wpforms_can_install' ) ) {
		return false;
	}

	// All plugin checks are done.
	if ( $type === 'plugin' ) {
		return true;
	}

	// Addons require additional license checks.
	$license = get_option( 'wpforms_license', [] );

	// Allow addons installation if license is not expired, enabled and valid.
	return empty( $license['is_expired'] ) && empty( $license['is_disabled'] ) && empty( $license['is_invalid'] );
}

/**
 * Get the current installation license type (always lowercase).
 *
 * @since 1.5.6
 *
 * @return string|false
 */
function wpforms_get_license_type() {

	$type = wpforms_setting( 'type', '', 'wpforms_license' );

	if ( empty( $type ) || ! wpforms()->is_pro() ) {
		return false;
	}

	return strtolower( $type );
}

/**
 * Get the current installation license key.
 *
 * @since 1.6.2.3
 * @since 1.8.0 WPFORMS_LICENSE_KEY constant has higher priority than the DB option.
 *
 * @return string
 */
function wpforms_get_license_key() {

	// Allow wp-config constant to pass key.
	if ( defined( 'WPFORMS_LICENSE_KEY' ) && WPFORMS_LICENSE_KEY ) {
		return WPFORMS_LICENSE_KEY;
	}

	return wpforms_setting( 'key', '', 'wpforms_license' );
}

/**
 * Get when WPForms was first installed.
 *
 * @since 1.6.0
 *
 * @param string $type Specific install type to check for.
 *
 * @return int|false Unix timestamp. False on failure.
 */
function wpforms_get_activated_timestamp( $type = '' ) {

	$activated = (array) get_option( 'wpforms_activated', [] );

	if ( empty( $activated ) ) {
		return false;
	}

	// When a passed install type is empty, then get it from a DB.
	// If it is installed/activated first, it is saved first.
	$type = empty( $type ) ? (string) array_keys( $activated )[0] : $type;

	if ( ! empty( $activated[ $type ] ) ) {
		return absint( $activated[ $type ] );
	}

	// Fallback.
	$types = array_diff( [ 'lite', 'pro' ], [ $type ] );

	foreach ( $types as $_type ) {
		if ( ! empty( $activated[ $_type ] ) ) {
			return absint( $activated[ $_type ] );
		}
	}

	return false;
}

/**
 * Retrieve a timestamp when WPForms was upgraded.
 *
 * @since 1.7.5
 *
 * @param string $version Specific plugin version to check for.
 *
 * @return int|false Unix timestamp or migration status. False on failure.
 *                   Available migration statuses:
 *                   -2 if migration is failed;
 *                   -1 if migration is started (in progress);
 *                    0 if migration is completed, but no luck to set a timestamp.
 */
function wpforms_get_upgraded_timestamp( $version ) {

	$option_name = wpforms()->is_pro() ? 'wpforms_versions' : 'wpforms_versions_lite';
	$upgrades    = (array) get_option( $option_name, [] );

	if ( ! isset( $upgrades[ $version ] ) ) {
		return false;
	}

	return (int) $upgrades[ $version ];
}

/**
 * Get the default capability to manage everything for WPForms.
 *
 * @since 1.4.4
 *
 * @return string
 */
function wpforms_get_capability_manage_options() {

	return apply_filters( 'wpforms_manage_cap', 'manage_options' );
}

/**
 * Check WPForms permissions for currently logged in user.
 * Both short (e.g. 'view_own_forms') or long (e.g. 'wpforms_view_own_forms') capability name can be used.
 * Only WPForms capabilities get processed.
 *
 * @since 1.4.4
 *
 * @param array|string $caps Capability name(s).
 * @param int          $id   ID of the specific object to check against if capability is a "meta" cap. "Meta"
 *                           capabilities, e.g. 'edit_post', 'edit_user', etc., are capabilities used by
 *                           map_meta_cap() to map to other "primitive" capabilities, e.g. 'edit_posts',
 *                           edit_others_posts', etc. Accessed via func_get_args() and passed to
 *                           WP_User::has_cap(), then map_meta_cap().
 *
 * @return bool
 */
function wpforms_current_user_can( $caps = [], $id = 0 ) {

	$access = wpforms()->get( 'access' );

	if ( ! method_exists( $access, 'current_user_can' ) ) {
		return false;
	}

	$user_can = $access->current_user_can( $caps , $id );

	return apply_filters( 'wpforms_current_user_can', $user_can, $caps, $id );
}

/**
 * Search for posts editable by user.
 *
 * @since 1.7.9
 *
 * @param string $search_term Optional search term. Default ''.
 * @param array  $args        Args {
 *                            Optional. An array of arguments.
 *
 * @type string   $post_type   Post type to search for.
 * @type string[] $post_status Post status to search for.
 * @type int      $count       Number of results to return. Default 20.
 * }
 *
 * @return array
 * @noinspection PhpTernaryExpressionCanBeReducedToShortVersionInspection
 * @noinspection ElvisOperatorCanBeUsedInspection
 */
function wpforms_search_posts( $search_term = '', $args = [] ) {

	global $wpdb;

	$default_args = [
		'post_type'   => 'page',
		'post_status' => [ 'publish' ],
		'count'       => 20,
	];
	$args         = wp_parse_args( $args, $default_args );

	// @todo: add trash access capabilities to MySQL.
	// See edit_post/edit_page case in map_meta_cap().
	$args['post_status'] = array_diff( $args['post_status'], [ 'trash' ] );

	$user      = wp_get_current_user();
	$user_id   = $user ? $user->ID : 0;
	$post_type = get_post_type_object( $args['post_type'] );

	if ( ! $user_id || ! $post_type || $args['count'] <= 0 ) {
		return [];
	}

	$last_changed = wp_cache_get_last_changed( 'posts' );
	$key          = __FUNCTION__ . ":$search_term:$last_changed";
	$cache_posts  = wp_cache_get( $key, '', false, $found );

	if ( $found ) {
		return $cache_posts;
	}

	$post_title_where = $search_term ? $wpdb->prepare(
		'post_title LIKE %s AND',
		'%' . $wpdb->esc_like( $search_term ) . '%'
	) :
		'';

	$post_statuses              = array_intersect( array_keys( get_post_statuses() ), $args['post_status'] );
	$post_statuses              = wpforms_wpdb_prepare_in( $post_statuses );
	$policy_id                  = (int) get_option( 'wp_page_for_privacy_policy' );
	$can_delete_published_posts = (int) $user->has_cap( $post_type->cap->delete_published_posts );
	$can_delete_posts           = (int) $user->has_cap( $post_type->cap->delete_posts );
	$can_delete_others_posts    = (int) $user->has_cap( $post_type->cap->delete_others_posts );
	$can_delete_private_posts   = (int) $user->has_cap( $post_type->cap->delete_private_posts );
	$can_edit_policy            = (int) $user->has_cap( map_meta_cap( 'manage_privacy_options', $user_id )[0] );

	// For the case when user is post author.
	$capability_author_where = "post_author = $user_id AND
		( ( post_status IN ( 'publish', 'future' ) AND $can_delete_published_posts ) OR
		( ( post_status NOT IN ( 'publish', 'future', 'trash' ) ) AND $can_delete_posts )
		)";

	// For the case when accessing someone other's post.
	$capability_other_where = "post_author != $user_id AND
		$can_delete_others_posts AND
		( ( post_status IN ( 'publish', 'future' ) AND $can_delete_published_posts ) OR
		( ( post_status IN ( 'private' ) ) AND $can_delete_private_posts )
		)";

	// For privacy policy page.
	$capability_policy_where = "ID = $policy_id AND $can_edit_policy";

	$capability_where = '( ' .
		'(' . $capability_author_where . ') OR ' .
		'(' . $capability_other_where . ') OR ' .
		'(' . $capability_policy_where . ')' .
		' )';

	// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$posts = $wpdb->get_results(
		$wpdb->prepare(
			"SELECT ID, post_title, post_author
					FROM $wpdb->posts
					WHERE $post_title_where
					post_type = '{$args['post_type']}' AND
					post_status IN ( $post_statuses ) AND
					$capability_where
					ORDER BY post_title LIMIT %d",
			absint( $args['count'] )
		)
	);
	// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

	$posts = $posts ? $posts : [];
	$posts = array_map(
		static function ( $post ) {
			$post->post_title = wpforms_get_post_title( $post );

			unset( $post->post_author );

			return $post;
		},
		$posts
	);

	wp_cache_set( $key, $posts );

	return $posts;
}

/**
 * Search pages by search term and return an array containing
 * `value` and `label` which is the post ID and post title respectively.
 *
 * @since 1.7.9
 *
 * @param string $search_term The search term.
 * @param array  $args        Optional. An array of arguments.
 *
 * @return array
 */
function wpforms_search_pages_for_dropdown( $search_term, $args = [] ) {

	$search_results = wpforms_search_posts( $search_term, $args );
	$result_pages   = [];

	// Prepare for ChoicesJS render.
	foreach ( $search_results as $search_result ) {
		$result_pages[] = [
			'value' => absint( $search_result->ID ),
			'label' => esc_html( $search_result->post_title ),
		];
	}

	return $result_pages;
}
