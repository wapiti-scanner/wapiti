<?php
/**
 * Used by the blogging prompt feature.
 *
 * @package automattic/jetpack
 */

/**
 * Hooked functions.
 */

/**
 * Adds the blogging prompt key post meta to the list of allowed post meta to be updated by rest api.
 *
 * @param array $keys Array of post meta keys that are allowed public metadata.
 *
 * @return array
 */
function jetpack_blogging_prompts_add_meta_data( $keys ) {
	$keys[] = '_jetpack_blogging_prompt_key';
	return $keys;
}

add_filter( 'rest_api_allowed_public_metadata', 'jetpack_blogging_prompts_add_meta_data' );

/**
 * Sets up a new post as an answer to a blogging prompt.
 *
 * When we know a user is explicitly answering a prompt, pre-populate the post meta to mark the post as a prompt response,
 * in case they decide to remove the block from the post content, preventing they meta from being added later.
 *
 * Called on `wp_insert_post` hook.
 *
 * @param int $post_id ID of post being inserted.
 * @return void
 */
function jetpack_setup_blogging_prompt_response( $post_id ) {
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Clicking a prompt response link can happen from notifications, Calypso, wp-admin, email, etc and only sets up a response post (tag, meta, prompt text); the user must take action to actually publish the post.
	$prompt_id = isset( $_GET['answer_prompt'] ) && absint( $_GET['answer_prompt'] ) ? absint( $_GET['answer_prompt'] ) : false;

	if ( ! jetpack_is_new_post_screen() || ! $prompt_id ) {
		return;
	}

	// Make sure the prompt exists.
	$prompt = jetpack_get_blogging_prompt_by_id( $prompt_id );

	if ( $prompt ) {
		update_post_meta( $post_id, '_jetpack_blogging_prompt_key', $prompt_id );
		wp_add_post_tags( $post_id, array( 'dailyprompt', "dailyprompt-$prompt_id" ) );
	}
}

add_action( 'wp_insert_post', 'jetpack_setup_blogging_prompt_response' );

/**
 * When a published posts answers a blogging prompt, store the prompt id in the post meta.
 *
 * @param int          $post_id     Post ID.
 * @param WP_Post      $post        Post object.
 * @param bool         $update      Whether this is an existing post being updated.
 * @param null|WP_Post $post_before Null for new posts, the WP_Post object prior
 *                                  to the update for updated posts.
 */
function jetpack_mark_if_post_answers_blogging_prompt( $post_id, $post, $update, $post_before ) {
	if ( ! $post instanceof WP_Post ) {
		return;
	}

	$post_type    = isset( $post->post_type ) ? $post->post_type : null;
	$post_content = isset( $post->post_content ) ? $post->post_content : null;

	if ( 'post' !== $post_type || ! $post_content ) {
		return;
	}

	$new_status = isset( $post->post_status ) ? $post->post_status : null;
	$old_status = $post_before && isset( $post_before->post_status ) ? $post_before->post_status : null;

	// Make sure we are publishing a post, and it's not already published.
	if ( 'publish' !== $new_status || 'publish' === $old_status ) {
		return;
	}

	$blocks = parse_blocks( $post->post_content );
	foreach ( $blocks as $block ) {
		if ( 'jetpack/blogging-prompt' === $block['blockName'] ) {
			$prompt_id      = isset( $block['attrs']['promptId'] ) ? absint( $block['attrs']['promptId'] ) : null;
			$has_prompt_tag = has_tag( 'dailyprompt', $post ) || ( $prompt_id && has_tag( "dailyprompt-{$prompt_id}", $post ) );

			if ( $prompt_id && $has_prompt_tag && count( $blocks ) > 1 ) {
				update_post_meta( $post->ID, '_jetpack_blogging_prompt_key', $prompt_id );
			}

			break;
		}
	}
}

add_action( 'wp_after_insert_post', 'jetpack_mark_if_post_answers_blogging_prompt', 10, 4 );

/**
 * Utility functions.
 */

/**
 * Retrieve a blogging prompt by prompt ID.
 *
 * @param int $prompt_id ID of the prompt fetch.
 * @return stdClass|null Prompt object or null.
 */
function jetpack_get_blogging_prompt_by_id( $prompt_id ) {
	// Ensure the REST API endpoint we need is loaded.
	require_once __DIR__ . '/lib/core-api/wpcom-endpoints/class-wpcom-rest-api-v3-endpoint-blogging-prompts.php';

	$locale = get_locale();
	$route  = sprintf( '/wpcom/v3/blogging-prompts/%d', $prompt_id );

	$request = new WP_REST_Request( 'GET', $route );
	$request->set_param( '_locale', $locale );
	$response = rest_do_request( $request );

	if ( $response->is_error() || WP_Http::OK !== $response->get_status() ) {
		return null;
	}

	$prompt = $response->get_data();

	return $prompt;
}

/**
 * Retrieve daily blogging prompts from the wpcom API and cache them.
 *
 * @param int $time Unix timestamp representing the day for which to get blogging prompts.
 * @return stdClass[]|null Array of blogging prompt objects or null.
 */
function jetpack_get_daily_blogging_prompts( $time = 0 ) {
	$timestamp = $time ? $time : time();

	// Include prompts from the previous day, just in case someone has an outdated prompt id.
	$day_before    = wp_date( 'Y-m-d', $timestamp - DAY_IN_SECONDS );
	$locale        = get_locale();
	$transient_key = 'jetpack_blogging_prompt_' . $day_before . '_' . $locale;
	$daily_prompts = get_transient( $transient_key );

	// Return the cached prompt, if we have it. Otherwise fetch it from the API.
	if ( false !== $daily_prompts ) {
		return $daily_prompts;
	}

	$blog_id = \Jetpack_Options::get_option( 'id' );
	$path    = '/sites/' . rawurldecode( $blog_id ) . '/blogging-prompts?from=' . rawurldecode( $day_before ) . '&number=10&_locale=' . rawurldecode( $locale );

	$args = array(
		'headers' => array(
			'Content-Type'    => 'application/json',
			'X-Forwarded-For' => ( new \Automattic\Jetpack\Status\Visitor() )->get_ip( true ),
		),
		// `method` and `url` are needed for using `WPCOM_API_Direct::do_request`
		// `wpcom_json_api_request_as_user` will generate and overwrite these.
		'method'  => \WP_REST_Server::READABLE,
		'url'     => JETPACK__WPCOM_JSON_API_BASE . '/wpcom/v2' . $path,
	);

	if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
		// This will load the library, but it may be too late to automatically load any endpoints using WPCOM_API_Direct::register_endpoints.
		// In that case, call `wpcom_rest_api_v2_load_plugin_files( 'wp-content/rest-api-plugins/endpoints/blogging-prompts.php' )`
		// on the `init` hook to load the blogging-prompts endpoint before calling this function.
		require_once WP_CONTENT_DIR . '/lib/wpcom-api-direct/wpcom-api-direct.php';
		$response = \WPCOM_API_Direct::do_request( $args );
	} else {
		$response = \Automattic\Jetpack\Connection\Client::wpcom_json_api_request_as_user( $path, 'v2', $args, null, 'wpcom' );
	}
	$response_status = wp_remote_retrieve_response_code( $response );

	if ( is_wp_error( $response ) || $response_status !== \WP_Http::OK ) {
		return null;
	}

	$body = json_decode( wp_remote_retrieve_body( $response ) );

	if ( ! $body || ! isset( $body->prompts ) ) {
		return null;
	}

	$prompts = $body->prompts;
	set_transient( $transient_key, $prompts, DAY_IN_SECONDS );

	return $prompts;
}

/**
 * Determines if the site has publish posts or plans to publish posts.
 *
 * @return bool
 */
function jetpack_has_or_will_publish_posts() {
	// Lets count the posts.
	$count_posts_object = wp_count_posts( 'post' );
	$count_posts        = (int) $count_posts_object->publish + (int) $count_posts_object->future + (int) $count_posts_object->draft;

	return $count_posts_object->publish >= 2 || $count_posts >= 100;
}

/**
 * Determines if the site has a posts page or shows posts on the front page.
 *
 * @return bool
 */
function jetpack_has_posts_page() {
	// The site is set up to be a blog.
	if ( 'posts' === get_option( 'show_on_front' ) ) {
		return true;
	}

	// There is a page set to show posts.
	$is_posts_page_set = (int) get_option( 'page_for_posts' ) > 0;
	if ( $is_posts_page_set ) {
		return true;
	}

	return false;
}

/**
 * Determines if site had the "Write" intent set when created.
 *
 * @return bool
 */
function jetpack_has_write_intent() {
	return 'write' === get_option( 'site_intent', '' );
}

/**
 * Determines if the current screen (in wp-admin) is creating a new post.
 *
 * /wp-admin/post-new.php
 *
 * @return bool
 */
function jetpack_is_new_post_screen() {
	global $current_screen;

	if (
		$current_screen instanceof \WP_Screen &&
		'add' === $current_screen->action &&
		'post' === $current_screen->post_type
	) {
		return true;
	}

	return false;
}

/**
 * Determines if the site might have a blog.
 *
 * @return bool
 */
function jetpack_is_potential_blogging_site() {
	return jetpack_has_write_intent() || jetpack_has_posts_page() || jetpack_has_or_will_publish_posts();
}
