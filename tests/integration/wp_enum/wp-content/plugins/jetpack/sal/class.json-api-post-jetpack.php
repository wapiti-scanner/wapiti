<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * This class extends the SAL_Post class, providing the implementation for
 * functions that were declared in that SAL_Post class.
 *
 * @see WPCOM_JSON_API_Post_v1_1_Endpoint in class.wpcom-json-api-post-v1-1-endpoint.php for more context on
 * the functions implemented here.
 *
 * @package automattic/jetpack
 */
/**
 * Base class for Jetpack_Post.
 */
class Jetpack_Post extends SAL_Post {
	/**
	 * Defines a default value for the like counts on a post, if this hasn't been defined yet.
	 *
	 * @return int Returns 0.
	 **/
	public function get_like_count() {
		return 0;
	}

	/**
	 * Defines a default value for whether or not the current user likes this post, if this hasn't been defined yet.
	 *
	 * @return bool Returns false
	 **/
	public function is_liked() {
		return false;
	}

	/**
	 * Defines a default value for whether or not the current user reblogged this post, if this hasn't been defined yet.
	 *
	 * @return bool Returns false
	 **/
	public function is_reblogged() {
		return false;
	}

	/**
	 * Defines a default value for whether or not the current user is following this blog, if this hasn't been defined yet.
	 *
	 * @return bool Returns false
	 **/
	public function is_following() {
		return false;
	}

	/**
	 * Defines the unique WordPress.com-wide representation of a post, if this hasn't been defined yet.
	 *
	 * @return string Returns an empty string
	 **/
	public function get_global_id() {
		return '';
	}

	/**
	 * Defines a default value for whether or not there is gelocation data for this post, if this hasn't been defined yet.
	 *
	 * @return bool Returns false
	 **/
	public function get_geo() {
		return false;
	}

	/**
	 * Returns the avatar URL for a user, or an empty string if there isn't a valid avatar.
	 *
	 * @param string $email The user's email.
	 * @param int    $avatar_size The size of the avatar in pixels.
	 *
	 * @return string
	 */
	protected function get_avatar_url( $email, $avatar_size = 96 ) {
		$avatar_url = get_avatar_url(
			$email,
			array(
				'size' => $avatar_size,
			)
		);

		if ( ! $avatar_url || is_wp_error( $avatar_url ) ) {
			return '';
		}
		return $avatar_url;
	}
}
