<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Endpoint: /sites/%s/comment-counts
 */

new WPCOM_JSON_API_GET_Comment_Counts_Endpoint(
	array(
		'description'      => 'Get comment counts for each available status',
		'group'            => 'comments',
		'stat'             => 'comments:1:comment-counts',
		'method'           => 'GET',
		'path'             => '/sites/%s/comment-counts',
		'path_labels'      => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'query_parameters' => array(
			'post_id' => '(int) post ID for filtering the comment counts by post',
		),

		'example_request'  => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/comment-counts',

		'response_format'  => array(
			'all'            => '(int) Combined number of approved and unapproved comments',
			'approved'       => '(int) Number of approved comments',
			'pending'        => '(int) Number of unapproved comments',
			'trash'          => '(int) Number of trash comments',
			'spam'           => '(int) Number of spam comments',
			'post_trashed'   => '(int) Number of comments whose parent post has been trashed',
			'total_comments' => '(int) Combined number of comments in each category',
		),
	)
);

/**
 * GET Comment Counts endpoint class.
 */
class WPCOM_JSON_API_GET_Comment_Counts_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 *
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );

		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( ! get_current_user_id() ) {
			return new WP_Error( 'authorization_required', 'An active access token must be used to retrieve comment counts.', 403 );
		}

		if ( ! current_user_can_for_blog( $blog_id, 'edit_posts' ) ) {
			return new WP_Error( 'authorization_required', 'You are not authorized to view comment counts for this blog.', 403 );
		}

		$args = $this->query_args();

		// If 0 is passed wp_count_comments will default to fetching counts for the whole site.
		$post_id = ! empty( $args['post_id'] ) ? (int) $args['post_id'] : 0;

		// Check if post with given id exists.
		if ( ! empty( $post_id ) && ! is_object( get_post( $post_id ) ) ) {
			return new WP_Error( 'invalid_input', 'Provided post_id does not exist', 400 );
		}

		$comment_counts = get_object_vars( $this->api->wp_count_comments( $post_id ) );

		// Keys coming from wp_count_comments don't match the ones that we use in
		// wp-admin and Calypso and are not consistent. Let's normalize the response.
		return array(
			'all'            => (int) $comment_counts['all'],
			'approved'       => (int) $comment_counts['approved'],
			'pending'        => (int) $comment_counts['moderated'],
			'trash'          => (int) $comment_counts['trash'],
			'spam'           => (int) $comment_counts['spam'],
			'post_trashed'   => (int) $comment_counts['post-trashed'],
			'total_comments' => (int) $comment_counts['total_comments'],
		);
	}
}
