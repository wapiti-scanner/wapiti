<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_GET_Post_Counts_V1_1_Endpoint(
	array(
		'description'      => 'Get number of posts in the post type groups by post status',
		'group'            => 'sites',
		'stat'             => 'sites:X:post-counts:X',
		'force'            => 'wpcom',
		'method'           => 'GET',
		'min_version'      => '1.1',
		'max_version'      => '1.2',
		'path'             => '/sites/%s/post-counts/%s',
		'path_labels'      => array(
			'$site'      => '(int|string) Site ID or domain',
			'$post_type' => '(string) Post Type',
		),

		'query_parameters' => array(
			'context' => false,
			'author'  => '(int) author ID',
		),

		'example_request'  => 'https://public-api.wordpress.com/rest/v1.2/sites/en.blog.wordpress.com/post-counts/page',

		'response_format'  => array(
			'counts' => array(
				'all'  => '(array) Number of posts by any author in the post type grouped by post status',
				'mine' => '(array) Number of posts by the current user in the post type grouped by post status',
			),
		),
	)
);

/**
 * GET Post Counts v1_1 endpoint class.
 */
class WPCOM_JSON_API_GET_Post_Counts_V1_1_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * Whitelist array.
	 *
	 * @var allowlist
	 */
	private $allowlist = array( 'publish' );

	/**
	 * Build SQL query
	 *
	 * This function must `$wpdb->prepare` the query. The return is expected to be prepared by consuming functions.
	 *
	 * @param string $post_type - post type.
	 * @param int    $user_id - the user ID.
	 * @return string SQL query
	 */
	private function buildCountsQuery( $post_type = 'post', $user_id = null ) {
		global $wpdb;

		$query  = 'SELECT post_status as status, count(*) as count ';
		$query .= "FROM {$wpdb->posts} ";
		$query .= 'WHERE post_type = %s ';
		if ( isset( $user_id ) ) {
			$query .= 'AND post_author = %d ';
		}

		$query .= 'GROUP BY status';

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- This is properly prepared, except the query is constructed in the variable, throwing the PHPCS error.
		return $wpdb->prepare( $query, $post_type, $user_id );
	}

	/**
	 * Retrive counts using wp_cache
	 *
	 * @param string $post_type - thge post type.
	 * @param int    $id - the ID.
	 */
	private function retrieveCounts( $post_type, $id = null ) {
		if ( ! isset( $id ) ) {
			$counts = array();
			foreach ( (array) wp_count_posts( $post_type ) as $status => $count ) {
				if ( in_array( $status, $this->allowlist, true ) && $count > 0 ) {
					$counts[ $status ] = (int) $count;
				}
			}

			return $counts;
		}

		global $wpdb;
		$key    = 'rest-api-' . $id . '-' . _count_posts_cache_key( $post_type );
		$counts = wp_cache_get( $key, 'counts' );

		if ( false === $counts ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- buildCountsQuery prepares the query.
			$results = $wpdb->get_results( $this->buildCountsQuery( $post_type, $id ) );
			$counts  = $this->filterStatusesByWhiteslist( $results );
			wp_cache_set( $key, $counts, 'counts' );
		}

		return $counts;
	}

	/**
	 * Filter statuses by whiteslist.
	 *
	 * @param array $in - the post we're checking.
	 */
	private function filterStatusesByWhiteslist( $in ) {
		$return = array();
		foreach ( $in as $result ) {
			if ( in_array( $result->status, $this->allowlist, true ) ) {
				$return[ $result->status ] = (int) $result->count;
			}
		}
		return $return;
	}

	/**
	 *
	 * API callback.
	 *
	 * /sites/%s/post-counts/%s
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 * @param string $post_type - the post type.
	 */
	public function callback( $path = '', $blog_id = 0, $post_type = 'post' ) {
		if ( ! get_current_user_id() ) {
			return new WP_Error( 'authorization_required', __( 'An active access token must be used to retrieve post counts.', 'jetpack' ), 403 );
		}

		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ), false );

		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		// @todo see if we can use a strict comparison here.
		// phpcs:ignore WordPress.PHP.StrictInArray.MissingTrueStrict
		if ( ! in_array( $post_type, array( 'post', 'revision', 'page', 'any' ), true ) && defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$this->load_theme_functions();
		}

		if ( ! post_type_exists( $post_type ) ) {
			return new WP_Error( 'unknown_post_type', __( 'Unknown post type requested.', 'jetpack' ), 404 );
		}

		$args    = $this->query_args();
		$mine_ID = get_current_user_id(); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase

		if ( current_user_can( 'edit_posts' ) ) {
			array_push( $this->allowlist, 'draft', 'future', 'pending', 'private', 'trash' );
		}

		$return = array(
			'counts' => (array) array(
				'all'  => (object) $this->retrieveCounts( $post_type ),
				'mine' => (object) $this->retrieveCounts( $post_type, $mine_ID ), // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
			),
		);

		// Author.
		if ( isset( $args['author'] ) ) {
			$author_ID                  = $args['author']; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
			$return['counts']['author'] = (object) $this->retrieveCounts( $post_type, $author_ID ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.VariableNotSnakeCase
		}

		return (object) $return;
	}
}
