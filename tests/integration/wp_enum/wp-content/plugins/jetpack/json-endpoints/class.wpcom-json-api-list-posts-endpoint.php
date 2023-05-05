<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * List posts endpoint.
 */
new WPCOM_JSON_API_List_Posts_Endpoint(
	array(
		'description'                          => 'Get a list of matching posts.',
		'new_version'                          => '1.1',
		'max_version'                          => '1',
		'group'                                => 'posts',
		'stat'                                 => 'posts',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/posts/',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'query_parameters'                     => array(
			'number'       => '(int=20) The number of posts to return. Limit: 100.',
			'offset'       => '(int=0) 0-indexed offset.',
			'page'         => '(int) Return the Nth 1-indexed page of posts. Takes precedence over the <code>offset</code> parameter.',
			'order'        => array(
				'DESC' => 'Return posts in descending order. For dates, that means newest to oldest.',
				'ASC'  => 'Return posts in ascending order. For dates, that means oldest to newest.',
			),
			'order_by'     => array(
				'date'          => 'Order by the created time of each post.',
				'modified'      => 'Order by the modified time of each post.',
				'title'         => "Order lexicographically by the posts' titles.",
				'comment_count' => 'Order by the number of comments for each post.',
				'ID'            => 'Order by post ID.',
			),
			'after'        => '(ISO 8601 datetime) Return posts dated on or after the specified datetime.',
			'before'       => '(ISO 8601 datetime) Return posts dated on or before the specified datetime.',
			'tag'          => '(string) Specify the tag name or slug.',
			'category'     => '(string) Specify the category name or slug.',
			'term'         => '(object:string) Specify comma-separated term slugs to search within, indexed by taxonomy slug.',
			'type'         => "(string) Specify the post type. Defaults to 'post', use 'any' to query for both posts and pages. Post types besides post and page need to be whitelisted using the <code>rest_api_allowed_post_types</code> filter.",
			'parent_id'    => '(int) Returns only posts which are children of the specified post. Applies only to hierarchical post types.',
			'include'      => '(array:int|int) Includes the specified post ID(s) in the response',
			'exclude'      => '(array:int|int) Excludes the specified post ID(s) from the response',
			'exclude_tree' => '(int) Excludes the specified post and all of its descendants from the response. Applies only to hierarchical post types.',
			'status'       => array(
				'publish' => 'Return only published posts.',
				'private' => 'Return only private posts.',
				'draft'   => 'Return only draft posts.',
				'pending' => 'Return only posts pending editorial approval.',
				'future'  => 'Return only posts scheduled for future publishing.',
				'trash'   => 'Return only posts in the trash.',
				'any'     => 'Return all posts regardless of status.',
			),
			'sticky'       => array(
				'false' => 'Post is not marked as sticky.',
				'true'  => 'Stick the post to the front page.',
			),
			'author'       => "(int) Author's user ID",
			'search'       => '(string) Search query',
			'meta_key'     => '(string) Metadata key that the post should contain',
			'meta_value'   => '(string) Metadata value that the post should contain. Will only be applied if a `meta_key` is also given',
		),

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/posts/?number=5',
	)
);

/**
 * List posts endpoint class.
 *
 * /sites/%s/posts/ -> $blog_id
 */
class WPCOM_JSON_API_List_Posts_Endpoint extends WPCOM_JSON_API_Post_Endpoint {

	/**
	 * The date range.
	 *
	 * @var array.
	 */
	public $date_range = array();

	/**
	 * The response format.
	 *
	 * @var array
	 */
	public $response_format = array(
		'found' => '(int) The total number of posts found that match the request (ignoring limits, offsets, and pagination).',
		'posts' => '(array:post) An array of post objects.',
	);

	/**
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param string $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$args = $this->query_args();

		if ( $args['number'] < 1 ) {
			$args['number'] = 20;
		} elseif ( 100 < $args['number'] ) {
			return new WP_Error( 'invalid_number', 'The NUMBER parameter must be less than or equal to 100.', 400 );
		}

		if ( isset( $args['type'] ) && ! $this->is_post_type_allowed( $args['type'] ) ) {
			return new WP_Error( 'unknown_post_type', 'Unknown post type', 404 );
		}

		// Normalize post_type.
		if ( isset( $args['type'] ) && 'any' === $args['type'] ) {
			if ( version_compare( $this->api->version, '1.1', '<' ) ) {
				$args['type'] = array( 'post', 'page' );
			} else { // 1.1+
				$args['type'] = $this->_get_whitelisted_post_types();
			}
		}

		// determine statuses.
		$status = $args['status'];
		$status = ( $status ) ? explode( ',', $status ) : array( 'publish' );
		if ( is_user_logged_in() ) {
			$statuses_whitelist = array(
				'publish',
				'pending',
				'draft',
				'future',
				'private',
				'trash',
				'any',
			);
			$status             = array_intersect( $status, $statuses_whitelist );
		} else {
			// logged-out users can see only published posts.
			$statuses_whitelist = array( 'publish', 'any' );
			$status             = array_intersect( $status, $statuses_whitelist );

			if ( empty( $status ) ) {
				// requested only protected statuses? nothing for you here.
				return array(
					'found' => 0,
					'posts' => array(),
				);
			}
			// clear it (AKA published only) because "any" includes protected.
			$status = array();
		}

		// let's be explicit about defaulting to 'post'.
		$args['type'] = isset( $args['type'] ) ? $args['type'] : 'post';

		// make sure the user can read or edit the requested post type(s).
		if ( is_array( $args['type'] ) ) {
			$allowed_types = array();
			foreach ( $args['type'] as $post_type ) {
				if ( $this->current_user_can_access_post_type( $post_type, $args['context'] ) ) {
					$allowed_types[] = $post_type;
				}
			}

			if ( empty( $allowed_types ) ) {
				return array(
					'found' => 0,
					'posts' => array(),
				);
			}
			$args['type'] = $allowed_types;
		} elseif ( ! $this->current_user_can_access_post_type( $args['type'], $args['context'] ) ) {
			return array(
				'found' => 0,
				'posts' => array(),
			);
		}

		$query = array(
			'posts_per_page' => $args['number'],
			'order'          => $args['order'],
			'orderby'        => $args['order_by'],
			'post_type'      => $args['type'],
			'post_status'    => $status,
			'post_parent'    => isset( $args['parent_id'] ) ? $args['parent_id'] : null,
			'author'         => isset( $args['author'] ) && 0 < $args['author'] ? $args['author'] : null,
			's'              => isset( $args['search'] ) && '' !== $args['search'] ? $args['search'] : null,
			'fields'         => 'ids',
		);

		if ( ! is_user_logged_in() ) {
			$query['has_password'] = false;
		}

		if ( isset( $args['include'] ) ) {
			$query['post__in'] = is_array( $args['include'] ) ? $args['include'] : array( (int) $args['include'] );
		}

		if ( isset( $args['meta_key'] ) ) {
			$show = false;
			if ( WPCOM_JSON_API_Metadata::is_public( $args['meta_key'] ) ) {
				$show = true;
			}
			if ( current_user_can( 'edit_post_meta', $query['post_type'], $args['meta_key'] ) ) {
				$show = true;
			}

			if ( is_protected_meta( $args['meta_key'], 'post' ) && ! $show ) {
				return new WP_Error( 'invalid_meta_key', 'Invalid meta key', 404 );
			}

			$meta = array( 'key' => $args['meta_key'] );
			if ( isset( $args['meta_value'] ) ) {
				$meta['value'] = $args['meta_value'];
			}

			$query['meta_query'] = array( $meta );
		}

		$sticky = get_option( 'sticky_posts' );
		if (
			isset( $args['sticky'] )
		&&
			$sticky
		&&
			is_array( $sticky )
		) {
			if ( $args['sticky'] ) {
				$query['post__in'] = isset( $args['include'] ) ? array_merge( $query['post__in'], $sticky ) : $sticky;
			} else {
				$query['post__not_in']        = $sticky;
				$query['ignore_sticky_posts'] = 1;
			}
		} else {
				$query['post__not_in']        = $sticky;
				$query['ignore_sticky_posts'] = 1;
		}

		if ( isset( $args['exclude'] ) ) {
			$query['post__not_in'] = array_merge( $query['post__not_in'], (array) $args['exclude'] );
		}

		if ( isset( $args['exclude_tree'] ) && is_post_type_hierarchical( $args['type'] ) ) {
			// get_page_children is a misnomer; it supports all hierarchical post types.
			$page_args        = array(
				'child_of'    => $args['exclude_tree'],
				'post_type'   => $args['type'],
				// since we're looking for things to exclude, be aggressive.
				'post_status' => 'publish,draft,pending,private,future,trash',
			);
			$post_descendants = get_pages( $page_args );

			$exclude_tree = array( $args['exclude_tree'] );
			foreach ( $post_descendants as $child ) {
				$exclude_tree[] = $child->ID;
			}

			$query['post__not_in'] = isset( $query['post__not_in'] ) ? array_merge( $query['post__not_in'], $exclude_tree ) : $exclude_tree;
		}

		if ( isset( $args['category'] ) ) {
			$category = get_term_by( 'slug', $args['category'], 'category' );
			if ( false === $category ) {
				$query['category_name'] = $args['category'];
			} else {
				$query['cat'] = $category->term_id;
			}
		}

		if ( isset( $args['tag'] ) ) {
			$query['tag'] = $args['tag'];
		}

		if ( ! empty( $args['term'] ) ) {
			$query['tax_query'] = array();
			foreach ( $args['term'] as $taxonomy => $slug ) {
				$taxonomy_object = get_taxonomy( $taxonomy );
				if ( false === $taxonomy_object || ( ! $taxonomy_object->public &&
						! current_user_can( $taxonomy_object->cap->assign_terms ) ) ) {
					continue;
				}

				$query['tax_query'][] = array(
					'taxonomy' => $taxonomy,
					'field'    => 'slug',
					'terms'    => explode( ',', $slug ),
				);
			}
		}

		if ( isset( $args['page'] ) ) {
			if ( $args['page'] < 1 ) {
				$args['page'] = 1;
			}

			$query['paged'] = $args['page'];
		} else {
			if ( $args['offset'] < 0 ) {
				$args['offset'] = 0;
			}

			$query['offset'] = $args['offset'];
		}

		if ( isset( $args['before'] ) ) {
			$this->date_range['before'] = $args['before'];
		}
		if ( isset( $args['after'] ) ) {
			$this->date_range['after'] = $args['after'];
		}

		if ( $this->date_range ) {
			add_filter( 'posts_where', array( $this, 'handle_date_range' ) );
		}

		/**
		 * 'column' necessary for the me/posts endpoint (which extends sites/$site/posts).
		 * Would need to be added to the sites/$site/posts definition if we ever want to
		 * use it there.
		 */
		$column_whitelist = array( 'post_modified_gmt' );
		if ( isset( $args['column'] ) && in_array( $args['column'], $column_whitelist, true ) ) {
			$query['column'] = $args['column'];
		}

		$wp_query = new WP_Query( $query );
		if ( $this->date_range ) {
			remove_filter( 'posts_where', array( $this, 'handle_date_range' ) );
			$this->date_range = array();
		}

		$return         = array();
		$excluded_count = 0;
		foreach ( array_keys( $this->response_format ) as $key ) {
			switch ( $key ) {
				case 'found':
					$return[ $key ] = (int) $wp_query->found_posts;
					break;
				case 'posts':
					$posts = array();
					foreach ( $wp_query->posts as $post_ID ) {
						$the_post = $this->get_post_by( 'ID', $post_ID, $args['context'] );
						if ( $the_post && ! is_wp_error( $the_post ) ) {
							$posts[] = $the_post;
						} else {
							++$excluded_count;
						}
					}

					if ( $posts ) {
						/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
						do_action( 'wpcom_json_api_objects', 'posts', count( $posts ) );
					}

					$return[ $key ] = $posts;
					break;
			}
		}

		$return['found'] -= $excluded_count;

		return $return;
	}

	/**
	 * Handle the date range.
	 *
	 * @param string $where - SQL where clause.
	 */
	public function handle_date_range( $where ) {
		global $wpdb;

		switch ( count( $this->date_range ) ) {
			case 2:
				$where .= $wpdb->prepare(
					" AND `$wpdb->posts`.post_date BETWEEN CAST( %s AS DATETIME ) AND CAST( %s AS DATETIME ) ",
					$this->date_range['after'],
					$this->date_range['before']
				);
				break;
			case 1:
				if ( isset( $this->date_range['before'] ) ) {
					$where .= $wpdb->prepare(
						" AND `$wpdb->posts`.post_date <= CAST( %s AS DATETIME ) ",
						$this->date_range['before']
					);
				} else {
					$where .= $wpdb->prepare(
						" AND `$wpdb->posts`.post_date >= CAST( %s AS DATETIME ) ",
						$this->date_range['after']
					);
				}
				break;
		}

		return $where;
	}
}
