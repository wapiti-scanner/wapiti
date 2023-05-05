<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Update post endpoint v1.2
 *
 * Endpoints:
 * Create a post:  /sites/%s/posts/new
 * Update a post:  /sites/%s/posts/%d
 * Delete a post:  /sites/%s/posts/%d/delete
 * Restore a post: /sites/%s/posts/%d/restore
 */

new WPCOM_JSON_API_Update_Post_v1_2_Endpoint(
	array(
		'description'          => 'Create a post.',
		'group'                => 'posts',
		'stat'                 => 'posts:new',
		'min_version'          => '1.2',
		'max_version'          => '1.2',
		'method'               => 'POST',
		'path'                 => '/sites/%s/posts/new',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters'     => array(
			'autosave' => '(bool) True if the post was saved automatically.',
		),

		'request_format'       => array(
			// explicitly document all input.
			'date'              => "(ISO 8601 datetime) The post's creation time.",
			'title'             => '(HTML) The post title.',
			'content'           => '(HTML) The post content.',
			'excerpt'           => '(HTML) An optional post excerpt.',
			'slug'              => '(string) The name (slug) for the post, used in URLs.',
			'author'            => '(string) The username or ID for the user to assign the post to.',
			'publicize'         => '(array|bool) True or false if the post be shared to external services. An array of services if we only want to share to a select few. Defaults to true.',
			'publicize_message' => '(string) Custom message to be shared to external services.',
			'status'            => array(
				'publish'    => 'Publish the post.',
				'private'    => 'Privately publish the post.',
				'draft'      => 'Save the post as a draft.',
				'pending'    => 'Mark the post as pending editorial approval.',
				'future'     => 'Schedule the post (alias for publish; you must also set a future date).',
				'auto-draft' => 'Save a placeholder for a newly created post, with no content.',
			),
			'sticky'            => array(
				'false' => 'Post is not marked as sticky.',
				'true'  => 'Stick the post to the front page.',
			),
			'password'          => '(string) The plaintext password protecting the post, or, more likely, the empty string if the post is not password protected.',
			'parent'            => "(int) The post ID of the new post's parent.",
			'type'              => "(string) The post type. Defaults to 'post'. Post types besides post and page need to be whitelisted using the <code>rest_api_allowed_post_types</code> filter.",
			'terms'             => '(object) Mapping of taxonomy to comma-separated list or array of term names',
			'categories'        => '(array|string) Comma-separated list or array of category names',
			'tags'              => '(array|string) Comma-separated list or array of tag names',
			'terms_by_id'       => '(object) Mapping of taxonomy to comma-separated list or array of term IDs',
			'categories_by_id'  => '(array|string) Comma-separated list or array of category IDs',
			'tags_by_id'        => '(array|string) Comma-separated list or array of tag IDs',
			'format'            => array_merge( array( 'default' => 'Use default post format' ), get_post_format_strings() ),
			'featured_image'    => '(string) The post ID of an existing attachment to set as the featured image. Pass an empty string to delete the existing image.',
			'media'             => '(media) An array of files to attach to the post. To upload media, the entire request should be multipart/form-data encoded. Multiple media items will be displayed in a gallery. Accepts  jpg, jpeg, png, gif, pdf, doc, ppt, odt, pptx, docx, pps, ppsx, xls, xlsx, key. Audio and Video may also be available. See <code>allowed_file_types</code> in the options response of the site endpoint. Errors produced by media uploads, if any, will be in `media_errors` in the response. <br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'title=Image Post' \<br />--form 'media[0]=@/path/to/file.jpg' \<br />--form 'media_attrs[0][caption]=My Great Photo' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/posts/new'</code>",
			'media_urls'        => '(array) An array of URLs for images to attach to a post. Sideloads the media in for a post. Errors produced by media sideloading, if any, will be in `media_errors` in the response.',
			'media_attrs'       => '(array) An array of attributes (`title`, `description` and `caption`) are supported to assign to the media uploaded via the `media` or `media_urls` properties. You must use a numeric index for the keys of `media_attrs` which follow the same sequence as `media` and `media_urls`. <br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'title=Gallery Post' \<br />--form 'media[]=@/path/to/file1.jpg' \<br />--form 'media_urls[]=http://exapmple.com/file2.jpg' \<br /> \<br />--form 'media_attrs[0][caption]=This will be the caption for file1.jpg' \<br />--form 'media_attrs[1][title]=This will be the title for file2.jpg' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/posts/new'</code>",
			'metadata'          => '(array) Array of metadata objects containing the following properties: `key` (metadata key), `id` (meta ID), `previous_value` (if set, the action will only occur for the provided previous value), `value` (the new value to set the meta to), `operation` (the operation to perform: `update` or `add`; defaults to `update`). All unprotected meta keys are available by default for read requests. Both unprotected and protected meta keys are avaiable for authenticated requests with proper capabilities. Protected meta keys can be made available with the <code>rest_api_allowed_public_metadata</code> filter.',
			'discussion'        => '(object) A hash containing one or more of the following boolean values, which default to the blog\'s discussion preferences: `comments_open`, `pings_open`',
			'likes_enabled'     => "(bool) Should the post be open to likes? Defaults to the blog's preference.",
			'sharing_enabled'   => '(bool) Should sharing buttons show on this post? Defaults to true.',
			'menu_order'        => '(int) (Pages Only) the order pages should appear in. Use 0 to maintain alphabetical order.',
			'page_template'     => '(string) (Pages Only) The page template this page should use.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.2/sites/82974409/posts/new/',

		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),

			'body'    => array(
				'title'      => 'Hello World',
				'content'    => 'Hello. I am a test post. I was created by the API',
				'tags'       => 'tests',
				'categories' => 'API',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Post_v1_2_Endpoint(
	array(
		'description'          => 'Edit a post.',
		'group'                => 'posts',
		'stat'                 => 'posts:1:POST',
		'min_version'          => '1.2',
		'max_version'          => '1.2',
		'method'               => 'POST',
		'path'                 => '/sites/%s/posts/%d',
		'path_labels'          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$post_ID' => '(int) The post ID',
		),
		'query_parameters'     => array(
			'autosave' => '(bool) True if the post was saved automatically.',
		),

		'request_format'       => array(
			'date'              => "(ISO 8601 datetime) The post's creation time.",
			'title'             => '(HTML) The post title.',
			'content'           => '(HTML) The post content.',
			'excerpt'           => '(HTML) An optional post excerpt.',
			'slug'              => '(string) The name (slug) for the post, used in URLs.',
			'author'            => '(string) The username or ID for the user to assign the post to.',
			'publicize'         => '(array|bool) True or false if the post be shared to external services. An array of services if we only want to share to a select few. Defaults to true.',
			'publicize_message' => '(string) Custom message to be shared to external services.',
			'status'            => array(
				'publish' => 'Publish the post.',
				'private' => 'Privately publish the post.',
				'draft'   => 'Save the post as a draft.',
				'future'  => 'Schedule the post (alias for publish; you must also set a future date).',
				'pending' => 'Mark the post as pending editorial approval.',
				'trash'   => 'Set the post as trashed.',
			),
			'sticky'            => array(
				'false' => 'Post is not marked as sticky.',
				'true'  => 'Stick the post to the front page.',
			),
			'password'          => '(string) The plaintext password protecting the post, or, more likely, the empty string if the post is not password protected.',
			'parent'            => "(int) The post ID of the new post's parent.",
			'terms'             => '(object) Mapping of taxonomy to comma-separated list or array of term names',
			'terms_by_id'       => '(object) Mapping of taxonomy to comma-separated list or array of term IDs',
			'categories'        => '(array|string) Comma-separated list or array of category names',
			'categories_by_id'  => '(array|string) Comma-separated list or array of category IDs',
			'tags'              => '(array|string) Comma-separated list or array of tag names',
			'tags_by_id'        => '(array|string) Comma-separated list or array of tag IDs',
			'format'            => array_merge( array( 'default' => 'Use default post format' ), get_post_format_strings() ),
			'discussion'        => '(object) A hash containing one or more of the following boolean values, which default to the blog\'s discussion preferences: `comments_open`, `pings_open`',
			'likes_enabled'     => '(bool) Should the post be open to likes?',
			'menu_order'        => '(int) (Pages only) the order pages should appear in. Use 0 to maintain alphabetical order.',
			'page_template'     => '(string) (Pages Only) The page template this page should use.',
			'sharing_enabled'   => '(bool) Should sharing buttons show on this post?',
			'featured_image'    => '(string) The post ID of an existing attachment to set as the featured image. Pass an empty string to delete the existing image.',
			'media'             => '(media) An array of files to attach to the post. To upload media, the entire request should be multipart/form-data encoded. Multiple media items will be displayed in a gallery. Accepts  jpg, jpeg, png, gif, pdf, doc, ppt, odt, pptx, docx, pps, ppsx, xls, xlsx, key. Audio and Video may also be available. See <code>allowed_file_types</code> in the options resposne of the site endpoint. <br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'title=Image' \<br />--form 'media[]=@/path/to/file.jpg' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/posts/new'</code>",
			'media_urls'        => '(array) An array of URLs for images to attach to a post. Sideloads the media in for a post.',
			'metadata'          => '(array) Array of metadata objects containing the following properties: `key` (metadata key), `id` (meta ID), `previous_value` (if set, the action will only occur for the provided previous value), `value` (the new value to set the meta to), `operation` (the operation to perform: `update` or `add`; defaults to `update`). All unprotected meta keys are available by default for read requests. Both unprotected and protected meta keys are available for authenticated requests with proper capabilities. Protected meta keys can be made available with the <code>rest_api_allowed_public_metadata</code> filter.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1.2/sites/82974409/posts/881',

		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),

			'body'    => array(
				'title'      => 'Hello World (Again)',
				'content'    => 'Hello. I am an edited post. I was edited by the API',
				'tags'       => 'tests',
				'categories' => 'API',
			),
		),
	)
);

use function \Automattic\Jetpack\Extensions\Map\map_block_from_geo_points;

// phpcs:disable PEAR.NamingConventions.ValidClassName.Invalid
/**
 * Update post v1.2 endpoint class.
 */
class WPCOM_JSON_API_Update_Post_v1_2_Endpoint extends WPCOM_JSON_API_Update_Post_v1_1_Endpoint {
	/**
	 * Create or update a post.
	 *
	 * /sites/%s/posts/new -> $blog_id
	 * /sites/%s/posts/%d  -> $blog_id, $post_id
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 * @param int    $post_id Post ID.
	 */
	public function write_post( $path, $blog_id, $post_id ) {
		global $wpdb;

		$new  = $this->api->ends_with( $path, '/new' );
		$args = $this->query_args();

		if ( ! empty( $args['autosave'] ) ) {
			define( 'DOING_AUTOSAVE', true );
		}

		// unhook publicize, it's hooked again later -- without this, skipping services is impossible.
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			remove_action( 'save_post', array( $GLOBALS['publicize_ui']->publicize, 'async_publicize_post' ), 100, 2 );
			add_action( 'rest_api_inserted_post', array( $GLOBALS['publicize_ui']->publicize, 'async_publicize_post' ) );

			if ( $this->should_load_theme_functions( $post_id ) ) {
				$this->load_theme_functions();
			}
		}

		if ( $new ) {
			$input = $this->input( true );

			// 'future' is an alias for 'publish' for now
			if ( isset( $input['status'] ) && 'future' === $input['status'] ) {
				$input['status'] = 'publish';
			}

			// default to post.
			if ( empty( $input['type'] ) ) {
				$input['type'] = 'post';
			}

			if ( 'revision' === $input['type'] ) {
				if ( ! isset( $input['parent'] ) ) {
					return new WP_Error( 'invalid_input', 'Invalid request input', 400 );
				}
				$input['status'] = 'inherit'; // force inherit for revision type.
				$input['slug']   = $input['parent'] . '-autosave-v1';
			} elseif ( ! isset( $input['title'] ) && ! isset( $input['content'] ) && ! isset( $input['excerpt'] ) ) {
				return new WP_Error( 'invalid_input', 'Invalid request input', 400 );
			}

			$post_type = get_post_type_object( $input['type'] );

			if ( ! $this->is_post_type_allowed( $input['type'] ) ) {
				return new WP_Error( 'unknown_post_type', 'Unknown post type', 404 );
			}

			if ( ! empty( $input['author'] ) ) {
				$author_id = parent::parse_and_set_author( $input['author'], $input['type'] );
				unset( $input['author'] );
				if ( is_wp_error( $author_id ) ) {
					return $author_id;
				}
			}

			if ( 'publish' === $input['status'] ) {
				if ( ! current_user_can( $post_type->cap->publish_posts ) ) {
					if ( current_user_can( $post_type->cap->edit_posts ) ) {
						$input['status'] = 'pending';
					} else {
						return new WP_Error( 'unauthorized', 'User cannot publish posts', 403 );
					}
				}
			} elseif ( ! current_user_can( $post_type->cap->edit_posts ) ) {
				return new WP_Error( 'unauthorized', 'User cannot edit posts', 403 );
			}
		} else {
			$input = $this->input( false );

			if ( ! is_array( $input ) || ! $input ) {
				return new WP_Error( 'invalid_input', 'Invalid request input', 400 );
			}

			if ( isset( $input['status'] ) && 'trash' === $input['status'] && ! current_user_can( 'delete_post', $post_id ) ) {
				return new WP_Error( 'unauthorized', 'User cannot delete post', 403 );
			}

			// 'future' is an alias for 'publish' for now
			if ( isset( $input['status'] ) && 'future' === $input['status'] ) {
				$input['status'] = 'publish';
			}

			$post = get_post( $post_id );
			if ( ! $post || is_wp_error( $post ) ) {
				return new WP_Error( 'unknown_post', 'Unknown post', 404 );
			}

			$_post_type = ( ! empty( $input['type'] ) ) ? $input['type'] : $post->post_type;
			$post_type  = get_post_type_object( $_post_type );

			if ( ! current_user_can( 'edit_post', $post->ID ) ) {
				return new WP_Error( 'unauthorized', 'User cannot edit post', 403 );
			}

			if ( ! empty( $input['author'] ) ) {
				$author_id = parent::parse_and_set_author( $input['author'], $_post_type );
				unset( $input['author'] );
				if ( is_wp_error( $author_id ) ) {
					return $author_id;
				}
			}

			if ( ( isset( $input['status'] ) && 'publish' === $input['status'] ) && 'publish' !== $post->post_status && ! current_user_can( 'publish_post', $post->ID ) ) {
				$input['status'] = 'pending';
			}
			$last_status = $post->post_status;
			$new_status  = isset( $input['status'] ) ? $input['status'] : $last_status;

			// Make sure that drafts get the current date when transitioning to publish if not supplied in the post.
			// Similarly, scheduled posts that are manually published before their scheduled date should have the date reset.
			$date_in_past         = ( strtotime( $post->post_date_gmt ) < time() );
			$reset_draft_date     = 'publish' === $new_status && 'draft' === $last_status && ! isset( $input['date_gmt'] ) && $date_in_past;
			$reset_scheduled_date = 'publish' === $new_status && 'future' === $last_status && ! isset( $input['date_gmt'] ) && ! $date_in_past;

			if ( $reset_draft_date || $reset_scheduled_date ) {
				$input['date_gmt'] = gmdate( 'Y-m-d H:i:s' );
			}

			// Untrash a post so that the proper hooks get called as well as the comments get untrashed.
			if ( $this->should_untrash_post( $last_status, $new_status, $post ) ) {
				$input = $this->untrash_post( $post, $input );
			}
		}

		if ( function_exists( 'wpcom_switch_to_blog_locale' ) ) {
			// fixes calypso-pre-oss #12476: respect blog locale when creating the post slug.
			wpcom_switch_to_blog_locale( $blog_id );
		}

		// If date is set, $this->input will set date_gmt, date still needs to be adjusted.
		if ( isset( $input['date_gmt'] ) ) {
			$gmt_offset       = get_option( 'gmt_offset' );
			$time_with_offset = strtotime( $input['date_gmt'] ) + $gmt_offset * HOUR_IN_SECONDS;
			$input['date']    = gmdate( 'Y-m-d H:i:s', $time_with_offset );
		}

		if ( ! empty( $author_id ) && get_current_user_id() !== $author_id ) {
			if ( ! current_user_can( $post_type->cap->edit_others_posts ) ) {
				return new WP_Error( 'unauthorized', "User is not allowed to publish others' posts.", 403 );
			} elseif ( ! user_can( $author_id, $post_type->cap->edit_posts ) ) {
				return new WP_Error( 'unauthorized', 'Assigned author cannot publish post.', 403 );
			}
		}

		if ( ! is_post_type_hierarchical( $post_type->name ) && 'revision' !== $post_type->name ) {
			unset( $input['parent'] );
		}

		foreach ( array( '', '_by_id' ) as $term_key_suffix ) {
			$term_input_key = 'terms' . $term_key_suffix;
			if ( isset( $input[ $term_input_key ] ) ) {
				$input[ $term_input_key ] = (array) $input[ $term_input_key ];
			} else {
				$input[ $term_input_key ] = array();
			}

			// Convert comma-separated terms to array before attempting to
			// merge with hardcoded taxonomies.
			foreach ( $input[ $term_input_key ] as $taxonomy => $terms ) {
				if ( is_string( $terms ) ) {
					$input[ $term_input_key ][ $taxonomy ] = explode( ',', $terms );
				} elseif ( ! is_array( $terms ) ) {
					$input[ $term_input_key ][ $taxonomy ] = array();
				}
			}

			// For each hard-coded taxonomy, merge into terms object.
			foreach ( array(
				'categories' => 'category',
				'tags'       => 'post_tag',
			) as $key_prefix => $taxonomy ) {
				$taxonomy_key = $key_prefix . $term_key_suffix;
				if ( ! isset( $input[ $taxonomy_key ] ) ) {
					continue;
				}

				if ( ! isset( $input[ $term_input_key ][ $taxonomy ] ) ) {
					$input[ $term_input_key ][ $taxonomy ] = array();
				}

				$terms = $input[ $taxonomy_key ];
				if ( is_string( $terms ) ) {
					$terms = explode( ',', $terms );
				} elseif ( ! is_array( $terms ) ) {
					continue;
				}

				$input[ $term_input_key ][ $taxonomy ] = array_merge(
					$input[ $term_input_key ][ $taxonomy ],
					$terms
				);
			}
		}

		/* add terms by name */
		$tax_input = array();
		foreach ( $input['terms'] as $taxonomy => $terms ) {
			$tax_input[ $taxonomy ] = array();
			$is_hierarchical        = is_taxonomy_hierarchical( $taxonomy );

			foreach ( $terms as $term ) {
				/**
				 * We assume these are names, not IDs, even if they are numeric.
				 * Note: A category named "0" will not work right.
				 * https://core.trac.wordpress.org/ticket/9059
				 */
				if ( ! is_string( $term ) ) {
					continue;
				}

				$term_info = get_term_by( 'name', $term, $taxonomy, ARRAY_A );

				if ( ! $term_info ) {
					// only add a new tag/cat if the user has access to.
					$tax = get_taxonomy( $taxonomy );

					// see https://core.trac.wordpress.org/ticket/26409 .
					if ( $is_hierarchical && ! current_user_can( $tax->cap->edit_terms ) ) {
						continue;
					} elseif ( ! current_user_can( $tax->cap->assign_terms ) ) {
						continue;
					}

					$term_info = wp_insert_term( $term, $taxonomy );
				}

				if ( ! is_wp_error( $term_info ) ) {
					if ( $is_hierarchical ) {
						// Hierarchical terms must be added by ID.
						$tax_input[ $taxonomy ][] = (int) $term_info['term_id'];
					} else {
						// Non-hierarchical terms must be added by name.
						$tax_input[ $taxonomy ][] = $term;
					}
				}
			}
		}

		/* add terms by ID */
		foreach ( $input['terms_by_id'] as $taxonomy => $terms ) {
			// combine with any previous selections.
			if ( ! isset( $tax_input[ $taxonomy ] ) || ! is_array( $tax_input[ $taxonomy ] ) ) {
				$tax_input[ $taxonomy ] = array();
			}

			$is_hierarchical = is_taxonomy_hierarchical( $taxonomy );

			foreach ( $terms as $term ) {
				$term = (string) $term; // ctype_digit compat.
				if ( ! ctype_digit( $term ) ) {
					// skip anything that doesn't look like an ID.
					continue;
				}
				$term      = (int) $term;
				$term_info = get_term_by( 'id', $term, $taxonomy, ARRAY_A );

				if ( $term_info && ! is_wp_error( $term_info ) ) {
					if ( $is_hierarchical ) {
						// Categories must be added by ID.
						$tax_input[ $taxonomy ][] = $term;
					} else {
						// Tags must be added by name.
						$tax_input[ $taxonomy ][] = $term_info['name'];
					}
				}
			}
		}

		if ( ( isset( $input['terms']['category'] ) || isset( $input['terms_by_id']['category'] ) )
				&& empty( $tax_input['category'] ) && 'revision' !== $post_type->name ) {
			$tax_input['category'][] = get_option( 'default_category' );
		}

		unset( $input['terms'], $input['tags'], $input['categories'], $input['terms_by_id'], $input['tags_by_id'], $input['categories_by_id'] );

		$insert = array();

		if ( ! empty( $input['slug'] ) ) {
			$insert['post_name'] = $input['slug'];
			unset( $input['slug'] );
		}

		if ( isset( $input['discussion'] ) ) {
			$discussion = (array) $input['discussion'];
			foreach ( array( 'comment', 'ping' ) as $discussion_type ) {
				$discussion_open   = sprintf( '%ss_open', $discussion_type );
				$discussion_status = sprintf( '%s_status', $discussion_type );

				if ( isset( $discussion[ $discussion_open ] ) ) {
					$is_open                          = WPCOM_JSON_API::is_truthy( $discussion[ $discussion_open ] );
					$discussion[ $discussion_status ] = $is_open ? 'open' : 'closed';
				}

				if ( in_array( $discussion[ $discussion_status ], array( 'open', 'closed' ), true ) ) {
					$insert[ $discussion_status ] = $discussion[ $discussion_status ];
				}
			}
		}

		unset( $input['discussion'] );

		if ( isset( $input['menu_order'] ) ) {
			$insert['menu_order'] = $input['menu_order'];
			unset( $input['menu_order'] );
		}

		$publicize = isset( $input['publicize'] ) ? $input['publicize'] : null;
		unset( $input['publicize'] );

		$publicize_custom_message = isset( $input['publicize_message'] ) ? $input['publicize_message'] : null;
		unset( $input['publicize_message'] );

		if ( isset( $input['featured_image'] ) ) {
			$featured_image        = trim( $input['featured_image'] );
			$delete_featured_image = empty( $featured_image );
			unset( $input['featured_image'] );
		}

		$metadata = isset( $input['metadata'] ) ? $input['metadata'] : null;
		unset( $input['metadata'] );

		$likes = isset( $input['likes_enabled'] ) ? $input['likes_enabled'] : null;
		unset( $input['likes_enabled'] );

		$sharing = isset( $input['sharing_enabled'] ) ? $input['sharing_enabled'] : null;
		unset( $input['sharing_enabled'] );

		$sticky = isset( $input['sticky'] ) ? $input['sticky'] : null;
		unset( $input['sticky'] );

		foreach ( $input as $key => $value ) {
			$insert[ "post_$key" ] = $value;
		}

		if ( ! empty( $author_id ) ) {
			$insert['post_author'] = absint( $author_id );
		}

		if ( ! empty( $tax_input ) ) {
			$insert['tax_input'] = $tax_input;
		}

		$has_media        = ! empty( $input['media'] ) ? count( $input['media'] ) : false;
		$has_media_by_url = ! empty( $input['media_urls'] ) ? count( $input['media_urls'] ) : false;

		$media_id_string = '';
		if ( $has_media || $has_media_by_url ) {
			$media_files     = ! empty( $input['media'] ) ? $input['media'] : array();
			$media_urls      = ! empty( $input['media_urls'] ) ? $input['media_urls'] : array();
			$media_attrs     = ! empty( $input['media_attrs'] ) ? $input['media_attrs'] : array();
			$media_results   = $this->handle_media_creation_v1_1( $media_files, $media_urls, $media_attrs );
			$media_id_string = join( ',', array_filter( array_map( 'absint', $media_results['media_ids'] ) ) );
		}

		$is_dtp_fb_post = false;
		if ( in_array( '_dtp_fb', wp_list_pluck( (array) $metadata, 'key' ), true ) ) {
			$is_dtp_fb_post = true;
			add_filter( 'rest_api_allowed_public_metadata', array( $this, 'dtp_fb_allowed_metadata' ) );
		}

		if ( $new ) {
			if ( isset( $input['content'] ) && ! has_shortcode( $input['content'], 'gallery' ) && ( $has_media || $has_media_by_url ) ) {
				switch ( ( $has_media + $has_media_by_url ) ) {
					case 0:
						// No images - do nothing.
						break;
					case 1:
						// 1 image - make it big.
						$input['content']       = sprintf(
							"[gallery size=full ids='%s' columns=1]\n\n",
							$media_id_string
						) . $input['content'];
						$insert['post_content'] = $input['content'];
						break;
					default:
						// Several images - 3 column gallery.
						$input['content']       = sprintf(
							"[gallery ids='%s']\n\n",
							$media_id_string
						) . $input['content'];
						$insert['post_content'] = $input['content'];
						break;
				}
			}

			$insert['post_date'] = isset( $insert['post_date'] ) ? $insert['post_date'] : '';

			if ( $is_dtp_fb_post ) {
				$insert = $this->dtp_fb_preprocess_post( $insert, $metadata );
			}

			$post_id = $this->post_exists( $insert['post_title'], $insert['post_content'], $insert['post_date'], $post_type->name );
			if ( 0 === $post_id ) {
				$post_id = wp_insert_post( add_magic_quotes( $insert ), true );
			}
		} else {
			$insert['ID'] = $post->ID;

			// wp_update_post ignores date unless edit_date is set
			// See: https://codex.wordpress.org/Function_Reference/wp_update_post#Scheduling_posts
			// See: https://core.trac.wordpress.org/browser/tags/3.9.2/src/wp-includes/post.php#L3302 .
			if ( isset( $input['date_gmt'] ) || isset( $input['date'] ) ) {
				$insert['edit_date'] = true;
			}

			// this two-step process ensures any changes submitted along with status=trash get saved before trashing.
			if ( isset( $input['status'] ) && 'trash' === $input['status'] ) {
				// if we insert it with status='trash', it will get double-trashed, so insert it as a draft first.
				unset( $insert['status'] );
				$post_id = wp_update_post( (object) $insert );
				// now call wp_trash_post so post_meta gets set and any filters get called.
				wp_trash_post( $post_id );
			} else {
				$post_id = wp_update_post( (object) $insert );
			}
		}

		if ( ! $post_id || is_wp_error( $post_id ) ) {
			return $post_id;
		}

		// make sure this post actually exists and is not an error of some kind (ie, trying to load media in the posts endpoint).
		$post_check = $this->get_post_by( 'ID', $post_id, $args['context'] );
		if ( is_wp_error( $post_check ) ) {
			return $post_check;
		}

		if ( $media_id_string ) {
			// Yes - this is really how wp-admin does it.
			$wpdb->query(
				$wpdb->prepare(
					"UPDATE $wpdb->posts SET post_parent = %d WHERE post_type = 'attachment' AND ID IN ( $media_id_string )", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- IDs are filtered to absint above.
					$post_id
				)
			);
			foreach ( $media_results['media_ids'] as $media_id ) {
				clean_attachment_cache( $media_id );
			}
			clean_post_cache( $post_id );
		}

		// set page template for this post.
		if ( isset( $input['page_template'] ) && 'page' === $post_type->name ) {
			$page_template  = $input['page_template'];
			$page_templates = wp_get_theme()->get_page_templates( get_post( $post_id ) );
			if ( empty( $page_template ) || 'default' === $page_template || isset( $page_templates[ $page_template ] ) ) {
				update_post_meta( $post_id, '_wp_page_template', $page_template );
			}
		}

		// Set like status for the post.
		/** This filter is documented in modules/likes.php */
		$sitewide_likes_enabled = (bool) apply_filters( 'wpl_is_enabled_sitewide', ! get_option( 'disabled_likes' ) );
		if ( $new ) {
			if ( $sitewide_likes_enabled ) {
				if ( false === $likes ) {
					update_post_meta( $post_id, 'switch_like_status', 0 );
				} else {
					delete_post_meta( $post_id, 'switch_like_status' );
				}
			} elseif ( $likes ) {
				update_post_meta( $post_id, 'switch_like_status', 1 );
			} else {
				delete_post_meta( $post_id, 'switch_like_status' );
			}
		} elseif ( isset( $likes ) ) {
			if ( $sitewide_likes_enabled ) {
				if ( false === $likes ) {
					update_post_meta( $post_id, 'switch_like_status', 0 );
				} else {
					delete_post_meta( $post_id, 'switch_like_status' );
				}
			} elseif ( true === $likes ) {
				update_post_meta( $post_id, 'switch_like_status', 1 );
			} else {
				delete_post_meta( $post_id, 'switch_like_status' );
			}
		}

		// Set sharing status of the post.
		if ( $new ) {
			$sharing_enabled = isset( $sharing ) ? (bool) $sharing : true;
			if ( false === $sharing_enabled ) {
				update_post_meta( $post_id, 'sharing_disabled', 1 );
			}
		} elseif ( isset( $sharing ) && true === $sharing ) {
			delete_post_meta( $post_id, 'sharing_disabled' );
		} elseif ( isset( $sharing ) && false == $sharing ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
			update_post_meta( $post_id, 'sharing_disabled', 1 );
		}

		if ( isset( $sticky ) ) {
			if ( true === $sticky ) {
				stick_post( $post_id );
			} else {
				unstick_post( $post_id );
			}
		}

		// WPCOM Specific (Jetpack's will get bumped elsewhere
		// Tracks how many posts are published and sets meta
		// so we can track some other cool stats (like likes & comments on posts published).
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			if (
				( $new && 'publish' === $input['status'] )
				|| (
					! $new && isset( $last_status )
					&& 'publish' !== $last_status
					&& isset( $new_status )
					&& 'publish' === $new_status
				)
			) {
				/** This action is documented in modules/widgets/social-media-icons.php */
				do_action( 'jetpack_bump_stats_extras', 'api-insights-posts', $this->api->token_details['client_id'] );
				update_post_meta( $post_id, '_rest_api_published', 1 );
				update_post_meta( $post_id, '_rest_api_client_id', $this->api->token_details['client_id'] );
			}
		}

		// We ask the user/dev to pass Publicize services he/she wants activated for the post, but Publicize expects us
		// to instead flag the ones we don't want to be skipped. proceed with said logic.
		// any posts coming from Path (client ID 25952) should also not publicize.
		if ( false === $publicize || ( isset( $this->api->token_details['client_id'] ) && 25952 === (int) $this->api->token_details['client_id'] ) ) {
			// No publicize at all, skip all by ID.
			foreach ( $GLOBALS['publicize_ui']->publicize->get_services( 'all' ) as $name => $service ) {
				delete_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_SKIP . $name );
				$service_connections = $GLOBALS['publicize_ui']->publicize->get_connections( $name );
				if ( ! $service_connections ) {
					continue;
				}
				foreach ( $service_connections as $service_connection ) {
					update_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_SKIP . $service_connection->unique_id, 1 );
				}
			}
		} elseif ( is_array( $publicize ) && ( count( $publicize ) > 0 ) ) {
			foreach ( $GLOBALS['publicize_ui']->publicize->get_services( 'all' ) as $name => $service ) {
				/*
				 * We support both indexed and associative arrays:
				 * * indexed are to pass entire services
				 * * associative are to pass specific connections per service
				 *
				 * We do support mixed arrays: mixed integer and string keys (see 3rd example below).
				 *
				 * EG: array( 'twitter', 'facebook') will only publicize to those, ignoring the other available services
				 *      Form data: publicize[]=twitter&publicize[]=facebook
				 * EG: array( 'twitter' => '(int) $pub_conn_id_0, (int) $pub_conn_id_3', 'facebook' => (int) $pub_conn_id_7 ) will publicize to two Twitter accounts, and one Facebook connection, of potentially many.
				 *      Form data: publicize[twitter]=$pub_conn_id_0,$pub_conn_id_3&publicize[facebook]=$pub_conn_id_7
				 * EG: array( 'twitter', 'facebook' => '(int) $pub_conn_id_0, (int) $pub_conn_id_3' ) will publicize to all available Twitter accounts, but only 2 of potentially many Facebook connections
				 *      Form data: publicize[]=twitter&publicize[facebook]=$pub_conn_id_0,$pub_conn_id_3
				 */

				// Delete any stale SKIP value for the service by name. We'll add it back by ID.
				delete_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_SKIP . $name );

				// Get the user's connections.
				$service_connections = $GLOBALS['publicize_ui']->publicize->get_connections( $name );

				// if the user doesn't have any connections for this service, move on.
				if ( ! $service_connections ) {
					continue;
				}

				if ( ! in_array( $name, $publicize, true ) && ! array_key_exists( $name, $publicize ) ) {
					// Skip the whole service by adding each connection ID.
					foreach ( $service_connections as $service_connection ) {
						update_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_SKIP . $service_connection->unique_id, 1 );
					}
				} elseif ( ! empty( $publicize[ $name ] ) ) {
					// Seems we're being asked to only push to [a] specific connection[s].
					// Explode the list on commas, which will also support a single passed ID.
					$requested_connections = explode( ',', ( preg_replace( '/[\s]*/', '', $publicize[ $name ] ) ) );

					// Flag the connections we can't match with the requested list to be skipped.
					foreach ( $service_connections as $service_connection ) {
						if ( ! in_array( $service_connection->meta['connection_data']->id, $requested_connections, true ) ) {
							update_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_SKIP . $service_connection->unique_id, 1 );
						} else {
							delete_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_SKIP . $service_connection->unique_id );
						}
					}
				} else {
					// delete all SKIP values; it's okay to publish to all connected IDs for this service.
					foreach ( $service_connections as $service_connection ) {
						delete_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_SKIP . $service_connection->unique_id );
					}
				}
			}
		}

		if ( $publicize_custom_message !== null ) {
			if ( empty( $publicize_custom_message ) ) {
				delete_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_MESS );
			} else {
				update_post_meta( $post_id, $GLOBALS['publicize_ui']->publicize->POST_MESS, trim( $publicize_custom_message ) );
			}
		}

		if ( ! empty( $insert['post_format'] ) ) {
			if ( 'default' !== strtolower( $insert['post_format'] ) ) {
				set_post_format( $post_id, $insert['post_format'] );
			} else {
				set_post_format( $post_id, get_option( 'default_post_format' ) );
			}
		}

		if ( isset( $featured_image ) ) {
			parent::parse_and_set_featured_image( $post_id, $delete_featured_image, $featured_image );
		}

		if ( ! empty( $metadata ) ) {
			foreach ( (array) $metadata as $meta ) {

				$meta = (object) $meta;

				if (
					in_array( $meta->key, Jetpack_SEO_Posts::POST_META_KEYS_ARRAY, true ) &&
					! Jetpack_SEO_Utils::is_enabled_jetpack_seo()
				) {
					return new WP_Error( 'unauthorized', __( 'SEO tools are not enabled for this site.', 'jetpack' ), 403 );
				}

				$existing_meta_item = new stdClass();

				if ( empty( $meta->operation ) ) {
					$meta->operation = 'update';
				}

				if ( ! empty( $meta->value ) ) {
					if ( 'true' == $meta->value ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
						$meta->value = true;
					}
					if ( 'false' == $meta->value ) { // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
						$meta->value = false;
					}
				}

				if ( ! empty( $meta->id ) ) {
					$meta->id           = absint( $meta->id );
					$existing_meta_item = get_metadata_by_mid( 'post', $meta->id );
					if ( $post_id !== (int) $existing_meta_item->post_id ) {
						// Only allow updates for metadata on this post.
						continue;
					}
				}

				$unslashed_meta_key           = wp_unslash( $meta->key ); // should match what the final key will be.
				$meta->key                    = wp_slash( $meta->key );
				$unslashed_existing_meta_key  = isset( $existing_meta_item->meta_key ) ? wp_unslash( $existing_meta_item->meta_key ) : '';
				$existing_meta_item->meta_key = isset( $existing_meta_item->meta_key ) ? wp_slash( $existing_meta_item->meta_key ) : '';

				// make sure that the meta id passed matches the existing meta key.
				if ( ! empty( $meta->id ) && ! empty( $meta->key ) ) {
					$meta_by_id = get_metadata_by_mid( 'post', $meta->id );
					if ( $meta_by_id->meta_key !== $meta->key ) {
						continue; // skip this meta.
					}
				}

				switch ( $meta->operation ) {
					case 'delete':
						if ( ! empty( $meta->id ) && ! empty( $existing_meta_item->meta_key ) && current_user_can( 'delete_post_meta', $post_id, $unslashed_existing_meta_key ) ) {
							delete_metadata_by_mid( 'post', $meta->id );
						} elseif ( ! empty( $meta->key ) && ! empty( $meta->previous_value ) && current_user_can( 'delete_post_meta', $post_id, $unslashed_meta_key ) ) {
							delete_post_meta( $post_id, $meta->key, $meta->previous_value );
						} elseif ( ! empty( $meta->key ) && current_user_can( 'delete_post_meta', $post_id, $unslashed_meta_key ) ) {
							delete_post_meta( $post_id, $meta->key );
						}

						break;
					case 'add':
						if ( ! empty( $meta->id ) || ! empty( $meta->previous_value ) ) {
							break;
						} elseif ( ! empty( $meta->key ) && ! empty( $meta->value ) && ( current_user_can( 'add_post_meta', $post_id, $unslashed_meta_key ) ) || WPCOM_JSON_API_Metadata::is_public( $meta->key ) ) {
							add_post_meta( $post_id, $meta->key, $meta->value );
						}

						break;
					case 'update':
						if ( ! isset( $meta->value ) ) {
							break;
						} elseif ( ! empty( $meta->id ) && ! empty( $existing_meta_item->meta_key ) && ( current_user_can( 'edit_post_meta', $post_id, $unslashed_existing_meta_key ) || WPCOM_JSON_API_Metadata::is_public( $meta->key ) ) ) {
							update_metadata_by_mid( 'post', $meta->id, $meta->value );
						} elseif ( ! empty( $meta->key ) && ! empty( $meta->previous_value ) && ( current_user_can( 'edit_post_meta', $post_id, $unslashed_meta_key ) || WPCOM_JSON_API_Metadata::is_public( $meta->key ) ) ) {
							update_post_meta( $post_id, $meta->key, $meta->value, $meta->previous_value );
						} elseif ( ! empty( $meta->key ) && ( current_user_can( 'edit_post_meta', $post_id, $unslashed_meta_key ) || WPCOM_JSON_API_Metadata::is_public( $meta->key ) ) ) {
							update_post_meta( $post_id, $meta->key, $meta->value );
						}

						break;
				}
			}
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-update-post-endpoint.php */
		do_action( 'rest_api_inserted_post', $post_id, $insert, $new );

		$return = $this->get_post_by( 'ID', $post_id, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		if ( isset( $input['type'] ) && 'revision' === $input['type'] ) {
			$return['preview_nonce'] = wp_create_nonce( 'post_preview_' . $input['parent'] );
		}

		if ( isset( $sticky ) ) {
			// workaround for sticky test occasionally failing, maybe a race condition with stick_post() above.
			$return['sticky'] = ( true === $sticky );
		}

		if ( ! empty( $media_results['errors'] ) ) {
			/*
			 * Depending on whether the errors array keys are sequential or not
			 * json_encode would transform this into either an array or an object
			 * see https://www.php.net/manual/en/function.json-encode.php#example-3967
			 * We use array_values to always return an array
			 */
			$return['media_errors'] = array_values( $media_results['errors'] );
		}

		if ( 'publish' !== $return['status'] && isset( $input['title'] ) ) {
			$sal_site             = $this->get_sal_post_by( 'ID', $post_id, $args['context'] );
			$return['other_URLs'] = (object) $sal_site->get_permalink_suggestions( $input['title'] );
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'posts' );

		return $return;
	}

	/**
	 * Determine if a theme's functions.php file should be loaded.
	 *
	 * @param int $post_id Post ID.
	 *
	 * @return bool
	 */
	protected function should_load_theme_functions( $post_id = null ) {
		if ( empty( $post_id ) ) {
			$input = $this->input( true );
			$type  = $input['type'];
		} else {
			$type = get_post_type( $post_id );
		}

		return ! empty( $type ) && ! in_array( $type, array( 'post', 'revision' ), true );
	}

	/**
	 * Filter for rest_api_allowed_public_metadata.
	 * Adds FB's DTP specific metadata.
	 *
	 * @param array $keys Array of metadata that is accessible by the REST API.
	 *
	 * @return array
	 */
	public function dtp_fb_allowed_metadata( $keys ) {
		return array_merge( $keys, array( '_dtp_fb', '_dtp_fb_geo_points', '_dtp_fb_post_link' ) );
	}

	/**
	 * Pre-process FB DTP posts before inserting.
	 * Here we can improve the DTP content for the following issues:
	 * - Render the map block based on provided coordinates in metadata
	 * - [TODO] Improve the title
	 *
	 * @param array $post Post to be inserted.
	 * @param array $metadata Metadata for the post.
	 *
	 * @return mixed
	 */
	private function dtp_fb_preprocess_post( $post, $metadata ) {
		$geo_points_metadata = wp_filter_object_list( $metadata, array( 'key' => '_dtp_fb_geo_points' ), 'and', 'value' );
		if ( ! empty( $geo_points_metadata ) ) {
			$fb_points  = reset( $geo_points_metadata );
			$geo_points = array();

			// Prepare Geo Points so that they match the format expected by the map block.
			foreach ( $fb_points as $fb_point ) {
				$geo_points[] = array(
					'coordinates' => array(
						'longitude' => $fb_point['longitude'],
						'latitude'  => $fb_point['latitude'],
					),
					'title'       => $fb_point['name'],
				);
			}
			$map_block = map_block_from_geo_points( $geo_points );

			$post['post_content'] = $map_block . $post['post_content'];
		}

		$post['post_format'] = 'aside';

		return $post;
	}

	/**
	 * Determines if a post exists based on title, content, date, and type,
	 * But excluding IDs in gallery shortcodes.
	 * This will prevent duplication of posts created through the API.
	 *
	 * @param string $title   Post title.
	 * @param string $content Post content.
	 * @param string $post_date    Post date.
	 * @param string $type    Optional post type.
	 * @return int Post ID if post exists, 0 otherwise.
	 */
	private function post_exists( $title, $content, $post_date, $type = '' ) {
		$date = date_create( $post_date );

		$posts = get_posts(
			array(
				'year'             => date_format( $date, 'Y' ),
				'monthnum'         => date_format( $date, 'n' ),
				'day'              => date_format( $date, 'j' ),
				'hour'             => date_format( $date, 'G' ),
				'minute'           => date_format( $date, 'i' ),
				'second'           => date_format( $date, 's' ),
				'post_type'        => $type,
				'title'            => $title,
				'numberposts'      => -1,
				'suppress_filters' => false,
			)
		);

		foreach ( $posts as $post ) {
			$gallery_ids_pattern = "/(\[gallery[^\]]*)(\sids='[\d,]+')([^\]]*\])/";

			$post->post_content = preg_replace( $gallery_ids_pattern, '$1$3', $post->post_content );
			$content            = preg_replace( $gallery_ids_pattern, '$1$3', $content );

			if ( $content === $post->post_content ) {
				return $post->ID;
			}
		}

		return 0;
	}
}
