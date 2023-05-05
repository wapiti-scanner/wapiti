<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Update post endpoint.
 *
 * Endpoints:
 * Create a post:  /sites/%s/posts/new
 * Update a post:  /sites/%s/posts/%d
 * Delete a post:  /sites/%s/posts/%d/delete
 * Restore a post: /sites/%s/posts/%d/restore
 */

new WPCOM_JSON_API_Update_Post_Endpoint(
	array(
		'description'          => 'Create a post.',
		'group'                => 'posts',
		'stat'                 => 'posts:new',
		'new_version'          => '1.2',
		'max_version'          => '1',
		'method'               => 'POST',
		'path'                 => '/sites/%s/posts/new',
		'path_labels'          => array(
			'$site' => '(int|string) Site ID or domain',
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
				'auto-draft' => 'Save a placeholder for a newly created post, with no content.',
			),
			'sticky'            => array(
				'false' => 'Post is not marked as sticky.',
				'true'  => 'Stick the post to the front page.',
			),
			'password'          => '(string) The plaintext password protecting the post, or, more likely, the empty string if the post is not password protected.',
			'parent'            => "(int) The post ID of the new post's parent.",
			'type'              => "(string) The post type. Defaults to 'post'. Post types besides post and page need to be whitelisted using the <code>rest_api_allowed_post_types</code> filter.",
			'categories'        => '(array|string) Comma-separated list or array of categories (name or id)',
			'tags'              => '(array|string) Comma-separated list or array of tags (name or id)',
			'format'            => array_merge( array( 'default' => 'Use default post format' ), get_post_format_strings() ),
			'featured_image'    => '(string) The post ID of an existing attachment to set as the featured image. Pass an empty string to delete the existing image.',
			'media'             => '(media) An array of files to attach to the post. To upload media, the entire request should be multipart/form-data encoded. Multiple media items will be displayed in a gallery. Accepts  jpg, jpeg, png, gif, pdf, doc, ppt, odt, pptx, docx, pps, ppsx, xls, xlsx, key. Audio and Video may also be available. See <code>allowed_file_types</code> in the options response of the site endpoint. <br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'title=Image' \<br />--form 'media[]=@/path/to/file.jpg' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/posts/new'</code>",
			'media_urls'        => '(array) An array of URLs for images to attach to a post. Sideloads the media in for a post.',
			'metadata'          => '(array) Array of metadata objects containing the following properties: `key` (metadata key), `id` (meta ID), `previous_value` (if set, the action will only occur for the provided previous value), `value` (the new value to set the meta to), `operation` (the operation to perform: `update` or `add`; defaults to `update`). All unprotected meta keys are available by default for read requests. Both unprotected and protected meta keys are avaiable for authenticated requests with proper capabilities. Protected meta keys can be made available with the <code>rest_api_allowed_public_metadata</code> filter.',
			'comments_open'     => "(bool) Should the post be open to comments? Defaults to the blog's preference.",
			'pings_open'        => "(bool) Should the post be open to comments? Defaults to the blog's preference.",
			'likes_enabled'     => "(bool) Should the post be open to likes? Defaults to the blog's preference.",
			'sharing_enabled'   => '(bool) Should sharing buttons show on this post? Defaults to true.',
			'menu_order'        => '(int) (Pages Only) the order pages should appear in. Use 0 to maintain alphabetical order.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/posts/new/',

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

new WPCOM_JSON_API_Update_Post_Endpoint(
	array(
		'description'          => 'Edit a post.',
		'group'                => 'posts',
		'stat'                 => 'posts:1:POST',
		'new_version'          => '1.2',
		'max_version'          => '1',
		'method'               => 'POST',
		'path'                 => '/sites/%s/posts/%d',
		'path_labels'          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$post_ID' => '(int) The post ID',
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
				'pending' => 'Mark the post as pending editorial approval.',
				'trash'   => 'Set the post as trashed.',
			),
			'sticky'            => array(
				'false' => 'Post is not marked as sticky.',
				'true'  => 'Stick the post to the front page.',
			),
			'password'          => '(string) The plaintext password protecting the post, or, more likely, the empty string if the post is not password protected.',
			'parent'            => "(int) The post ID of the new post's parent.",
			'categories'        => '(array|string) Comma-separated list or array of categories (name or id)',
			'tags'              => '(array|string) Comma-separated list or array of tags (name or id)',
			'format'            => array_merge( array( 'default' => 'Use default post format' ), get_post_format_strings() ),
			'comments_open'     => '(bool) Should the post be open to comments?',
			'pings_open'        => '(bool) Should the post be open to comments?',
			'likes_enabled'     => '(bool) Should the post be open to likes?',
			'menu_order'        => '(int) (Pages Only) the order pages should appear in. Use 0 to maintain alphabetical order.',
			'sharing_enabled'   => '(bool) Should sharing buttons show on this post?',
			'featured_image'    => '(string) The post ID of an existing attachment to set as the featured image. Pass an empty string to delete the existing image.',
			'media'             => '(media) An array of files to attach to the post. To upload media, the entire request should be multipart/form-data encoded. Multiple media items will be displayed in a gallery. Accepts  jpg, jpeg, png, gif, pdf, doc, ppt, odt, pptx, docx, pps, ppsx, xls, xlsx, key. Audio and Video may also be available. See <code>allowed_file_types</code> in the options resposne of the site endpoint. <br /><br /><strong>Example</strong>:<br />' .
							"<code>curl \<br />--form 'title=Image' \<br />--form 'media[]=@/path/to/file.jpg' \<br />-H 'Authorization: BEARER your-token' \<br />'https://public-api.wordpress.com/rest/v1/sites/123/posts/new'</code>",
			'media_urls'        => '(array) An array of URLs for images to attach to a post. Sideloads the media in for a post.',
			'metadata'          => '(array) Array of metadata objects containing the following properties: `key` (metadata key), `id` (meta ID), `previous_value` (if set, the action will only occur for the provided previous value), `value` (the new value to set the meta to), `operation` (the operation to perform: `update` or `add`; defaults to `update`). All unprotected meta keys are available by default for read requests. Both unprotected and protected meta keys are available for authenticated requests with proper capabilities. Protected meta keys can be made available with the <code>rest_api_allowed_public_metadata</code> filter.',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/posts/881',

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

new WPCOM_JSON_API_Update_Post_Endpoint(
	array(
		'description'          => 'Delete a post. Note: If the trash is enabled, this request will send the post to the trash. A second request will permanently delete the post.',
		'group'                => 'posts',
		'stat'                 => 'posts:1:delete',
		'new_version'          => '1.1',
		'max_version'          => '1',
		'method'               => 'POST',
		'path'                 => '/sites/%s/posts/%d/delete',
		'path_labels'          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$post_ID' => '(int) The post ID',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/posts/$post_ID/delete/',

		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

new WPCOM_JSON_API_Update_Post_Endpoint(
	array(
		'description'          => 'Restore a post or page from the trash to its previous status.',
		'group'                => 'posts',
		'stat'                 => 'posts:1:restore',

		'method'               => 'POST',
		'new_version'          => '1.1',
		'max_version'          => '1',
		'path'                 => '/sites/%s/posts/%d/restore',
		'path_labels'          => array(
			'$site'    => '(int|string) Site ID or domain',
			'$post_ID' => '(int) The post ID',
		),

		'example_request'      => 'https://public-api.wordpress.com/rest/v1/sites/82974409/posts/$post_ID/restore/',

		'example_request_data' => array(
			'headers' => array(
				'authorization' => 'Bearer YOUR_API_TOKEN',
			),
		),
	)
);

/**
 * Update post endpoint class.
 */
class WPCOM_JSON_API_Update_Post_Endpoint extends WPCOM_JSON_API_Post_Endpoint {
	/**
	 * WPCOM_JSON_API_Update_Post_Endpoint constructor.
	 *
	 * @param array $args Args.
	 */
	public function __construct( $args ) {
		parent::__construct( $args );
		if ( $this->api->ends_with( $this->path, '/delete' ) ) {
			$this->post_object_format['status']['deleted'] = 'The post has been deleted permanently.';
		}
	}

	/**
	 * Update post API callback.
	 *
	 * /sites/%s/posts/new        -> $blog_id
	 * /sites/%s/posts/%d         -> $blog_id, $post_id
	 * /sites/%s/posts/%d/delete  -> $blog_id, $post_id
	 * /sites/%s/posts/%d/restore -> $blog_id, $post_id
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 * @param int    $post_id Post ID.
	 *
	 * @return array|bool|WP_Error
	 */
	public function callback( $path = '', $blog_id = 0, $post_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( $this->api->ends_with( $path, '/delete' ) ) {
			return $this->delete_post( $path, $blog_id, $post_id );
		} elseif ( $this->api->ends_with( $path, '/restore' ) ) {
			return $this->restore_post( $path, $blog_id, $post_id );
		} else {
			return $this->write_post( $path, $blog_id, $post_id );
		}
	}

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
		$new  = $this->api->ends_with( $path, '/new' );
		$args = $this->query_args();

		// unhook publicize, it's hooked again later -- without this, skipping services is impossible.
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			remove_action( 'save_post', array( $GLOBALS['publicize_ui']->publicize, 'async_publicize_post' ), 100, 2 );
			add_action( 'rest_api_inserted_post', array( $GLOBALS['publicize_ui']->publicize, 'async_publicize_post' ) );
		}

		if ( $new ) {
			$input = $this->input( true );

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
				$author_id = $this->parse_and_set_author( $input['author'], $input['type'] );
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

			$post       = get_post( $post_id );
			$_post_type = ( ! empty( $input['type'] ) ) ? $input['type'] : $post->post_type;
			$post_type  = get_post_type_object( $_post_type );
			if ( ! $post || is_wp_error( $post ) ) {
				return new WP_Error( 'unknown_post', 'Unknown post', 404 );
			}

			if ( ! current_user_can( 'edit_post', $post->ID ) ) {
				return new WP_Error( 'unauthorized', 'User cannot edit post', 403 );
			}

			if ( ! empty( $input['author'] ) ) {
				$author_id = $this->parse_and_set_author( $input['author'], $_post_type );
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
			$date_in_past = ( strtotime( $post->post_date_gmt ) < time() );
			if ( 'publish' === $new_status && 'draft' === $last_status && ! isset( $input['date_gmt'] ) && $date_in_past ) {
				$input['date_gmt'] = gmdate( 'Y-m-d H:i:s' );
			}

			// Untrash a post so that the proper hooks get called as well as the comments get untrashed.
			if ( 'trash' === $last_status && 'trash' !== $new_status && isset( $post->ID ) ) {
				wp_untrash_post( $post->ID );
				$untashed_post = get_post( $post->ID );
				// Lets make sure that we use the revert the slug.
				if ( isset( $untashed_post->post_name ) && $untashed_post->post_name . '__trashed' === $input['slug'] ) {
					unset( $input['slug'] );
				}
			}
		}

		if ( function_exists( 'wpcom_switch_to_locale' ) ) {
			// fixes calypso-pre-oss #12476: respect blog locale when creating the post slug.
			wpcom_switch_to_locale( get_blog_lang_code( $blog_id ) );
		}

		// If date was set, $this->input will set date_gmt, date still needs to be adjusted for the blog's offset.
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

		$tax_input = array();

		foreach ( array(
			'categories' => 'category',
			'tags'       => 'post_tag',
		) as $key => $taxonomy ) {
			if ( ! isset( $input[ $key ] ) ) {
				continue;
			}

			$tax_input[ $taxonomy ] = array();

			$is_hierarchical = is_taxonomy_hierarchical( $taxonomy );

			if ( is_array( $input[ $key ] ) ) {
				$terms = $input[ $key ];
			} else {
				$terms = explode( ',', $input[ $key ] );
			}

			foreach ( $terms as $term ) {
				/**
				 * `curl --data 'category[]=123'` should be interpreted as a category ID,
				 * not a category whose name is '123'.
				 *
				 * Consequence: To add a category/tag whose name is '123', the client must
				 * first look up its ID.
				 */
				$term = (string) $term; // ctype_digit compat.
				if ( ctype_digit( $term ) ) {
					$term = (int) $term;
				}

				$term_info = term_exists( $term, $taxonomy );

				if ( ! $term_info ) {
					// A term ID that doesn't already exist. Ignore it: we don't know what name to give it.
					if ( is_int( $term ) ) {
						continue;
					}
					// only add a new tag/cat if the user has access to.
					$tax = get_taxonomy( $taxonomy );

					// see https://core.trac.wordpress.org/ticket/26409 .
					if ( 'category' === $taxonomy && ! current_user_can( $tax->cap->edit_terms ) ) {
						continue;
					} elseif ( ! current_user_can( $tax->cap->assign_terms ) ) {
						continue;
					}

					$term_info = wp_insert_term( $term, $taxonomy );
				}

				if ( ! is_wp_error( $term_info ) ) {
					if ( $is_hierarchical ) {
						// Categories must be added by ID.
						$tax_input[ $taxonomy ][] = (int) $term_info['term_id'];
					} elseif ( is_int( $term ) ) { // Tags must be added by name.
						$term                     = get_term( $term, $taxonomy );
						$tax_input[ $taxonomy ][] = $term->name;
					} else {
						$tax_input[ $taxonomy ][] = $term;
					}
				}
			}
		}

		if ( isset( $input['categories'] ) && empty( $tax_input['category'] ) && 'revision' !== $post_type->name ) {
			$tax_input['category'][] = get_option( 'default_category' );
		}

		unset( $input['tags'], $input['categories'] );

		$insert = array();

		if ( ! empty( $input['slug'] ) ) {
			$insert['post_name'] = $input['slug'];
			unset( $input['slug'] );
		}

		if ( isset( $input['comments_open'] ) ) {
			$insert['comment_status'] = ( true === $input['comments_open'] ) ? 'open' : 'closed';
		}

		if ( isset( $input['pings_open'] ) ) {
			$insert['ping_status'] = ( true === $input['pings_open'] ) ? 'open' : 'closed';
		}

		unset( $input['comments_open'], $input['pings_open'] );

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

		$has_media        = isset( $input['media'] ) && $input['media'] ? count( $input['media'] ) : false;
		$has_media_by_url = isset( $input['media_urls'] ) && $input['media_urls'] ? count( $input['media_urls'] ) : false;

		if ( $new ) {

			if ( isset( $input['content'] ) && ! has_shortcode( $input['content'], 'gallery' ) && ( $has_media || $has_media_by_url ) ) {
				switch ( ( $has_media + $has_media_by_url ) ) {
					case 0:
						// No images - do nothing.
						break;
					case 1:
						// 1 image - make it big.
						$input['content']       = "[gallery size=full columns=1]\n\n" . $input['content'];
						$insert['post_content'] = $input['content'];
						break;
					default:
						// Several images - 3 column gallery.
						$input['content']       = "[gallery]\n\n" . $input['content'];
						$insert['post_content'] = $input['content'];
						break;
				}
			}

			$post_id = wp_insert_post( add_magic_quotes( $insert ), true );
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

		if ( $has_media ) {
			$this->api->trap_wp_die( 'upload_error' );
			foreach ( $input['media'] as $media_item ) {
				$_FILES['.api.media.item.'] = $media_item;
				// check for WP_Error if we ever actually need $media_id .
				$media_id = media_handle_upload( '.api.media.item.', $post_id ); // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			}
			$this->api->trap_wp_die( null );

			unset( $_FILES['.api.media.item.'] );
		}

		if ( $has_media_by_url ) {
			foreach ( $input['media_urls'] as $url ) {
				$this->handle_media_sideload( $url, $post_id );
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
			$this->parse_and_set_featured_image( $post_id, $delete_featured_image, $featured_image );
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
				$unslashed_existing_meta_key  = wp_unslash( $existing_meta_item->meta_key );
				$existing_meta_item->meta_key = wp_slash( $existing_meta_item->meta_key );

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

		/**
		 * Fires when a post is created via the REST API.
		 *
		 * @module json-api
		 *
		 * @since 2.3.0
		 *
		 * @param int $post_id Post ID.
		 * @param array $insert Data used to build the post.
		 * @param string $new New post URL suffix.
		 */
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

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'posts' );

		return $return;
	}

	/**
	 * Delete a post.
	 *
	 * /sites/%s/posts/%d/delete -> $blog_id, $post_id
	 *
	 * @param string $path API path.
	 * @param array  $blog_id Blog ID.
	 * @param array  $post_id Post ID.
	 *
	 * @return array|WP_Error
	 */
	public function delete_post( $path, $blog_id, $post_id ) {
		$post = get_post( $post_id );
		if ( ! $post || is_wp_error( $post ) ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		if ( ! $this->is_post_type_allowed( $post->post_type ) ) {
			return new WP_Error( 'unknown_post_type', 'Unknown post type', 404 );
		}

		if ( ! current_user_can( 'delete_post', $post->ID ) ) {
			return new WP_Error( 'unauthorized', 'User cannot delete posts', 403 );
		}

		$args   = $this->query_args();
		$return = $this->get_post_by( 'ID', $post->ID, $args['context'] );
		if ( ! $return || is_wp_error( $return ) ) {
			return $return;
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'posts' );

		// we need to call wp_trash_post so that untrash will work correctly for all post types.
		if ( 'trash' === $post->post_status ) {
			wp_delete_post( $post->ID );
		} else {
			wp_trash_post( $post->ID );
		}

		$status = get_post_status( $post->ID );
		if ( false === $status ) {
			$return['status'] = 'deleted';
			return $return;
		}

		return $this->get_post_by( 'ID', $post->ID, $args['context'] );
	}

	/**
	 * Restore a post.
	 *
	 * /sites/%s/posts/%d/restore -> $blog_id, $post_id
	 *
	 * @param string $path API path.
	 * @param int    $blog_id Blog ID.
	 * @param int    $post_id Post ID.
	 *
	 * @return array|WP_Error
	 */
	public function restore_post( $path, $blog_id, $post_id ) {
		$args = $this->query_args();
		$post = get_post( $post_id );

		if ( ! $post || is_wp_error( $post ) ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		if ( ! current_user_can( 'delete_post', $post->ID ) ) {
			return new WP_Error( 'unauthorized', 'User cannot restore trashed posts', 403 );
		}

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'posts' );

		wp_untrash_post( $post->ID );

		return $this->get_post_by( 'ID', $post->ID, $args['context'] );
	}

	/**
	 * Set or delete a post's featured image.
	 *
	 * @param int  $post_id Post ID.
	 * @param bool $delete_featured_image Whether to delete the featured image.
	 * @param int  $featured_image Thumbnail ID to attach.
	 *
	 * @return null|int|bool
	 */
	private function parse_and_set_featured_image( $post_id, $delete_featured_image, $featured_image ) {
		if ( $delete_featured_image ) {
			delete_post_thumbnail( $post_id );
			return;
		}

		$featured_image = (string) $featured_image;

		// if we got a post ID, we can just set it as the thumbnail.
		if ( ctype_digit( $featured_image ) && 'attachment' === get_post_type( $featured_image ) ) {
			set_post_thumbnail( $post_id, $featured_image );
			return $featured_image;
		}

		$featured_image_id = $this->handle_media_sideload( $featured_image, $post_id, 'image' );

		if ( empty( $featured_image_id ) || ! is_int( $featured_image_id ) ) {
			return false;
		}

		set_post_thumbnail( $post_id, $featured_image_id );
		return $featured_image_id;
	}

	/**
	 * Get the Author ID for a post.
	 *
	 * @param int|string $author Author ID.
	 * @param string     $post_type Post type.
	 *
	 * @return int|WP_Error
	 */
	private function parse_and_set_author( $author = null, $post_type = 'post' ) {
		if ( empty( $author ) || ! post_type_supports( $post_type, 'author' ) ) {
			return get_current_user_id();
		}

		$author = (string) $author;
		if ( ctype_digit( $author ) ) {
			$_user = get_user_by( 'id', $author );
			if ( ! $_user || is_wp_error( $_user ) ) {
				return new WP_Error( 'invalid_author', 'Invalid author provided' );
			}

			return $_user->ID;
		}

		$_user = get_user_by( 'login', $author );
		if ( ! $_user || is_wp_error( $_user ) ) {
			return new WP_Error( 'invalid_author', 'Invalid author provided' );
		}

		return $_user->ID;
	}
}
