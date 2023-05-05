<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Post Endpoint class.
 */
abstract class WPCOM_JSON_API_Post_Endpoint extends WPCOM_JSON_API_Endpoint {
	/**
	 * Post object format.
	 *
	 * @var array
	 */
	public $post_object_format = array(
		// explicitly document and cast all output
		'ID'               => '(int) The post ID.',
		'site_ID'          => '(int) The site ID.',
		'author'           => '(object>author) The author of the post.',
		'date'             => "(ISO 8601 datetime) The post's creation time.",
		'modified'         => "(ISO 8601 datetime) The post's most recent update time.",
		'title'            => '(HTML) <code>context</code> dependent.',
		'URL'              => '(URL) The full permalink URL to the post.',
		'short_URL'        => '(URL) The wp.me short URL.',
		'content'          => '(HTML) <code>context</code> dependent.',
		'excerpt'          => '(HTML) <code>context</code> dependent.',
		'slug'             => '(string) The name (slug) for the post, used in URLs.',
		'guid'             => '(string) The GUID for the post.',
		'status'           => array(
			'publish'    => 'The post is published.',
			'draft'      => 'The post is saved as a draft.',
			'pending'    => 'The post is pending editorial approval.',
			'private'    => 'The post is published privately',
			'future'     => 'The post is scheduled for future publishing.',
			'trash'      => 'The post is in the trash.',
			'auto-draft' => 'The post is a placeholder for a new post.',
		),
		'sticky'           => '(bool) Is the post sticky?',
		'password'         => '(string) The plaintext password protecting the post, or, more likely, the empty string if the post is not password protected.',
		'parent'           => "(object>post_reference|false) A reference to the post's parent, if it has one.",
		'type'             => "(string) The post's post_type. Post types besides post, page and revision need to be whitelisted using the <code>rest_api_allowed_post_types</code> filter.",
		'comments_open'    => '(bool) Is the post open for comments?',
		'pings_open'       => '(bool) Is the post open for pingbacks, trackbacks?',
		'likes_enabled'    => '(bool) Is the post open to likes?',
		'sharing_enabled'  => '(bool) Should sharing buttons show on this post?',
		'comment_count'    => '(int) The number of comments for this post.',
		'like_count'       => '(int) The number of likes for this post.',
		'i_like'           => '(bool) Does the current user like this post?',
		'is_reblogged'     => '(bool) Did the current user reblog this post?',
		'is_following'     => '(bool) Is the current user following this blog?',
		'global_ID'        => '(string) A unique WordPress.com-wide representation of a post.',
		'featured_image'   => '(URL) The URL to the featured image for this post if it has one.',
		'post_thumbnail'   => '(object>attachment) The attachment object for the featured image if it has one.',
		'format'           => array(), // see constructor
		'geo'              => '(object>geo|false)',
		'menu_order'       => '(int) (Pages Only) The order pages should appear in.',
		'publicize_URLs'   => '(array:URL) Array of Twitter and Facebook URLs published by this post.',
		'tags'             => '(object:tag) Hash of tags (keyed by tag name) applied to the post.',
		'categories'       => '(object:category) Hash of categories (keyed by category name) applied to the post.',
		'attachments'      => '(object:attachment) Hash of post attachments (keyed by attachment ID).',
		'metadata'         => '(array) Array of post metadata keys and values. All unprotected meta keys are available by default for read requests. Both unprotected and protected meta keys are available for authenticated requests with access. Protected meta keys can be made available with the <code>rest_api_allowed_public_metadata</code> filter.',
		'meta'             => '(object) API result meta data',
		'current_user_can' => '(object) List of permissions. Note, deprecated in favor of `capabilities`',
		'capabilities'     => '(object) List of post-specific permissions for the user; publish_post, edit_post, delete_post',
	);

	/**
	 * Constructor function.
	 *
	 * @param string|array|object $args — Args.
	 */
	public function __construct( $args ) {
		if ( is_array( $this->post_object_format ) && isset( $this->post_object_format['format'] ) ) {
			$this->post_object_format['format'] = get_post_format_strings();
		}
		if ( ! $this->response_format ) {
			$this->response_format =& $this->post_object_format;
		}
		parent::__construct( $args );
	}

	/**
	 * Filter to replace the password form with a simple message that the post is protected.
	 *
	 * @return string
	 */
	public function the_password_form() {
		return __( 'This post is password protected.', 'jetpack' );
	}

	/**
	 * Get a post by a specified field and value
	 *
	 * @param string $field - the field.
	 * @param string $field_value - the field value.
	 * @param string $context Post use context (e.g. 'display').
	 * @return array|bool|WP_Error Post
	 **/
	public function get_post_by( $field, $field_value, $context = 'display' ) {
		global $blog_id;

		/** This filter is documented in class.json-api-endpoints.php */
		$is_jetpack = true === apply_filters( 'is_jetpack_site', false, $blog_id );

		if ( defined( 'GEO_LOCATION__CLASS' ) && class_exists( GEO_LOCATION__CLASS ) ) {
			$geo = call_user_func( array( GEO_LOCATION__CLASS, 'init' ) );
		} else {
			$geo = false;
		}

		if ( 'display' === $context ) {
			$args = $this->query_args();
			if ( isset( $args['content_width'] ) && $args['content_width'] ) {
				$GLOBALS['content_width'] = (int) $args['content_width'];
			}
		}

		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) && strpos( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ), 'wp-windows8' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- we're not using this value and making changes, just checking if it exists.
			remove_shortcode( 'gallery', 'gallery_shortcode' );
			add_shortcode( 'gallery', array( $this, 'win8_gallery_shortcode' ) );
		}

		switch ( $field ) {
			case 'name':
				$post_id = $this->get_post_id_by_name( $field_value );
				if ( is_wp_error( $post_id ) ) {
					return $post_id;
				}
				break;
			default:
				$post_id = (int) $field_value;
				break;
		}

		$post = get_post( $post_id, OBJECT, $context );

		if ( ! $post || is_wp_error( $post ) ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		if ( ! $this->is_post_type_allowed( $post->post_type ) && ( ! function_exists( 'is_post_freshly_pressed' ) || ! is_post_freshly_pressed( $post->ID ) ) ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		// Permissions
		$capabilities = $this->get_current_user_capabilities( $post );

		switch ( $context ) {
			case 'edit':
				if ( ! $capabilities['edit_post'] ) {
					return new WP_Error( 'unauthorized', 'User cannot edit post', 403 );
				}
				break;
			case 'display':
				break;
			default:
				return new WP_Error( 'invalid_context', 'Invalid API CONTEXT', 400 );
		}

		$can_view = $this->user_can_view_post( $post->ID );
		if ( ! $can_view || is_wp_error( $can_view ) ) {
			return $can_view;
		}

		$GLOBALS['post'] = $post; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		if ( 'display' === $context ) {
			setup_postdata( $post );
		}

		$response = array();

		$fields = null;
		if ( 'display' === $context && ! empty( $this->api->query['fields'] ) ) {
			$fields = array_fill_keys( array_map( 'trim', explode( ',', $this->api->query['fields'] ) ), true );
		}

		foreach ( array_keys( $this->post_object_format ) as $key ) {
			if ( $fields !== null && ! isset( $fields[ $key ] ) ) {
				continue;
			}
			switch ( $key ) {
				case 'ID':
					// explicitly cast all output
					$response[ $key ] = (int) $post->ID;
					break;
				case 'site_ID':
					$response[ $key ] = (int) $this->api->get_blog_id_for_output();
					break;
				case 'author':
					$response[ $key ] = (object) $this->get_author( $post, 'edit' === $context && $capabilities['edit_post'] );
					break;
				case 'date':
					$response[ $key ] = (string) $this->format_date( $post->post_date_gmt, $post->post_date );
					break;
				case 'modified':
					$response[ $key ] = (string) $this->format_date( $post->post_modified_gmt, $post->post_modified );
					break;
				case 'title':
					if ( 'display' === $context ) {
						$response[ $key ] = (string) get_the_title( $post->ID );
					} else {
						$response[ $key ] = (string) htmlspecialchars_decode( $post->post_title, ENT_QUOTES );
					}
					break;
				case 'URL':
					if ( 'revision' === $post->post_type ) {
						$response[ $key ] = (string) esc_url_raw( get_permalink( $post->post_parent ) );
					} else {
						$response[ $key ] = (string) esc_url_raw( get_permalink( $post->ID ) );
					}
					break;
				case 'short_URL':
					$response[ $key ] = (string) esc_url_raw( wp_get_shortlink( $post->ID ) );
					break;
				case 'content':
					if ( 'display' === $context ) {
						add_filter( 'the_password_form', array( $this, 'the_password_form' ) );
						$response[ $key ] = (string) $this->get_the_post_content_for_display();
						remove_filter( 'the_password_form', array( $this, 'the_password_form' ) );
					} else {
						$response[ $key ] = (string) $post->post_content;
					}
					break;
				case 'excerpt':
					if ( 'display' === $context ) {
						add_filter( 'the_password_form', array( $this, 'the_password_form' ) );
						ob_start();
						the_excerpt();
						$response[ $key ] = (string) ob_get_clean();
						remove_filter( 'the_password_form', array( $this, 'the_password_form' ) );
					} else {
						$response[ $key ] = htmlspecialchars_decode( (string) $post->post_excerpt, ENT_QUOTES );
					}
					break;
				case 'status':
					$response[ $key ] = (string) get_post_status( $post->ID );
					break;
				case 'sticky':
					$response[ $key ] = (bool) is_sticky( $post->ID );
					break;
				case 'slug':
					$response[ $key ] = (string) $post->post_name;
					break;
				case 'guid':
					$response[ $key ] = (string) $post->guid;
					break;
				case 'password':
					$response[ $key ] = (string) $post->post_password;
					if ( 'edit' === $context ) {
						$response[ $key ] = htmlspecialchars_decode( (string) $response[ $key ], ENT_QUOTES );
					}
					break;
				/** (object|false) */
				case 'parent':
					if ( $post->post_parent ) {
						$parent = get_post( $post->post_parent );
						if ( 'display' === $context ) {
							$parent_title = (string) get_the_title( $parent->ID );
						} else {
							$parent_title = (string) htmlspecialchars_decode( $post->post_title, ENT_QUOTES );
						}
						$response[ $key ] = (object) array(
							'ID'    => (int) $parent->ID,
							'type'  => (string) $parent->post_type,
							'link'  => (string) $this->links->get_post_link( $this->api->get_blog_id_for_output(), $parent->ID ),
							'title' => $parent_title,
						);
					} else {
						$response[ $key ] = false;
					}
					break;
				case 'type':
					$response[ $key ] = (string) $post->post_type;
					break;
				case 'comments_open':
					$response[ $key ] = (bool) comments_open( $post->ID );
					break;
				case 'pings_open':
					$response[ $key ] = (bool) pings_open( $post->ID );
					break;
				case 'likes_enabled':
					/** This filter is documented in modules/likes.php */
					$sitewide_likes_enabled = (bool) apply_filters( 'wpl_is_enabled_sitewide', ! get_option( 'disabled_likes' ) );
					$post_likes_switched    = get_post_meta( $post->ID, 'switch_like_status', true );
					$post_likes_enabled     = $post_likes_switched || ( $sitewide_likes_enabled && $post_likes_switched !== '0' );
					$response[ $key ]       = (bool) $post_likes_enabled;
					break;
				case 'sharing_enabled':
					$show = true;
					/** This filter is documented in modules/sharedaddy/sharing-service.php */
					$show = apply_filters( 'sharing_show', $show, $post );

					$switched_status = get_post_meta( $post->ID, 'sharing_disabled', false );

					if ( ! empty( $switched_status ) ) {
						$show = false;
					}
					$response[ $key ] = (bool) $show;
					break;
				case 'comment_count':
					$response[ $key ] = (int) $post->comment_count;
					break;
				case 'like_count':
					$response[ $key ] = (int) $this->api->post_like_count( $blog_id, $post->ID );
					break;
				case 'i_like':
					$response[ $key ] = (bool) $this->api->is_liked( $blog_id, $post->ID );
					break;
				case 'is_reblogged':
					$response[ $key ] = (bool) $this->api->is_reblogged( $blog_id, $post->ID );
					break;
				case 'is_following':
					$response[ $key ] = (bool) $this->api->is_following( $blog_id );
					break;
				case 'global_ID':
					$response[ $key ] = (string) $this->api->add_global_ID( $blog_id, $post->ID );
					break;
				case 'featured_image':
					if ( $is_jetpack && ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ) {
						$response[ $key ] = get_post_meta( $post->ID, '_jetpack_featured_image', true );
					} else {
						$image_attributes = wp_get_attachment_image_src( get_post_thumbnail_id( $post->ID ), 'full' );
						if ( is_array( $image_attributes ) && isset( $image_attributes[0] ) ) {
							$response[ $key ] = (string) $image_attributes[0];
						} else {
							$response[ $key ] = '';
						}
					}
					break;
				case 'post_thumbnail':
					$response[ $key ] = null;

					$thumb_id = get_post_thumbnail_id( $post->ID );
					if ( ! empty( $thumb_id ) ) {
						$attachment = get_post( $thumb_id );
						if ( ! empty( $attachment ) ) {
							$featured_image_object = $this->get_attachment( $attachment );
						}

						if ( ! empty( $featured_image_object ) ) {
							$response[ $key ] = (object) $featured_image_object;
						}
					}
					break;
				case 'format':
					$response[ $key ] = (string) get_post_format( $post->ID );
					if ( ! $response[ $key ] ) {
						$response[ $key ] = 'standard';
					}
					break;
				/** (object|false) */
				case 'geo':
					if ( ! $geo ) {
						$response[ $key ] = false;
					} else {
						$geo_data         = $geo->get_geo( 'post', $post->ID );
						$response[ $key ] = false;
						if ( $geo_data ) {
							$geo_data = array_intersect_key(
								$geo_data,
								array(
									'latitude'  => true,
									'longitude' => true,
									'address'   => true,
									'public'    => true,
								)
							);
							if ( $geo_data ) {
								$response[ $key ] = (object) array(
									'latitude'  => isset( $geo_data['latitude'] ) ? (float) $geo_data['latitude'] : 0,
									'longitude' => isset( $geo_data['longitude'] ) ? (float) $geo_data['longitude'] : 0,
									'address'   => isset( $geo_data['address'] ) ? (string) $geo_data['address'] : '',
								);
							} else {
								$response[ $key ] = false;
							}
							// Private
							if ( ! isset( $geo_data['public'] ) || ! $geo_data['public'] ) {
								if ( 'edit' !== $context || ! $capabilities['edit_post'] ) {
									// user can't access
									$response[ $key ] = false;
								}
							}
						}
					}
					break;
				case 'menu_order':
					$response[ $key ] = (int) $post->menu_order;
					break;
				case 'publicize_URLs':
					$publicize_urls = array();
					$publicize      = get_post_meta( $post->ID, 'publicize_results', true );
					if ( $publicize ) {
						foreach ( $publicize as $service => $data ) {
							switch ( $service ) {
								case 'twitter':
									foreach ( $data as $datum ) {
										$publicize_urls[] = esc_url_raw( "https://twitter.com/{$datum['user_id']}/status/{$datum['post_id']}" );
									}
									break;
								case 'fb':
									foreach ( $data as $datum ) {
										$publicize_urls[] = esc_url_raw( "https://www.facebook.com/permalink.php?story_fbid={$datum['post_id']}&id={$datum['user_id']}" );
									}
									break;
							}
						}
					}
					$response[ $key ] = (array) $publicize_urls;
					break;
				case 'tags':
					$response[ $key ] = array();
					$terms            = wp_get_post_tags( $post->ID );
					foreach ( $terms as $term ) {
						if ( ! empty( $term->name ) ) {
							$response[ $key ][ $term->name ] = $this->format_taxonomy( $term, 'post_tag', 'display' );
						}
					}
					$response[ $key ] = (object) $response[ $key ];
					break;
				case 'categories':
					$response[ $key ] = array();
					$terms            = wp_get_object_terms( $post->ID, 'category', array( 'fields' => 'all' ) );
					foreach ( $terms as $term ) {
						if ( ! empty( $term->name ) ) {
							$response[ $key ][ $term->name ] = $this->format_taxonomy( $term, 'category', 'display' );
						}
					}
					$response[ $key ] = (object) $response[ $key ];
					break;
				case 'attachments':
					$response[ $key ] = array();
					$_attachments     = get_posts(
						array(
							'post_parent'    => $post->ID,
							'post_status'    => 'inherit',
							'post_type'      => 'attachment',
							'posts_per_page' => 100,
						)
					);
					foreach ( $_attachments as $attachment ) {
						$response[ $key ][ $attachment->ID ] = $this->get_attachment( $attachment );
					}
					$response[ $key ] = (object) $response[ $key ];
					break;
				/** (array|false) */
				case 'metadata':
					$metadata = array();
					foreach ( (array) has_meta( $post_id ) as $meta ) {
						// Don't expose protected fields.
						$show = false;
						if ( WPCOM_JSON_API_Metadata::is_public( $meta['meta_key'] ) ) {
							$show = true;
						}
						if ( current_user_can( 'edit_post_meta', $post_id, $meta['meta_key'] ) ) {
							$show = true;
						}

						if (
							in_array( $meta['meta_key'], Jetpack_SEO_Posts::POST_META_KEYS_ARRAY, true ) &&
							! Jetpack_SEO_Utils::is_enabled_jetpack_seo()
						) {
							$show = false;
						}

						if ( ! $show ) {
							continue;
						}

						$metadata[] = array(
							'id'    => $meta['meta_id'],
							'key'   => $meta['meta_key'],
							'value' => maybe_unserialize( $meta['meta_value'] ),
						);
					}

					if ( ! empty( $metadata ) ) {
						$response[ $key ] = $metadata;
					} else {
						$response[ $key ] = false;
					}
					break;
				case 'meta':
					$response[ $key ] = (object) array(
						'links' => (object) array(
							'self'    => (string) $this->links->get_post_link( $this->api->get_blog_id_for_output(), $post->ID ),
							'help'    => (string) $this->links->get_post_link( $this->api->get_blog_id_for_output(), $post->ID, 'help' ),
							'site'    => (string) $this->links->get_site_link( $this->api->get_blog_id_for_output() ),
							'replies' => (string) $this->links->get_post_link( $this->api->get_blog_id_for_output(), $post->ID, 'replies/' ),
							'likes'   => (string) $this->links->get_post_link( $this->api->get_blog_id_for_output(), $post->ID, 'likes/' ),
						),
					);
					break;
				case 'current_user_can':
					$response[ $key ] = $capabilities;
					break;
				case 'capabilities':
					$response[ $key ] = $capabilities;
					break;

			}
		}

		unset( $GLOBALS['post'] );
		return $response;
	}

	/**
	 *
	 * Get the post content for display.
	 *
	 * No Blog ID parameter.  No Post ID parameter.  Depends on globals.
	 * Expects setup_postdata() to already have been run.
	 *
	 * @return string|false
	 */
	public function get_the_post_content_for_display() {
		global $pages, $page;

		$old_pages = $pages;
		$old_page  = $page;

		$content = join( "\n\n", $pages );
		$content = preg_replace( '/<!--more(.*?)?-->/', '', $content );
		$pages   = array( $content ); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$page    = 1; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		ob_start();
		the_content();
		$return = ob_get_clean();

		$pages = $old_pages; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$page  = $old_page; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		return $return;
	}

	/**
	 * Gets the blog post.
	 *
	 * @param int    $blog_id - the blog ID.
	 * @param int    $post_id - the post ID.
	 * @param string $context - the context.
	 * @return array|bool|WP_Error Post
	 */
	public function get_blog_post( $blog_id, $post_id, $context = 'display' ) {
		$blog_id = $this->api->get_blog_id( $blog_id );
		if ( ! $blog_id || is_wp_error( $blog_id ) ) {
			return $blog_id;
		}
		switch_to_blog( $blog_id );
		$post = $this->get_post_by( 'ID', $post_id, $context );
		restore_current_blog();
		return $post;
	}

	/**
	 * Supporting featured media in post endpoints. Currently on for wpcom blogs
	 * since it's calling WPCOM_JSON_API_Read_Endpoint methods which presently
	 * rely on wpcom specific functionality.
	 *
	 * @param  WP_Post $post - the WP Post object.
	 * @return object list of featured media
	 */
	public static function find_featured_media( &$post ) {

		if ( class_exists( 'WPCOM_JSON_API_Read_Endpoint' ) ) {
			return WPCOM_JSON_API_Read_Endpoint::find_featured_worthy_media( (array) $post );
		} else {
			return (object) array();
		}
	}

	/**
	 * Win8 Gallery shortcode.
	 *
	 * @param array $attr - the attribute.
	 */
	public function win8_gallery_shortcode( $attr ) {
		global $post;

		static $instance = 0;
		++$instance;

		// @todo - find out if this is a bug, intentionally unused, or can be removed.
		$output = ''; // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable

		// We're trusting author input, so let's at least make sure it looks like a valid orderby statement
		if ( isset( $attr['orderby'] ) ) {
			$attr['orderby'] = sanitize_sql_orderby( $attr['orderby'] );
			if ( ! $attr['orderby'] ) {
				unset( $attr['orderby'] );
			}
		}

		$atts = shortcode_atts(
			array(
				'order'     => 'ASC',
				'orderby'   => 'menu_order ID',
				'id'        => $post->ID,
				'include'   => '',
				'exclude'   => '',
				'slideshow' => false,
			),
			$attr,
			'gallery'
		);
		$id   = ! empty( $atts['id'] ) ? (int) $atts['id'] : 0;

		// Custom image size and always use it.
		add_image_size( 'win8app-column', 480 );
		$size = 'win8app-column';

		if ( 'RAND' === $atts['order'] ) {
			$orderby = 'none';
		} else {
			$orderby = $atts['orderby'];
		}

		if ( ! empty( $atts['include'] ) ) {
			$include      = preg_replace( '/[^0-9,]+/', '', $atts['include'] );
			$_attachments = get_posts(
				array(
					'include'        => $include,
					'post_status'    => 'inherit',
					'post_type'      => 'attachment',
					'post_mime_type' => 'image',
					'order'          => $atts['order'],
					'orderby'        => $orderby,
				)
			);
			$attachments  = array();
			foreach ( $_attachments as $key => $val ) {
				$attachments[ $val->ID ] = $_attachments[ $key ];
			}
		} elseif ( ! empty( $atts['exclude'] ) ) {
			$exclude     = preg_replace( '/[^0-9,]+/', '', $atts['exclude'] );
			$attachments = get_children(
				array(
					'post_parent'    => $id,
					'exclude'        => $exclude,
					'post_status'    => 'inherit',
					'post_type'      => 'attachment',
					'post_mime_type' => 'image',
					'order'          => $atts['order'],
					'orderby'        => $orderby,
				)
			);
		} else {
			$attachments = get_children(
				array(
					'post_parent'    => $id,
					'post_status'    => 'inherit',
					'post_type'      => 'attachment',
					'post_mime_type' => 'image',
					'order'          => $atts['order'],
					'orderby'        => $orderby,
				)
			);
		}

		if ( ! empty( $attachments ) ) {
			foreach ( $attachments as $id => $attachment ) {
				$link = isset( $attr['link'] ) && 'file' === $attr['link']
					? wp_get_attachment_link( $id, $size, false, false )
					: wp_get_attachment_link( $id, $size, true, false );
				// phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
				if ( $captiontag && trim( $attachment->post_excerpt ) ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
					$output .= "<div class='wp-caption aligncenter'>$link
						<p class='wp-caption-text'>" . wptexturize( $attachment->post_excerpt ) . '</p>
						</div>';
				} else {
					$output .= $link . ' ';
				}
				// phpcs:enable VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			}
		}
	}

	/**
	 * Returns attachment object.
	 *
	 * @param object - $attachment attachment row.
	 *
	 * @return object
	 */
	public function get_attachment( $attachment ) {
		$metadata = wp_get_attachment_metadata( $attachment->ID );

		$result = array(
			'ID'        => (int) $attachment->ID,
			'URL'       => (string) wp_get_attachment_url( $attachment->ID ),
			'guid'      => (string) $attachment->guid,
			'mime_type' => (string) $attachment->post_mime_type,
			'width'     => (int) isset( $metadata['width'] ) ? $metadata['width'] : 0,
			'height'    => (int) isset( $metadata['height'] ) ? $metadata['height'] : 0,
		);

		if ( isset( $metadata['duration'] ) ) {
			$result['duration'] = (int) $metadata['duration'];
		}

		return (object) apply_filters( 'get_attachment', $result );
	}

	/**
	 * Get post-specific user capabilities
	 *
	 * @param WP_Post $post - the WP_Post object.
	 *
	 * @return array - array of post-level permissions; 'publish_post', 'delete_post', 'edit_post'
	 */
	public function get_current_user_capabilities( $post ) {
		return array(
			'publish_post' => current_user_can( 'publish_post', $post->ID ),
			'delete_post'  => current_user_can( 'delete_post', $post->ID ),
			'edit_post'    => current_user_can( 'edit_post', $post->ID ),
		);
	}

	/**
	 * Get post ID by name
	 *
	 * Attempts to match name on post title and page path
	 *
	 * @param string $name - the name of the post.
	 *
	 * @return int|object Post ID on success, WP_Error object on failure
	 **/
	protected function get_post_id_by_name( $name ) {
		$name = sanitize_title( $name );

		if ( ! $name ) {
			return new WP_Error( 'invalid_post', 'Invalid post', 400 );
		}

		$posts = get_posts(
			array(
				'name'        => $name,
				'numberposts' => 1,
				'post_type'   => $this->_get_whitelisted_post_types(),
			)
		);

		if ( ! $posts || ! isset( $posts[0]->ID ) || ! $posts[0]->ID ) {
			$page = get_page_by_path( $name );

			if ( ! $page ) {
				return new WP_Error( 'unknown_post', 'Unknown post', 404 );
			}

			$post_id = $page->ID;
		} else {
			$post_id = (int) $posts[0]->ID;
		}

		return $post_id;
	}
}
