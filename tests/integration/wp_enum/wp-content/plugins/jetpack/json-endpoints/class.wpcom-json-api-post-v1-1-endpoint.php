<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

/**
 * Post v1_1 Endpoint class.
 */
abstract class WPCOM_JSON_API_Post_v1_1_Endpoint extends WPCOM_JSON_API_Endpoint { // phpcs:ignore PEAR.NamingConventions.ValidClassName.Invalid, Generic.Classes.OpeningBraceSameLine.ContentAfterBrace
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
		'discussion'       => '(object) Hash of discussion options for the post',
		'likes_enabled'    => '(bool) Is the post open to likes?',
		'sharing_enabled'  => '(bool) Should sharing buttons show on this post?',
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
		'page_template'    => '(string) (Pages Only) The page template this page is using.',
		'publicize_URLs'   => '(array:URL) Array of Twitter and Facebook URLs published by this post.',
		'terms'            => '(object) Hash of taxonomy names mapping to a hash of terms keyed by term name.',
		'tags'             => '(object:tag) Hash of tags (keyed by tag name) applied to the post.',
		'categories'       => '(object:category) Hash of categories (keyed by category name) applied to the post.',
		'attachments'      => '(object:attachment) Hash of post attachments (keyed by attachment ID). Returns the most recent 20 attachments. Use the `/sites/$site/media` endpoint to query the attachments beyond the default of 20 that are returned here.',
		'attachment_count' => '(int) The total number of attachments for this post. Use the `/sites/$site/media` endpoint to query the attachments beyond the default of 20 that are returned here.',
		'metadata'         => '(array) Array of post metadata keys and values. All unprotected meta keys are available by default for read requests. Both unprotected and protected meta keys are available for authenticated requests with access. Protected meta keys can be made available with the <code>rest_api_allowed_public_metadata</code> filter.',
		'meta'             => '(object) API result meta data',
		'capabilities'     => '(object) List of post-specific permissions for the user; publish_post, edit_post, delete_post',
		'revisions'        => '(array) List of post revision IDs. Only available for posts retrieved with context=edit.',
		'other_URLs'       => '(object) List of URLs for this post. Permalink and slug suggestions.',
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
	 * Get a post by a specified field and value
	 *
	 * @param string $field - the field.
	 * @param string $field_value - the field value.
	 * @param string $context Post use context (e.g. 'display').
	 *
	 * @return array|WP_Error Post
	 **/
	public function get_post_by( $field, $field_value, $context = 'display' ) {

		// validate input
		if ( ! in_array( $field, array( 'ID', 'name' ), true ) ) {
			return new WP_Error( 'invalid_field', 'Invalid API FIELD', 400 );
		}

		if ( ! in_array( $context, array( 'display', 'edit' ), true ) ) {
			return new WP_Error( 'invalid_context', 'Invalid API CONTEXT', 400 );
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

		// fetch SAL post
		$post = $this->get_sal_post_by( $field, $field_value, $context );

		if ( is_wp_error( $post ) ) {
			return $post;
		}

		$GLOBALS['post'] = $post; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		// TODO: not sure where this one should go
		if ( 'display' === $context ) {
			setup_postdata( $post );
		}

		$keys_to_render = array_keys( $this->post_object_format );
		if ( isset( $this->api->query['fields'] ) ) {
			$limit_to_fields = array_map( 'trim', explode( ',', $this->api->query['fields'] ) );
			$keys_to_render  = array_intersect( $keys_to_render, $limit_to_fields );
		}

		// always include some keys because processors require it to validate access
		$keys_to_render = array_unique( array_merge( $keys_to_render, array( 'type', 'status', 'password' ) ) );

		$response = $this->render_response_keys( $post, $context, $keys_to_render );

		unset( $GLOBALS['post'] );

		return $response;
	}

	/**
	 * Get SAL post by a specified field and value
	 *
	 * @param string $field - the field.
	 * @param string $field_value - the field value.
	 * @param string $context Post use context (e.g. 'display').
	 *
	 * @return SAL_Post|WP_Error Post
	 **/
	protected function get_sal_post_by( $field, $field_value, $context ) {
		global $blog_id;

		$site = $this->get_platform()->get_site( $blog_id );

		$post = ( $field === 'name' ) ?
			$site->get_post_by_name( $field_value, $context ) :
			$site->get_post_by_id( $field_value, $context );

		return $post;
	}

	/**
	 * Render the response keys.
	 *
	 * @param object $post - the post.
	 * @param string $context Post use context (e.g. 'display').
	 * @param array  $keys - the keys.
	 *
	 * @return array
	 */
	private function render_response_keys( $post, $context, $keys ) {
		$response = array();
		foreach ( $keys as $key ) {
			switch ( $key ) {
				case 'ID':
					// explicitly cast all output
					$response[ $key ] = (int) $post->ID;
					break;
				case 'site_ID':
					$response[ $key ] = $post->site->get_id();
					break;
				case 'author':
					$response[ $key ] = $post->get_author();
					break;
				case 'date':
					$response[ $key ] = $post->get_date();
					break;
				case 'modified':
					$response[ $key ] = $post->get_modified_date();
					break;
				case 'title':
					$response[ $key ] = $post->get_title();
					break;
				case 'URL':
					$response[ $key ] = $post->get_url();
					break;
				case 'short_URL':
					$response[ $key ] = $post->get_shortlink();
					break;
				case 'content':
					$response[ $key ] = $post->get_content();
					break;
				case 'excerpt':
					$response[ $key ] = $post->get_excerpt();
					break;
				case 'status':
					$response[ $key ] = $post->get_status();
					break;
				case 'sticky':
					$response[ $key ] = $post->is_sticky();
					break;
				case 'slug':
					$response[ $key ] = $post->get_slug();
					break;
				case 'guid':
					$response[ $key ] = $post->get_guid();
					break;
				case 'password':
					$response[ $key ] = $post->get_password();
					break;
				/** (object|false) */
				case 'parent':
					$response[ $key ] = $post->get_parent();
					break;
				case 'type':
					$response[ $key ] = $post->get_type();
					break;
				case 'discussion':
					$response[ $key ] = $post->get_discussion();
					break;
				case 'likes_enabled':
					$response[ $key ] = $post->is_likes_enabled();
					break;
				case 'sharing_enabled':
					$response[ $key ] = $post->is_sharing_enabled();
					break;
				case 'like_count':
					$response[ $key ] = $post->get_like_count();
					break;
				case 'i_like':
					$response[ $key ] = $post->is_liked();
					break;
				case 'is_reblogged':
					$response[ $key ] = $post->is_reblogged();
					break;
				case 'is_following':
					$response[ $key ] = $post->is_following();
					break;
				case 'global_ID':
					$response[ $key ] = $post->get_global_id();
					break;
				case 'featured_image':
					$response[ $key ] = $post->get_featured_image();
					break;
				case 'post_thumbnail':
					$response[ $key ] = $post->get_post_thumbnail();
					break;
				case 'format':
					$response[ $key ] = $post->get_format();
					break;
				/** (object|false) */
				case 'geo':
					$response[ $key ] = $post->get_geo();
					break;
				case 'menu_order':
					$response[ $key ] = $post->get_menu_order();
					break;
				case 'page_template':
					$response[ $key ] = $post->get_page_template();
					break;
				case 'publicize_URLs':
					$response[ $key ] = $post->get_publicize_urls();
					break;
				case 'terms':
					$response[ $key ] = $post->get_terms();
					break;
				case 'tags':
					$response[ $key ] = $post->get_tags();
					break;
				case 'categories':
					$response[ $key ] = $post->get_categories();
					break;
				case 'attachments':
					list( $attachments, $attachment_count ) = $post->get_attachments_and_count();
					$response[ $key ]                       = $attachments;
					$response['attachment_count']           = $attachment_count;
					break;
				/** (array|false) */
				case 'metadata':
					$response[ $key ] = $post->get_metadata();
					break;
				case 'meta':
					$response[ $key ] = $post->get_meta();
					break;
				case 'capabilities':
					$response[ $key ] = $post->get_current_user_capabilities();
					break;
				case 'revisions':
					$revisions = $post->get_revisions();
					if ( $revisions ) {
						$response[ $key ] = $revisions;
					}
					break;
				case 'other_URLs':
					$response[ $key ] = $post->get_other_urls();
					break;
			}
		}

		return $response;
	}

	/**
	 * Filter respnse.
	 *
	 * @param array $response - the response.
	 * @return array Filtered response.
	 */
	public function filter_response( $response ) {

		// Do minimal processing if the caller didn't request it
		if ( ! isset( $_REQUEST['meta_fields'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- we're not making any changes to the site.
			return $response;
		}

		// Retrieve an array of field paths, such as: [`autosave.modified`, `autosave.post_ID`]
		$fields = explode( ',', sanitize_text_field( wp_unslash( $_REQUEST['meta_fields'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- we're not making any changes to the site.

		foreach ( $response['posts'] as $post ) {

			if ( ! isset( $post['meta'] ) || ! isset( $post['meta']->data ) || ( ! is_array( $post['meta']->data ) && ! is_object( $post['meta']->data ) ) ) {
				continue;
			}

			$newmeta = array();
			foreach ( $post['meta']->data as $field_key => $field_value ) {

				foreach ( $field_value as $subfield_key => $subfield_value ) {
					$key_path = $field_key . '.' . $subfield_key;

					if ( in_array( $key_path, $fields, true ) ) {
						$newmeta[ $field_key ][ $subfield_key ] = $subfield_value;
					}
				}
			}

			$post['meta']->data = $newmeta;
		}

		return $response;
	}

	/**
	 * Gets the blog post.
	 *
	 * @param int    $blog_id - the blog ID.
	 * @param int    $post_id - the post ID.
	 * @param string $context - the context.
	 *
	 * @return array|bool|WP_Error
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
}
