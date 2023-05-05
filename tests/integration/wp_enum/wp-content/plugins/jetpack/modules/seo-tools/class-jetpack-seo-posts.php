<?php
/**
 * Class containing utility static methods for managing SEO options for Posts and Pages.
 *
 * @package automattic/jetpack
 */

/**
 * Provides static utility methods for managing SEO options for Posts and Pages.
 */
class Jetpack_SEO_Posts {
	/**
	 * Key of the post meta values that will be used to store post custom data.
	 */
	const DESCRIPTION_META_KEY = 'advanced_seo_description';
	const HTML_TITLE_META_KEY  = 'jetpack_seo_html_title';
	const NOINDEX_META_KEY     = 'jetpack_seo_noindex';
	const POST_META_KEYS_ARRAY = array(
		self::DESCRIPTION_META_KEY,
		self::HTML_TITLE_META_KEY,
		self::NOINDEX_META_KEY,
	);

	/**
	 * Build meta description for post SEO.
	 *
	 * @param WP_Post|null $post Source of data for custom description.
	 *
	 * @return string Post description or empty string.
	 */
	public static function get_post_description( $post = null ) {
		$post = get_post( $post );
		if ( ! ( $post instanceof WP_Post ) ) {
			return '';
		}

		if ( post_password_required() || ! is_singular() ) {
			return '';
		}

		// Business users can overwrite the description.
		$custom_description = self::get_post_custom_description( $post );

		if ( ! empty( $custom_description ) ) {
			return $custom_description;
		}

		if ( ! empty( $post->post_excerpt ) ) {
			return $post->post_excerpt;
		}

		return $post->post_content;
	}

	/**
	 * Returns post's custom meta description if it is set, and if
	 * SEO tools are enabled for current blog.
	 *
	 * @param WP_Post|null $post Source of data for custom description.
	 *
	 * @return string Custom description or empty string
	 */
	public static function get_post_custom_description( $post = null ) {
		$post = get_post( $post );
		if ( ! ( $post instanceof WP_Post ) ) {
			return '';
		}

		$custom_description = get_post_meta( $post->ID, self::DESCRIPTION_META_KEY, true );

		if ( empty( $custom_description ) || ! Jetpack_SEO_Utils::is_enabled_jetpack_seo() ) {
			return '';
		}

		return $custom_description;
	}

	/**
	 * Gets a custom HTML title for a post if one is set, and if
	 * SEO tools are enabled for the current blog.
	 *
	 * @param WP_Post|null $post Source of data for the custom HTML title.
	 *
	 * @return string Custom HTML title or an empty string if not set.
	 */
	public static function get_post_custom_html_title( $post = null ) {
		$post = get_post( $post );
		if ( ! ( $post instanceof WP_Post ) ) {
			return '';
		}

		$custom_html_title = get_post_meta( $post->ID, self::HTML_TITLE_META_KEY, true );

		if ( empty( $custom_html_title ) || ! Jetpack_SEO_Utils::is_enabled_jetpack_seo() ) {
			return '';
		}

		return $custom_html_title;
	}

	/**
	 * Gets the `jetpack_seo_noindex` setting for a post, if
	 * SEO tools are enabled for the current blog.
	 *
	 * @param WP_Post|null $post Provided post or defaults to the global post.
	 *
	 * @return bool True if post should be marked as noindex, false otherwise.
	 */
	public static function get_post_noindex_setting( $post = null ) {
		$post = get_post( $post );
		if ( ! ( $post instanceof WP_Post ) ) {
			return false;
		}

		$mark_as_noindex = get_post_meta( $post->ID, self::NOINDEX_META_KEY, true );

		if ( empty( $mark_as_noindex ) || ! Jetpack_SEO_Utils::is_enabled_jetpack_seo() ) {
			return false;
		}

		return (bool) $mark_as_noindex;
	}

	/**
	 * Filter callback for `jetpack_sitemap_skip_post`; if a post has `jetpack_seo_noindex` set to true,
	 * then exclude that post from the Jetpack sitemap.
	 *
	 * @param bool    $skip Whether to skip the post in the sitemap.
	 * @param WP_Post $post The post to check.
	 *
	 * @return bool
	 */
	public static function exclude_noindex_posts_from_jetpack_sitemap( $skip, $post ) {
		$exclude = self::get_post_noindex_setting( $post );
		if ( $exclude ) {
			$skip = true;
		}
		return $skip;
	}

	/**
	 * Registers the following meta keys for use in the REST API:
	 *   - self::DESCRIPTION_META_KEY
	 *   - self::HTML_TITLE_META_KEY
	 */
	public static function register_post_meta() {
		$description_args = array(
			'type'         => 'string',
			'description'  => __( 'Custom post description to be used in HTML <meta /> tag.', 'jetpack' ),
			'single'       => true,
			'default'      => '',
			'show_in_rest' => array(
				'name' => self::DESCRIPTION_META_KEY,
			),
		);

		$html_title_args = array(
			'type'         => 'string',
			'description'  => __( 'Custom title to be used in HTML <title /> tag.', 'jetpack' ),
			'single'       => true,
			'default'      => '',
			'show_in_rest' => array(
				'name' => self::HTML_TITLE_META_KEY,
			),
		);

		$noindex_args = array(
			'type'         => 'boolean',
			'description'  => __( 'Whether to hide the post from search engines and the Jetpack sitemap.', 'jetpack' ),
			'single'       => true,
			'default'      => false,
			'show_in_rest' => array(
				'name' => self::NOINDEX_META_KEY,
			),
		);

		register_meta( 'post', self::DESCRIPTION_META_KEY, $description_args );
		register_meta( 'post', self::HTML_TITLE_META_KEY, $html_title_args );
		register_meta( 'post', self::NOINDEX_META_KEY, $noindex_args );
	}

	/**
	 * Register the Advanced SEO Gutenberg extension
	 */
	public static function register_gutenberg_extension() {
		if ( Jetpack_SEO_Utils::is_enabled_jetpack_seo() ) {
			Jetpack_Gutenberg::set_extension_available( 'jetpack-seo' );
		} else {
			Jetpack_Gutenberg::set_extension_unavailable( 'jetpack-seo', 'jetpack_seo_disabled' );
		}
	}
}
