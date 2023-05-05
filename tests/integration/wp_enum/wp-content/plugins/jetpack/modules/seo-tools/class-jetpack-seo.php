<?php
/**
 * Main class file for the SEO Tools module.
 *
 * @package automattic/jetpack
 */

/**
 * An SEO expert walks into a bar, bars, pub, public house, Irish pub, drinks, beer, wine, liquor, Grey Goose, Cristal...
 */
class Jetpack_SEO {
	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'init' ) );
	}

	/**
	 * Initialization method for Jetpack_SEO.
	 */
	public function init() {
		/**
		 * Can be used to prevent SEO tools from inserting custom meta tags.
		 *
		 * @module seo-tools
		 *
		 * @since 4.4.0
		 *
		 * @param bool true Should Jetpack's SEO Meta Tags be enabled. Defaults to true.
		 */
		if ( apply_filters( 'jetpack_seo_meta_tags_enabled', true ) ) {
			add_action( 'wp_head', array( $this, 'meta_tags' ) );

			// Add support for editing page excerpts in pages, regardless of theme support.
			add_post_type_support( 'page', 'excerpt' );
		}

		/**
		 * Can be used to prevent SEO tools form modifying site titles.
		 *
		 * @module seo-tools
		 *
		 * @since 4.4.0
		 *
		 * @param bool true Should Jetpack SEO modify site titles. Defaults to true.
		 */
		if ( apply_filters( 'jetpack_seo_custom_titles', true ) ) {
			// Overwrite page title with custom SEO meta title for themes that support title-tag.
			add_filter( 'pre_get_document_title', array( 'Jetpack_SEO_Titles', 'get_custom_title' ) );

			// Add overwrite support for themes that don't support title-tag.
			add_filter( 'wp_title', array( 'Jetpack_SEO_Titles', 'get_custom_title' ) );
		}

		add_filter( 'jetpack_open_graph_tags', array( $this, 'set_custom_og_tags' ) );
		Jetpack_SEO_Posts::register_post_meta();
		Jetpack_SEO_Posts::register_gutenberg_extension();
		// Exclude posts with 'jetpack_seo_noindex' set true from the Jetpack sitemap.
		add_filter( 'jetpack_sitemap_skip_post', array( 'Jetpack_SEO_Posts', 'exclude_noindex_posts_from_jetpack_sitemap' ), 10, 2 );
	}

	/**
	 * Helper method to fetch authors.
	 */
	private function get_authors() {
		global $wp_query;

		$authors = array();

		foreach ( $wp_query->posts as $post ) {
			$authors[] = get_the_author_meta( 'display_name', (int) $post->post_author );
		}

		$authors = array_unique( $authors );

		return $authors;
	}

	/**
	 * Constructs open graph tag data.
	 *
	 * @param array $tags Array of tag data.
	 * @return array of tag data.
	 */
	public function set_custom_og_tags( $tags ) {
		$custom_title = Jetpack_SEO_Titles::get_custom_title();

		if ( ! empty( $custom_title ) ) {
			$tags['og:title'] = $custom_title;
		}

		$post_custom_description = Jetpack_SEO_Posts::get_post_custom_description( get_post() );
		$front_page_meta         = Jetpack_SEO_Utils::get_front_page_meta_description();

		if ( class_exists( 'woocommerce' ) && is_shop() ) {
			$shop_page_id = get_option( 'woocommerce_shop_page_id' );
			if ( $shop_page_id ) {
				$post_custom_description = Jetpack_SEO_Posts::get_post_custom_description( get_post( $shop_page_id ) );
			}
		}

		if ( is_front_page() && ! empty( $front_page_meta ) ) {
			$tags['og:description'] = $front_page_meta;
		} elseif ( ! empty( $post_custom_description ) ) {
			$tags['og:description'] = $post_custom_description;
		}

		return $tags;
	}

	/**
	 * Outputs Jetpack's SEO <meta> tags.
	 */
	public function meta_tags() {
		global $wp_query;

		$period   = '';
		$template = '';
		$meta     = array();

		/**
		 * Can be used to specify a list of themes that set their own meta tags.
		 *
		 * If current site is using one of the themes listed as conflicting, inserting Jetpack SEO
		 * meta tags will be prevented.
		 *
		 * @module seo-tools
		 *
		 * @since 4.4.0
		 *
		 * @param array List of conflicted theme names. Defaults to empty array.
		 */
		$conflicted_themes = apply_filters( 'jetpack_seo_meta_tags_conflicted_themes', array() );

		if ( isset( $conflicted_themes[ get_option( 'template' ) ] ) ) {
			return;
		}

		$front_page_meta     = Jetpack_SEO_Utils::get_front_page_meta_description();
		$description         = $front_page_meta ? $front_page_meta : get_bloginfo( 'description' );
		$meta['description'] = trim( $description );

		// Try to target things if we're on a "specific" page of any kind.
		if ( is_singular() ) {
			if ( ! ( is_front_page() && Jetpack_SEO_Utils::get_front_page_meta_description() ) ) {
				$description = Jetpack_SEO_Posts::get_post_description( get_post() );

				if ( $description ) {
					$description         = wp_trim_words(
						strip_shortcodes(
							wp_strip_all_tags( $description, true )
						)
					);
					$meta['description'] = $description;
				}
			}
		} elseif ( is_author() ) {
			$obj = get_queried_object();

			$meta['description'] = sprintf(
				/* translators: first property is an user's display name, the second is the site's title. */
				_x( 'Read all of the posts by %1$s on %2$s', 'Read all of the posts by Author Name on Blog Title', 'jetpack' ),
				isset( $obj->display_name ) ? $obj->display_name : __( 'the author', 'jetpack' ),
				get_bloginfo( 'title' )
			);
		} elseif ( is_tag() || is_category() || is_tax() ) {
			$obj         = get_queried_object();
			$description = '';

			if ( isset( $obj->term_id ) && isset( $obj->taxonomy ) ) {
				$description = get_term_field( 'description', $obj->term_id, $obj->taxonomy, 'raw' );
			}

			if ( ! is_wp_error( $description ) && $description ) {
				$meta['description'] = wp_trim_words( $description );
			} else {
				$authors = $this->get_authors();

				$meta['description'] = wp_sprintf(
					/* translators: %1$s: A post category. %2$l: Post authors. */
					_x( 'Posts about %1$s written by %2$l', 'Posts about Category written by John and Bob', 'jetpack' ),
					single_term_title( '', false ),
					$authors
				);
			}
		} elseif ( is_date() ) {
			if ( is_year() ) {
				$period = get_query_var( 'year' );

				/* translators: %1$s: Number of posts published. %2$l: Post author. %3$s: A year date. */
				$template = _nx(
					'%1$s post published by %2$l in the year %3$s', // Singular.
					'%1$s posts published by %2$l in the year %3$s', // Plural.
					count( $wp_query->posts ), // Number.
					'10 posts published by John in the year 2012', // Context.
					'jetpack'
				);
			} elseif ( is_month() ) {
				$period = gmdate( 'F Y', mktime( 0, 0, 0, get_query_var( 'monthnum' ), 1, get_query_var( 'year' ) ) );

				/* translators: %1$s: Number of posts published. %2$l: Post author. %3$s: A month/year date. */
				$template = _nx(
					'%1$s post published by %2$l during %3$s', // Singular.
					'%1$s posts published by %2$l during %3$s', // Plural.
					count( $wp_query->posts ), // Number.
					'10 posts publishes by John during May 2012', // Context.
					'jetpack'
				);
			} elseif ( is_day() ) {
				$period = gmdate(
					'F j, Y',
					mktime( 0, 0, 0, get_query_var( 'monthnum' ), get_query_var( 'day' ), get_query_var( 'year' ) )
				);

				/* translators: %1$s: Number of posts published. %2$l: Post author. %3$s: A month/day/year date. */
				$template = _nx(
					'%1$s post published by %2$l on %3$s', // Singular.
					'%1$s posts published by %2$l on %3$s', // Plural.
					count( $wp_query->posts ), // Number.
					'10 posts published by John on May 30, 2012', // Context.
					'jetpack'
				);
			}

			$authors             = $this->get_authors();
			$meta['description'] = wp_sprintf( $template, count( $wp_query->posts ), $authors, $period );
		}

		$mark_as_noindex = Jetpack_SEO_Posts::get_post_noindex_setting( get_post() );
		if ( $mark_as_noindex ) {
			$meta['robots'] = 'noindex';
		}

		/**
		 * Can be used to edit the default SEO tools meta tags.
		 *
		 * @module seo-tools
		 *
		 * @since 4.4.0
		 *
		 * @param array Array that consists of meta name and meta content pairs.
		 */
		$meta = apply_filters( 'jetpack_seo_meta_tags', $meta );

		// Output them.
		foreach ( $meta as $name => $content ) {
			if ( ! empty( $content ) ) {
				echo '<meta name="' . esc_attr( $name ) . '" content="' . esc_attr( $content ) . '" />' . "\n";
			}
		}
	}
}
