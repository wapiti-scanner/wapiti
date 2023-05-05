<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Jetpack Twitter Card handling.
 *
 * @package automattic/jetpack
 */

/**
 * Twitter Cards
 *
 * Hooks onto the Open Graph protocol and extends it by adding only the tags
 * we need for twitter cards.
 *
 * @see /wp-content/blog-plugins/open-graph.php
 * @see https://dev.twitter.com/cards/overview
 */
class Jetpack_Twitter_Cards {

	/**
	 * Adds Twitter Card tags.
	 *
	 * @param array $og_tags Existing OG tags.
	 *
	 * @return array OG tags inclusive of Twitter Card output.
	 */
	public static function twitter_cards_tags( $og_tags ) {
		global $post;
		$post_id = ( $post instanceof WP_Post ) ? $post->ID : null;

		/**
		 * Maximum alt text length.
		 *
		 * @see https://developer.twitter.com/en/docs/tweets/optimize-with-cards/overview/summary-card-with-large-image.html
		 */
		$alt_length = 420;

		if ( post_password_required() ) {
			return $og_tags;
		}

		/** This action is documented in class.jetpack.php */
		if ( apply_filters( 'jetpack_disable_twitter_cards', false ) ) {
			return $og_tags;
		}

		/*
		 * These tags apply to any page (home, archives, etc).
		 */

		// If we have information on the author/creator, then include that as well.
		if ( ! empty( $post ) && ! empty( $post->post_author ) ) {
			/** This action is documented in modules/sharedaddy/sharing-sources.php */
			$handle = apply_filters( 'jetpack_sharing_twitter_via', '', $post_id );
			if ( ! empty( $handle ) && ! self::is_default_site_tag( $handle ) ) {
				$og_tags['twitter:creator'] = self::sanitize_twitter_user( $handle );
			}
		}

		$site_tag = self::site_tag();
		/** This action is documented in modules/sharedaddy/sharing-sources.php */
		$site_tag = apply_filters( 'jetpack_sharing_twitter_via', $site_tag, ( is_singular() ? $post_id : null ) );
		/** This action is documented in modules/sharedaddy/sharing-sources.php */
		$site_tag = apply_filters( 'jetpack_twitter_cards_site_tag', $site_tag, $og_tags );
		if ( ! empty( $site_tag ) ) {
			$og_tags['twitter:site'] = self::sanitize_twitter_user( $site_tag );
		}

		if ( ! is_singular() || ! empty( $og_tags['twitter:card'] ) ) {
			/**
			 * Filter the default Twitter card image, used when no image can be found in a post.
			 *
			 * @module sharedaddy, publicize
			 *
			 * @since 5.9.0
			 *
			 * @param string $str Default image URL.
			 */
			$image = apply_filters( 'jetpack_twitter_cards_image_default', '' );
			if ( ! empty( $image ) ) {
				$og_tags['twitter:image'] = $image;
			}

			return $og_tags;
		}

		$the_title = get_the_title();
		if ( ! $the_title ) {
			$the_title = get_bloginfo( 'name' );
		}
		$og_tags['twitter:text:title'] = $the_title;

		/*
		 * The following tags only apply to single pages.
		 */

		$card_type = 'summary';

		// Try to give priority to featured images.
		if ( class_exists( 'Jetpack_PostImages' ) && ! empty( $post_id ) ) {
			$post_image = Jetpack_PostImages::get_image(
				$post_id,
				array(
					'width'  => 144,
					'height' => 144,
				)
			);
			if ( ! empty( $post_image ) && is_array( $post_image ) ) {
				// 4096 is the maximum size for an image per https://developer.twitter.com/en/docs/tweets/optimize-with-cards/overview/summary .
				if (
					isset( $post_image['src_width'], $post_image['src_height'] )
					&& (int) $post_image['src_width'] <= 4096
					&& (int) $post_image['src_height'] <= 4096
				) {
					// 300x157 is the minimum size for a summary_large_image per https://developer.twitter.com/en/docs/tweets/optimize-with-cards/overview/summary-card-with-large-image .
					if ( (int) $post_image['src_width'] >= 300 && (int) $post_image['src_height'] >= 157 ) {
						$card_type                = 'summary_large_image';
						$og_tags['twitter:image'] = esc_url( add_query_arg( 'w', 640, $post_image['src'] ) );
					} else {
						$og_tags['twitter:image'] = esc_url( add_query_arg( 'w', 144, $post_image['src'] ) );
					}

					// Add the alt tag if we have one.
					if ( ! empty( $post_image['alt_text'] ) ) {
						// Shorten it if it is too long.
						if ( strlen( $post_image['alt_text'] ) > $alt_length ) {
							$og_tags['twitter:image:alt'] = esc_attr( mb_substr( $post_image['alt_text'], 0, $alt_length ) . '…' );
						} else {
							$og_tags['twitter:image:alt'] = esc_attr( $post_image['alt_text'] );
						}
					}
				}
			}
		}

		// Only proceed with media analysis if a featured image has not superseded it already.
		if ( empty( $og_tags['twitter:image'] ) && empty( $og_tags['twitter:image:src'] ) ) {
			if ( ! class_exists( 'Jetpack_Media_Summary' ) ) {
				require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.media-summary.php';
			}

			// Test again, class should already be auto-loaded in Jetpack.
			// If not, skip extra media analysis and stick with a summary card.
			if ( class_exists( 'Jetpack_Media_Summary' ) && ! empty( $post_id ) ) {
				$extract = Jetpack_Media_Summary::get( $post_id );

				if ( 'gallery' === $extract['type'] ) {
					list( $og_tags, $card_type ) = self::twitter_cards_define_type_based_on_image_count( $og_tags, $extract );
				} elseif ( 'video' === $extract['type'] ) {
					// Leave as summary, but with large pict of poster frame (we know those comply to Twitter's size requirements).
					$card_type                = 'summary_large_image';
					$og_tags['twitter:image'] = esc_url( add_query_arg( 'w', 640, $extract['image'] ) );
				} else {
					list( $og_tags, $card_type ) = self::twitter_cards_define_type_based_on_image_count( $og_tags, $extract );
				}
			}
		}

		$og_tags['twitter:card'] = $card_type;

		// Make sure we have a description for Twitter, their validator isn't happy without some content (single space not valid).
		if ( ! isset( $og_tags['og:description'] ) || '' === trim( $og_tags['og:description'] ) || __( 'Visit the post for more.', 'jetpack' ) === $og_tags['og:description'] ) { // empty( trim( $og_tags['og:description'] ) ) isn't valid php.
			$has_creator = ( ! empty( $og_tags['twitter:creator'] ) && '@wordpressdotcom' !== $og_tags['twitter:creator'] ) ? true : false;
			if ( ! empty( $extract ) && 'video' === $extract['type'] ) { // use $extract['type'] since $card_type is 'summary' for video posts.
				/* translators: %s is the post author */
				$og_tags['twitter:description'] = ( $has_creator ) ? sprintf( __( 'Video post by %s.', 'jetpack' ), $og_tags['twitter:creator'] ) : __( 'Video post.', 'jetpack' );
			} else {
				/* translators: %s is the post author */
				$og_tags['twitter:description'] = ( $has_creator ) ? sprintf( __( 'Post by %s.', 'jetpack' ), $og_tags['twitter:creator'] ) : __( 'Visit the post for more.', 'jetpack' );
			}
		}

		if ( empty( $og_tags['twitter:image'] ) && empty( $og_tags['twitter:image:src'] ) ) {
			/** This action is documented in class.jetpack-twitter-cards.php */
			$image = apply_filters( 'jetpack_twitter_cards_image_default', '' );
			if ( ! empty( $image ) ) {
				$og_tags['twitter:image'] = $image;
			}
		}

		return $og_tags;
	}

	/**
	 * Sanitize the Twitter user by normalizing the @.
	 *
	 * @param string $str Twitter user value.
	 *
	 * @return string Twitter user value.
	 */
	public static function sanitize_twitter_user( $str ) {
		return '@' . preg_replace( '/^@/', '', $str );
	}

	/**
	 * Determines if a site tag is one of the default WP.com/Jetpack ones.
	 *
	 * @param string $site_tag Site tag.
	 *
	 * @return bool True if the default site tag is being used.
	 */
	public static function is_default_site_tag( $site_tag ) {
		return in_array( $site_tag, array( '@wordpressdotcom', '@jetpack', 'wordpressdotcom', 'jetpack' ), true );
	}

	/**
	 * Give priority to the creator tag if using the default site tag.
	 *
	 * @param string $site_tag Site tag.
	 * @param array  $og_tags OG tags.
	 *
	 * @return string Site tag.
	 */
	public static function prioritize_creator_over_default_site( $site_tag, $og_tags = array() ) {
		if ( ! empty( $og_tags['twitter:creator'] ) && self::is_default_site_tag( $site_tag ) ) {
			return $og_tags['twitter:creator'];
		}
		return $site_tag;
	}

	/**
	 * Define the Twitter Card type based on image count.
	 *
	 * @param array $og_tags Existing OG tags.
	 * @param array $extract Result of the Image Extractor class.
	 *
	 * @return array
	 */
	public static function twitter_cards_define_type_based_on_image_count( $og_tags, $extract ) {
		$card_type = 'summary';
		$img_count = $extract['count']['image'];

		if ( empty( $img_count ) ) {

			// No images, use Blavatar as a thumbnail for the summary type.
			if ( function_exists( 'blavatar_domain' ) ) {
				$blavatar_domain = blavatar_domain( site_url() );
				if ( blavatar_exists( $blavatar_domain ) ) {
					$og_tags['twitter:image'] = blavatar_url( $blavatar_domain, 'img', 240 );
				}
			}

			// Second fall back, Site Logo.
			if ( empty( $og_tags['twitter:image'] ) && ( function_exists( 'jetpack_has_site_logo' ) && jetpack_has_site_logo() ) ) {
				$og_tags['twitter:image'] = jetpack_get_site_logo( 'url' );
			}

			// Third fall back, Site Icon.
			if ( empty( $og_tags['twitter:image'] ) && has_site_icon() ) {
				$og_tags['twitter:image'] = get_site_icon_url( '240' );
			}

			// Not falling back on Gravatar, because there's no way to know if we end up with an auto-generated one.

		} elseif ( $img_count && ( 'image' === $extract['type'] || 'gallery' === $extract['type'] ) ) {
			// Test for $extract['type'] to limit to image and gallery, so we don't send a potential fallback image like a Gravatar as a photo post.
			$card_type                = 'summary_large_image';
			$og_tags['twitter:image'] = esc_url( add_query_arg( 'w', 1400, ( empty( $extract['images'] ) ) ? $extract['image'] : $extract['images'][0]['url'] ) );
		}

		return array( $og_tags, $card_type );
	}

	/**
	 * Updates the Twitter Card output.
	 *
	 * @param string $og_tag A single OG tag.
	 *
	 * @return string Result of the OG tag.
	 */
	public static function twitter_cards_output( $og_tag ) {
		return ( false !== strpos( $og_tag, 'twitter:' ) ) ? preg_replace( '/property="([^"]+)"/', 'name="\1"', $og_tag ) : $og_tag;
	}

	/**
	 * Adds settings section and field.
	 */
	public static function settings_init() {
		add_settings_section( 'jetpack-twitter-cards-settings', 'Twitter Cards', '__return_false', 'sharing' );
		add_settings_field(
			'jetpack-twitter-cards-site-tag',
			__( 'Twitter Site Tag', 'jetpack' ),
			array( __CLASS__, 'settings_field' ),
			'sharing',
			'jetpack-twitter-cards-settings',
			array(
				'label_for' => 'jetpack-twitter-cards-site-tag',
			)
		);
	}

	/**
	 * Add global sharing options.
	 */
	public static function sharing_global_options() {
		do_settings_fields( 'sharing', 'jetpack-twitter-cards-settings' );
	}

	/**
	 * Get the Twitter Via tag.
	 *
	 * @return string Twitter via tag.
	 */
	public static function site_tag() {
		$site_tag = ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ?
			trim( get_option( 'twitter_via' ) ) :
			Jetpack_Options::get_option_and_ensure_autoload( 'jetpack-twitter-cards-site-tag', '' );
		if ( empty( $site_tag ) ) {
			/** This action is documented in modules/sharedaddy/sharing-sources.php */
			return apply_filters( 'jetpack_sharing_twitter_via', '', null );
		}
		return $site_tag;
	}

	/**
	 * Output the settings field.
	 */
	public static function settings_field() {
		wp_nonce_field( 'jetpack-twitter-cards-settings', 'jetpack_twitter_cards_nonce', false );
		?>
		<input type="text" id="jetpack-twitter-cards-site-tag" class="regular-text" name="jetpack-twitter-cards-site-tag" value="<?php echo esc_attr( get_option( 'jetpack-twitter-cards-site-tag' ) ); ?>" />
		<p class="description" style="width: auto;"><?php esc_html_e( 'The Twitter username of the owner of this site\'s domain.', 'jetpack' ); ?></p>
		<?php
	}

	/**
	 * Validate the settings submission.
	 */
	public static function settings_validate() {
		if ( isset( $_POST['jetpack_twitter_cards_nonce'] ) && wp_verify_nonce( $_POST['jetpack_twitter_cards_nonce'], 'jetpack-twitter-cards-settings' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			update_option( 'jetpack-twitter-cards-site-tag', isset( $_POST['jetpack-twitter-cards-site-tag'] ) ? trim( ltrim( wp_strip_all_tags( filter_var( wp_unslash( $_POST['jetpack-twitter-cards-site-tag'] ) ) ), '@' ) ) : '' );
		}
	}

	/**
	 * Initiates the class.
	 */
	public static function init() {
		add_filter( 'jetpack_open_graph_tags', array( __CLASS__, 'twitter_cards_tags' ), 11 ); // $priority=11: this should hook into jetpack_open_graph_tags after 'class.jetpack-seo.php' has done so.
		add_filter( 'jetpack_open_graph_output', array( __CLASS__, 'twitter_cards_output' ) );
		add_filter( 'jetpack_twitter_cards_site_tag', array( __CLASS__, 'site_tag' ), -99 );
		add_filter( 'jetpack_twitter_cards_site_tag', array( __CLASS__, 'prioritize_creator_over_default_site' ), 99, 2 );
		add_action( 'admin_init', array( __CLASS__, 'settings_init' ) );
		add_action( 'sharing_global_options', array( __CLASS__, 'sharing_global_options' ) );
		add_action( 'sharing_admin_update', array( __CLASS__, 'settings_validate' ) );
	}
}

Jetpack_Twitter_Cards::init();
