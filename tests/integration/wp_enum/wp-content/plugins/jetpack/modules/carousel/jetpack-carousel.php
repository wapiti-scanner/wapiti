<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module: Jetpack Carousel
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Stats\Options as Stats_Options;
use Automattic\Jetpack\Status;
/**
 * Jetpack_Carousel class.
 */
class Jetpack_Carousel {
	/**
	 * Defines Carousel pre-built widths
	 *
	 * @var array
	 */
	public $prebuilt_widths = array( 370, 700, 1000, 1200, 1400, 2000 );

	/**
	 * Localization strings and other data for the JavaScript
	 *
	 * @var array
	 */
	public $localize_strings;

	/**
	 * Represents whether or not this is the first load of Carousel on a page. Default is true.
	 *
	 * @var bool
	 */
	public $first_run = true;

	/**
	 * Determines whether or not to set in the gallery. Default is false.
	 *
	 * @deprecated since 10.8
	 *
	 * @var bool
	 */
	public $in_gallery = false;

	/**
	 * Determines whether the Jetpack class and method exists. Default is true.
	 *
	 * @var bool
	 */
	public $in_jetpack = true;

	/**
	 * Determines whether or not a single image gallery is enabled. Default is false.
	 *
	 * @var bool
	 */
	public $single_image_gallery_enabled = false;

	/**
	 * Determines whether images that link to themselves should be replaced with a one image gallery. Default is false.
	 *
	 * @var bool
	 */
	public $single_image_gallery_enabled_media_file = false;

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'init', array( $this, 'init' ) );
	}

	/**
	 * Initialize class
	 */
	public function init() {
		if ( $this->maybe_disable_jp_carousel() ) {
			return;
		}

		$this->in_jetpack = ( class_exists( 'Jetpack' ) && method_exists( 'Jetpack', 'enable_module_configurable' ) ) ? true : false;

		$this->single_image_gallery_enabled            = ! $this->maybe_disable_jp_carousel_single_images();
		$this->single_image_gallery_enabled_media_file = $this->maybe_enable_jp_carousel_single_images_media_file();

		if ( is_admin() ) {
			// Register the Carousel-related related settings.
			add_action( 'admin_init', array( $this, 'register_settings' ), 5 );
			if ( ! $this->in_jetpack ) {
				if ( 0 === $this->test_1or0_option( get_option( 'carousel_enable_it' ), true ) ) {
					return; // Carousel disabled, abort early, but still register setting so user can switch it back on.
				}
			}
			// If in admin, register the ajax endpoints.
			add_action( 'wp_ajax_get_attachment_comments', array( $this, 'get_attachment_comments' ) );
			add_action( 'wp_ajax_nopriv_get_attachment_comments', array( $this, 'get_attachment_comments' ) );
			add_action( 'wp_ajax_post_attachment_comment', array( $this, 'post_attachment_comment' ) );
			add_action( 'wp_ajax_nopriv_post_attachment_comment', array( $this, 'post_attachment_comment' ) );
		} else {
			if ( ! $this->in_jetpack ) {
				if ( 0 === $this->test_1or0_option( get_option( 'carousel_enable_it' ), true ) ) {
					return; // Carousel disabled, abort early.
				}
			}
			// If on front-end, do the Carousel thang.
			/**
			 * Filter the array of default prebuilt widths used in Carousel.
			 *
			 * @module carousel
			 *
			 * @since 1.6.0
			 *
			 * @param array $this->prebuilt_widths Array of default widths.
			 */
			$this->prebuilt_widths = apply_filters( 'jp_carousel_widths', $this->prebuilt_widths );
			// below: load later than other callbacks hooked it (e.g. 3rd party plugins handling gallery shortcode).
			add_filter( 'post_gallery', array( $this, 'check_if_shortcode_processed_and_enqueue_assets' ), 1000, 2 );
			add_filter( 'post_gallery', array( $this, 'set_in_gallery' ), -1000 );
			add_filter( 'gallery_style', array( $this, 'add_data_to_container' ) );
			add_filter( 'wp_get_attachment_image_attributes', array( $this, 'add_data_to_images' ), 10, 2 );
			add_filter( 'jetpack_tiled_galleries_block_content', array( $this, 'add_data_img_tags_and_enqueue_assets' ) );
			if ( $this->single_image_gallery_enabled ) {
				add_filter( 'the_content', array( $this, 'add_data_img_tags_and_enqueue_assets' ) );
			}

			if (
				! class_exists( 'Jetpack_AMP_Support' )
				|| ! Jetpack_AMP_Support::is_amp_request()
			) {
				add_filter( 'render_block_core/gallery', array( $this, 'filter_gallery_block_render' ), 10, 2 );
				add_filter( 'render_block_jetpack/tiled-gallery', array( $this, 'filter_gallery_block_render' ), 10, 2 );
			}
		}

		if ( $this->in_jetpack ) {
			Jetpack::enable_module_configurable( dirname( __DIR__ ) . '/carousel.php' );
		}
	}

	/**
	 * Returns the value of the applied jp_carousel_maybe_disable filter
	 *
	 * @since 1.6.0
	 *
	 * @return bool - Should Carousel be disabled? Default to false.
	 */
	public function maybe_disable_jp_carousel() {
		/**
		 * Allow third-party plugins or themes to disable Carousel.
		 *
		 * @module carousel
		 *
		 * @since 1.6.0
		 *
		 * @param bool false Should Carousel be disabled? Default to false.
		 */
		return apply_filters( 'jp_carousel_maybe_disable', false );
	}

	/**
	 * Returns the value of the applied jp_carousel_maybe_disable_single_images filter
	 *
	 * @since 4.5.0
	 *
	 * @return bool - Should Carousel be disabled for single images? Default to false.
	 */
	public function maybe_disable_jp_carousel_single_images() {
		/**
		 * Allow third-party plugins or themes to disable Carousel for single images.
		 *
		 * @module carousel
		 *
		 * @since 4.5.0
		 *
		 * @param bool false Should Carousel be disabled for single images? Default to false.
		 */
		return apply_filters( 'jp_carousel_maybe_disable_single_images', false );
	}

	/**
	 * Returns the value of the applied jp_carousel_load_for_images_linked_to_file filter
	 *
	 * @since 4.5.0
	 *
	 * @return bool - Should Carousel be enabled for single images linking to 'Media File'? Default to false.
	 */
	public function maybe_enable_jp_carousel_single_images_media_file() {
		/**
		 * Allow third-party plugins or themes to enable Carousel
		 * for single images linking to 'Media File' (full size image).
		 *
		 * @module carousel
		 *
		 * @since 4.5.0
		 *
		 * @param bool false Should Carousel be enabled for single images linking to 'Media File'? Default to false.
		 */
		return apply_filters( 'jp_carousel_load_for_images_linked_to_file', false );
	}

	/**
	 * Returns the value of the applied jp_carousel_asset_version filter
	 *
	 * @since 1.6.0
	 *
	 * @param string $version Asset version.
	 *
	 * @return string
	 */
	public function asset_version( $version ) {
		/**
		 * Filter the version string used when enqueuing Carousel assets.
		 *
		 * @module carousel
		 *
		 * @since 1.6.0
		 *
		 * @param string $version Asset version.
		 */
		return apply_filters( 'jp_carousel_asset_version', $version );
	}

	/**
	 * Displays a message on top of gallery if carousel has bailed.
	 *
	 * @param string $output Gallery shortcode output.
	 *
	 * @return string Shortcode output with bail message prepended.
	 */
	public function display_bail_message( $output = '' ) {
		$message  = '<div class="jp-carousel-msg"><p>';
		$message .= __( 'Jetpack\'s Carousel has been disabled, because another plugin or your theme is overriding the [gallery] shortcode.', 'jetpack' );
		$message .= '</p></div>';
		// put before gallery output.
		$output = $message . $output;
		return $output;
	}

	/**
	 * Determine whether Carousel is enabled, and adjust filters and enqueue assets accordingly.
	 *
	 * If no other filter hook produced output for the gallery shortcode or something returns true for
	 * the `jp_carousel_force_enable` filter, Carousel is enabled and we queue our assets. Otherwise
	 * it's disabled and we remove some of our subsequent filter hooks.
	 *
	 * @since 1.9.0
	 *
	 * @param string $output Gallery shortcode output.
	 *
	 * @return string Gallery shortcode output.
	 */
	public function check_if_shortcode_processed_and_enqueue_assets( $output ) {
		if (
			class_exists( 'Jetpack_AMP_Support' )
			&& Jetpack_AMP_Support::is_amp_request()
		) {
			return $output;
		}

		if (
			! empty( $output ) &&
			/**
			 * Allow third-party plugins or themes to force-enable Carousel.
			 *
			 * @module carousel
			 *
			 * @since 1.9.0
			 *
			 * @param bool false Should we force enable Carousel? Default to false.
			 */
			! apply_filters( 'jp_carousel_force_enable', false )
		) {
			// Bail because someone is overriding the [gallery] shortcode.
			remove_filter( 'gallery_style', array( $this, 'add_data_to_container' ) );
			remove_filter( 'wp_get_attachment_image_attributes', array( $this, 'add_data_to_images' ) );
			remove_filter( 'the_content', array( $this, 'add_data_img_tags_and_enqueue_assets' ) );
			// Display message that carousel has bailed, if user is super_admin, and if we're not on WordPress.com.
			if (
				is_super_admin() &&
				! ( defined( 'IS_WPCOM' ) && IS_WPCOM )
			) {
				add_filter( 'post_gallery', array( $this, 'display_bail_message' ) );
			}
			return $output;
		}

		/**
		 * Fires when thumbnails are shown in Carousel.
		 *
		 * @module carousel
		 *
		 * @since 1.6.0
		 */
		do_action( 'jp_carousel_thumbnails_shown' );

		$this->enqueue_assets();

		return $output;
	}

	/**
	 * Check if the content of a post uses gallery blocks. To be used by 'the_content' filter.
	 *
	 * @since 6.8.0
	 * @deprecated since 11.3 We now hook into the 'block_render_{block_name}' hook to add markup.
	 *
	 * @param string $content Post content.
	 *
	 * @return string $content Post content.
	 */
	public function check_content_for_blocks( $content ) {
		_deprecated_function( __METHOD__, 'jetpack-11.3' );

		if (
			class_exists( 'Jetpack_AMP_Support' )
			&& Jetpack_AMP_Support::is_amp_request()
		) {
			return $content;
		}

		if ( has_block( 'gallery', $content ) || has_block( 'jetpack/tiled-gallery', $content ) ) {
			$this->enqueue_assets();
			$content = $this->add_data_to_container( $content );
		}

		return $content;
	}

	/**
	 * Enrich the gallery block content using the render_block_{$this->name} filter.
	 * This function is triggered after block render to make sure we track galleries within
	 * reusable blocks.
	 *
	 * @see https://developer.wordpress.org/reference/hooks/render_block_this-name/
	 *
	 * @param string $block_content The rendered HTML for the carousel or gallery block.
	 * @param array  $block         The parsed block details for the block.
	 * @return string The fully-processed HTML for the carousel or gallery block.
	 *
	 * @since 11.3
	 */
	public function filter_gallery_block_render( $block_content, $block ) {
		global $post;

		if ( empty( $block['blockName'] ) || ! in_array( $block['blockName'], array( 'core/gallery', 'jetpack/tiled-gallery' ), true ) ) {
			return $block_content;
		}

		$this->enqueue_assets();

		if ( ! isset( $post ) ) {
			return $block_content;
		}

		$blog_id = (int) get_current_blog_id();

		$extra_data = array(
			'data-carousel-extra' => array(
				'blog_id'   => $blog_id,
				'permalink' => get_permalink( $post->ID ),
			),
		);

		/**
		 * Filter the data added to the Gallery container.
		 *
		 * @module carousel
		 *
		 * @since 1.6.0
		 *
		 * @param array $extra_data Array of data about the site and the post.
		 */
		$extra_data = apply_filters( 'jp_carousel_add_data_to_container', $extra_data );
		$extra_data = (array) $extra_data;

		if ( empty( $extra_data ) ) {
			return $block_content;
		}

		$extra_attributes = implode(
			' ',
			array_map(
				function ( $data_key, $data_values ) {
					return esc_attr( $data_key ) . "='" . wp_json_encode( $data_values ) . "'";
				},
				array_keys( $extra_data ),
				array_values( $extra_data )
			)
		);

		// Add extra attributes to first HTML element (which may have leading whitespace)
		return preg_replace(
			'/^(\s*<(div|ul|figure))/',
			'$1 ' . $extra_attributes . ' ',
			$block_content,
			1
		);
	}

	/**
	 * Enqueueing Carousel assets.
	 */
	public function enqueue_assets() {
		if ( $this->first_run ) {
			wp_enqueue_script(
				'jetpack-carousel',
				Assets::get_file_url_for_environment(
					'_inc/build/carousel/jetpack-carousel.min.js',
					'modules/carousel/jetpack-carousel.js'
				),
				array(),
				$this->asset_version( JETPACK__VERSION ),
				true
			);

			$swiper_library_path = array(
				'url' => Assets::get_file_url_for_environment(
					'_inc/build/carousel/swiper-bundle.min.js',
					'modules/carousel/swiper-bundle.js'
				),
			);
			wp_localize_script( 'jetpack-carousel', 'jetpackSwiperLibraryPath', $swiper_library_path );

			// Note: using  home_url() instead of admin_url() for ajaxurl to be sure  to get same domain on wpcom when using mapped domains (also works on self-hosted).
			// Also: not hardcoding path since there is no guarantee site is running on site root in self-hosted context.
			$is_logged_in         = is_user_logged_in();
			$comment_registration = (int) get_option( 'comment_registration' );
			$require_name_email   = (int) get_option( 'require_name_email' );
			$localize_strings     = array(
				'widths'                          => $this->prebuilt_widths,
				'is_logged_in'                    => $is_logged_in,
				'lang'                            => strtolower( substr( get_locale(), 0, 2 ) ),
				'ajaxurl'                         => set_url_scheme( admin_url( 'admin-ajax.php' ) ),
				'nonce'                           => wp_create_nonce( 'carousel_nonce' ),
				'display_exif'                    => $this->test_1or0_option( Jetpack_Options::get_option_and_ensure_autoload( 'carousel_display_exif', true ) ),
				'display_comments'                => $this->test_1or0_option( Jetpack_Options::get_option_and_ensure_autoload( 'carousel_display_comments', true ) ),
				'single_image_gallery'            => $this->single_image_gallery_enabled,
				'single_image_gallery_media_file' => $this->single_image_gallery_enabled_media_file,
				'background_color'                => $this->carousel_background_color_sanitize( Jetpack_Options::get_option_and_ensure_autoload( 'carousel_background_color', '' ) ),
				'comment'                         => __( 'Comment', 'jetpack' ),
				'post_comment'                    => __( 'Post Comment', 'jetpack' ),
				'write_comment'                   => __( 'Write a Comment...', 'jetpack' ),
				'loading_comments'                => __( 'Loading Comments...', 'jetpack' ),
				'download_original'               => sprintf(
					/* translators: %1s is the full-size image width, and %2s is the height. */
					__( 'View full size <span class="photo-size">%1$s<span class="photo-size-times">&times;</span>%2$s</span>', 'jetpack' ),
					'{0}',
					'{1}'
				),
				'no_comment_text'                 => __( 'Please be sure to submit some text with your comment.', 'jetpack' ),
				'no_comment_email'                => __( 'Please provide an email address to comment.', 'jetpack' ),
				'no_comment_author'               => __( 'Please provide your name to comment.', 'jetpack' ),
				'comment_post_error'              => __( 'Sorry, but there was an error posting your comment. Please try again later.', 'jetpack' ),
				'comment_approved'                => __( 'Your comment was approved.', 'jetpack' ),
				'comment_unapproved'              => __( 'Your comment is in moderation.', 'jetpack' ),
				'camera'                          => __( 'Camera', 'jetpack' ),
				'aperture'                        => __( 'Aperture', 'jetpack' ),
				'shutter_speed'                   => __( 'Shutter Speed', 'jetpack' ),
				'focal_length'                    => __( 'Focal Length', 'jetpack' ),
				'copyright'                       => __( 'Copyright', 'jetpack' ),
				'comment_registration'            => $comment_registration,
				'require_name_email'              => $require_name_email,
				/** This action is documented in core/src/wp-includes/link-template.php */
				'login_url'                       => wp_login_url( apply_filters( 'the_permalink', get_permalink() ) ),
				'blog_id'                         => (int) get_current_blog_id(),
				'meta_data'                       => array( 'camera', 'aperture', 'shutter_speed', 'focal_length', 'copyright' ),
			);

			/**
			 * Handle WP stats for images in full-screen.
			 * Build string with tracking info.
			 */

			/**
			 * Filter if Jetpack should enable stats collection on carousel views
			 *
			 * @module carousel
			 *
			 * @since 4.3.2
			 *
			 * @param bool Enable Jetpack Carousel stat collection. Default false.
			 */
			if ( apply_filters( 'jetpack_enable_carousel_stats', false ) && in_array( 'stats', Jetpack::get_active_modules(), true ) && ! ( new Status() )->is_offline_mode() ) {
				$localize_strings['stats'] = 'blog=' . Jetpack_Options::get_option( 'id' ) . '&host=' . wp_parse_url( get_option( 'home' ), PHP_URL_HOST ) . '&v=ext&j=' . JETPACK__API_VERSION . ':' . JETPACK__VERSION;

				// Set the stats as empty if user is logged in but logged-in users shouldn't be tracked.
				if ( is_user_logged_in() ) {
					$stats_options        = Stats_Options::get_options();
					$track_loggedin_users = isset( $stats_options['count_roles'] ) ? (bool) $stats_options['count_roles'] : false;

					if ( ! $track_loggedin_users ) {
						$localize_strings['stats'] = '';
					}
				}
			}

			/**
			 * Filter the strings passed to the Carousel's js file.
			 *
			 * @module carousel
			 *
			 * @since 1.6.0
			 *
			 * @param array $localize_strings Array of strings passed to the Jetpack js file.
			 */
			$localize_strings = apply_filters( 'jp_carousel_localize_strings', $localize_strings );
			wp_localize_script( 'jetpack-carousel', 'jetpackCarouselStrings', $localize_strings );
			wp_enqueue_style(
				'jetpack-carousel-swiper-css',
				plugins_url( 'swiper-bundle.css', __FILE__ ),
				array(),
				$this->asset_version( JETPACK__VERSION )
			);
			wp_enqueue_style( 'jetpack-carousel', plugins_url( 'jetpack-carousel.css', __FILE__ ), array(), $this->asset_version( JETPACK__VERSION ) );
			wp_style_add_data( 'jetpack-carousel', 'rtl', 'replace' );

			/**
			 * Fires after carousel assets are enqueued for the first time.
			 * Allows for adding additional assets to the carousel page.
			 *
			 * @module carousel
			 *
			 * @since 1.6.0
			 *
			 * @param bool $first_run First load if Carousel on the page.
			 * @param array $localized_strings Array of strings passed to the Jetpack js file.
			 */
			do_action( 'jp_carousel_enqueue_assets', $this->first_run, $localize_strings );

			// Add the carousel skeleton to the page.
			$this->localize_strings = $localize_strings;
			add_action( 'wp_footer', array( $this, 'add_carousel_skeleton' ) );

			$this->first_run = false;
		}
	}

	/**
	 * Generate the HTML skeleton that will be picked up by the Carousel JS and used for showing the carousel.
	 */
	public function add_carousel_skeleton() {
		$localize_strings = $this->localize_strings;
		$is_light         = ( 'white' === $localize_strings['background_color'] );
		// Determine whether to fall back to standard local comments.
		$use_local_comments = ! isset( $localize_strings['jetpack_comments_iframe_src'] ) || empty( $localize_strings['jetpack_comments_iframe_src'] );
		$current_user       = wp_get_current_user();
		$require_name_email = (int) get_option( 'require_name_email' );
		/* translators: %s is replaced with a field name in the form, e.g. "Email" */
		$required = ( $require_name_email ) ? __( '%s (Required)', 'jetpack' ) : '%s';
		?>
		<div id="jp-carousel-loading-overlay">
			<div id="jp-carousel-loading-wrapper">
				<span id="jp-carousel-library-loading">&nbsp;</span>
			</div>
		</div>
		<div class="jp-carousel-overlay<?php echo( $is_light ? ' jp-carousel-light' : '' ); ?>" style="display: none;">

		<div class="jp-carousel-container<?php echo( $is_light ? ' jp-carousel-light' : '' ); ?>">
			<!-- The Carousel Swiper -->
			<div
				class="jp-carousel-wrap swiper-container jp-carousel-swiper-container jp-carousel-transitions"
				itemscope
				itemtype="https://schema.org/ImageGallery">
				<div class="jp-carousel swiper-wrapper"></div>
				<div class="jp-swiper-button-prev swiper-button-prev">
					<svg width="25" height="24" viewBox="0 0 25 24" fill="none" xmlns="http://www.w3.org/2000/svg">
						<mask id="maskPrev" mask-type="alpha" maskUnits="userSpaceOnUse" x="8" y="6" width="9" height="12">
							<path d="M16.2072 16.59L11.6496 12L16.2072 7.41L14.8041 6L8.8335 12L14.8041 18L16.2072 16.59Z" fill="white"/>
						</mask>
						<g mask="url(#maskPrev)">
							<rect x="0.579102" width="23.8823" height="24" fill="#FFFFFF"/>
						</g>
					</svg>
				</div>
				<div class="jp-swiper-button-next swiper-button-next">
					<svg width="25" height="24" viewBox="0 0 25 24" fill="none" xmlns="http://www.w3.org/2000/svg">
						<mask id="maskNext" mask-type="alpha" maskUnits="userSpaceOnUse" x="8" y="6" width="8" height="12">
							<path d="M8.59814 16.59L13.1557 12L8.59814 7.41L10.0012 6L15.9718 12L10.0012 18L8.59814 16.59Z" fill="white"/>
						</mask>
						<g mask="url(#maskNext)">
							<rect x="0.34375" width="23.8822" height="24" fill="#FFFFFF"/>
						</g>
					</svg>
				</div>
			</div>
			<!-- The main close buton -->
			<div class="jp-carousel-close-hint">
				<svg width="25" height="24" viewBox="0 0 25 24" fill="none" xmlns="http://www.w3.org/2000/svg">
					<mask id="maskClose" mask-type="alpha" maskUnits="userSpaceOnUse" x="5" y="5" width="15" height="14">
						<path d="M19.3166 6.41L17.9135 5L12.3509 10.59L6.78834 5L5.38525 6.41L10.9478 12L5.38525 17.59L6.78834 19L12.3509 13.41L17.9135 19L19.3166 17.59L13.754 12L19.3166 6.41Z" fill="white"/>
					</mask>
					<g mask="url(#maskClose)">
						<rect x="0.409668" width="23.8823" height="24" fill="#FFFFFF"/>
					</g>
				</svg>
			</div>
			<!-- Image info, comments and meta -->
			<div class="jp-carousel-info">
				<div class="jp-carousel-info-footer">
					<div class="jp-carousel-pagination-container">
						<div class="jp-swiper-pagination swiper-pagination"></div>
						<div class="jp-carousel-pagination"></div>
					</div>
					<div class="jp-carousel-photo-title-container">
						<h2 class="jp-carousel-photo-caption"></h2>
					</div>
					<div class="jp-carousel-photo-icons-container">
						<a href="#" class="jp-carousel-icon-btn jp-carousel-icon-info" aria-label="<?php esc_attr_e( 'Toggle photo metadata visibility', 'jetpack' ); ?>">
							<span class="jp-carousel-icon">
								<svg width="25" height="24" viewBox="0 0 25 24" fill="none" xmlns="http://www.w3.org/2000/svg">
									<mask id="maskInfo" mask-type="alpha" maskUnits="userSpaceOnUse" x="2" y="2" width="21" height="20">
										<path fill-rule="evenodd" clip-rule="evenodd" d="M12.7537 2C7.26076 2 2.80273 6.48 2.80273 12C2.80273 17.52 7.26076 22 12.7537 22C18.2466 22 22.7046 17.52 22.7046 12C22.7046 6.48 18.2466 2 12.7537 2ZM11.7586 7V9H13.7488V7H11.7586ZM11.7586 11V17H13.7488V11H11.7586ZM4.79292 12C4.79292 16.41 8.36531 20 12.7537 20C17.142 20 20.7144 16.41 20.7144 12C20.7144 7.59 17.142 4 12.7537 4C8.36531 4 4.79292 7.59 4.79292 12Z" fill="white"/>
									</mask>
									<g mask="url(#maskInfo)">
										<rect x="0.8125" width="23.8823" height="24" fill="#FFFFFF"/>
									</g>
								</svg>
							</span>
						</a>
						<?php if ( $localize_strings['display_comments'] ) : ?>
						<a href="#" class="jp-carousel-icon-btn jp-carousel-icon-comments" aria-label="<?php esc_attr_e( 'Toggle photo comments visibility', 'jetpack' ); ?>">
							<span class="jp-carousel-icon">
								<svg width="25" height="24" viewBox="0 0 25 24" fill="none" xmlns="http://www.w3.org/2000/svg">
									<mask id="maskComments" mask-type="alpha" maskUnits="userSpaceOnUse" x="2" y="2" width="21" height="20">
										<path fill-rule="evenodd" clip-rule="evenodd" d="M4.3271 2H20.2486C21.3432 2 22.2388 2.9 22.2388 4V16C22.2388 17.1 21.3432 18 20.2486 18H6.31729L2.33691 22V4C2.33691 2.9 3.2325 2 4.3271 2ZM6.31729 16H20.2486V4H4.3271V18L6.31729 16Z" fill="white"/>
									</mask>
									<g mask="url(#maskComments)">
										<rect x="0.34668" width="23.8823" height="24" fill="#FFFFFF"/>
									</g>
								</svg>

								<span class="jp-carousel-has-comments-indicator" aria-label="<?php esc_attr_e( 'This image has comments.', 'jetpack' ); ?>"></span>
							</span>
						</a>
						<?php endif; ?>
					</div>
				</div>
				<div class="jp-carousel-info-extra">
					<div class="jp-carousel-info-content-wrapper">
						<div class="jp-carousel-photo-title-container">
							<h2 class="jp-carousel-photo-title"></h2>
						</div>
						<div class="jp-carousel-comments-wrapper">
							<?php if ( $localize_strings['display_comments'] ) : ?>
								<div id="jp-carousel-comments-loading">
									<span><?php echo esc_html( $localize_strings['loading_comments'] ); ?></span>
								</div>
								<div class="jp-carousel-comments"></div>
								<div id="jp-carousel-comment-form-container">
									<span id="jp-carousel-comment-form-spinner">&nbsp;</span>
									<div id="jp-carousel-comment-post-results"></div>
									<?php if ( $use_local_comments ) : ?>
										<?php if ( ! $localize_strings['is_logged_in'] && $localize_strings['comment_registration'] ) : ?>
											<div id="jp-carousel-comment-form-commenting-as">
												<p id="jp-carousel-commenting-as">
													<?php
														echo wp_kses(
															__( 'You must be <a href="#" class="jp-carousel-comment-login">logged in</a> to post a comment.', 'jetpack' ),
															array(
																'a' => array(
																	'href'  => array(),
																	'class' => array(),
																),
															)
														);
													?>
												</p>
											</div>
										<?php else : ?>
											<form id="jp-carousel-comment-form">
												<label for="jp-carousel-comment-form-comment-field" class="screen-reader-text"><?php echo esc_attr( $localize_strings['write_comment'] ); ?></label>
												<textarea
													name="comment"
													class="jp-carousel-comment-form-field jp-carousel-comment-form-textarea"
													id="jp-carousel-comment-form-comment-field"
													placeholder="<?php echo esc_attr( $localize_strings['write_comment'] ); ?>"
												></textarea>
												<div id="jp-carousel-comment-form-submit-and-info-wrapper">
													<div id="jp-carousel-comment-form-commenting-as">
														<?php if ( $localize_strings['is_logged_in'] ) : ?>
															<p id="jp-carousel-commenting-as">
																<?php
																	printf(
																		/* translators: %s is replaced with the user's display name */
																		esc_html__( 'Commenting as %s', 'jetpack' ),
																		esc_html( $current_user->data->display_name )
																	);
																?>
															</p>
														<?php else : ?>
															<fieldset>
																<label for="jp-carousel-comment-form-email-field"><?php echo esc_html( sprintf( $required, __( 'Email', 'jetpack' ) ) ); ?></label>
																<input type="text" name="email" class="jp-carousel-comment-form-field jp-carousel-comment-form-text-field" id="jp-carousel-comment-form-email-field" />
															</fieldset>
															<fieldset>
																<label for="jp-carousel-comment-form-author-field"><?php echo esc_html( sprintf( $required, __( 'Name', 'jetpack' ) ) ); ?></label>
																<input type="text" name="author" class="jp-carousel-comment-form-field jp-carousel-comment-form-text-field" id="jp-carousel-comment-form-author-field" />
															</fieldset>
															<fieldset>
																<label for="jp-carousel-comment-form-url-field"><?php esc_html_e( 'Website', 'jetpack' ); ?></label>
																<input type="text" name="url" class="jp-carousel-comment-form-field jp-carousel-comment-form-text-field" id="jp-carousel-comment-form-url-field" />
															</fieldset>
														<?php endif ?>
													</div>
													<input
														type="submit"
														name="submit"
														class="jp-carousel-comment-form-button"
														id="jp-carousel-comment-form-button-submit"
														value="<?php echo esc_attr( $localize_strings['post_comment'] ); ?>" />
												</div>
											</form>
										<?php endif ?>
									<?php endif ?>
								</div>
							<?php endif ?>
						</div>
						<div class="jp-carousel-image-meta">
							<div class="jp-carousel-title-and-caption">
								<div class="jp-carousel-photo-info">
									<h3 class="jp-carousel-caption" itemprop="caption description"></h3>
								</div>

								<div class="jp-carousel-photo-description"></div>
							</div>
							<ul class="jp-carousel-image-exif" style="display: none;"></ul>
							<a class="jp-carousel-image-download" target="_blank" style="display: none;">
								<svg width="25" height="24" viewBox="0 0 25 24" fill="none" xmlns="http://www.w3.org/2000/svg">
									<mask id="mask0" mask-type="alpha" maskUnits="userSpaceOnUse" x="3" y="3" width="19" height="18">
										<path fill-rule="evenodd" clip-rule="evenodd" d="M5.84615 5V19H19.7775V12H21.7677V19C21.7677 20.1 20.8721 21 19.7775 21H5.84615C4.74159 21 3.85596 20.1 3.85596 19V5C3.85596 3.9 4.74159 3 5.84615 3H12.8118V5H5.84615ZM14.802 5V3H21.7677V10H19.7775V6.41L9.99569 16.24L8.59261 14.83L18.3744 5H14.802Z" fill="white"/>
									</mask>
									<g mask="url(#mask0)">
										<rect x="0.870605" width="23.8823" height="24" fill="#FFFFFF"/>
									</g>
								</svg>
								<span class="jp-carousel-download-text"></span>
							</a>
							<div class="jp-carousel-image-map" style="display: none;"></div>
						</div>
					</div>
				</div>
			</div>
		</div>

		</div>
		<?php
	}

	/**
	 * Sets the "in_gallery" flag when the first gallery is encountered (unless in AMP mode).
	 *
	 * @deprecated since 10.8
	 *
	 * @param string $output Gallery shortcode output. Passed through unchanged.
	 *
	 * @return string
	 */
	public function set_in_gallery( $output ) {
		if (
			class_exists( 'Jetpack_AMP_Support' )
			&& Jetpack_AMP_Support::is_amp_request()
		) {
			return $output;
		}
		$this->in_gallery = true;
		return $output;
	}

	/**
	 * Adds data-* attributes required by carousel to img tags in post HTML
	 * content. To be used by 'the_content' filter.
	 *
	 * @see add_data_to_images()
	 * @see wp_make_content_images_responsive() in wp-includes/media.php
	 *
	 * @param string $content HTML content of the post.
	 * @return string
	 */
	public function add_data_img_tags_and_enqueue_assets( $content ) {
		if (
			class_exists( 'Jetpack_AMP_Support' )
			&& Jetpack_AMP_Support::is_amp_request()
		) {
			return $this->maybe_add_amp_lightbox( $content );
		}

		if ( ! preg_match_all( '/<img [^>]+>/', $content, $matches ) ) {
			return $content;
		}
		$selected_images = array();
		foreach ( $matches[0] as $image_html ) {
			if ( preg_match( '/(wp-image-|data-id=)\"?([0-9]+)\"?/i', $image_html, $class_id ) &&
				! preg_match( '/wp-block-jetpack-slideshow_image/', $image_html ) ) {
				$attachment_id = absint( $class_id[2] );
				/**
				 * The same image tag may be used more than once but with different attribs,
				 * so save each of them against the attachment id.
				 */
				if ( ! isset( $selected_images[ $attachment_id ] ) || ! in_array( $image_html, $selected_images[ $attachment_id ], true ) ) {
					$selected_images[ $attachment_id ][] = $image_html;
				}
			}
		}

		$find    = array();
		$replace = array();
		if ( empty( $selected_images ) ) {
			return $content;
		}

		$attachments = get_posts(
			array(
				'include'          => array_keys( $selected_images ),
				'post_type'        => 'any',
				'post_status'      => 'any',
				'suppress_filters' => false,
			)
		);

		foreach ( $attachments as $attachment ) {
			/*
			 * If the item from get_posts isn't an attachment, skip. This can occur when copy-pasta from another WP site.
			 * For example, if one copies "<img class="wp-image-7 size-full" src="https://twentysixteendemo.files.wordpress.com/2015/11/post.png" alt="post" width="1000" height="563" />"
			 * then, we're going to look up post 7 below, which making sure it is an attachment.
			 *
			 * This is meant as a relatively quick fix, as a better fix is likely to update the get_posts call above to only
			 * include attachments.
			 */
			if ( ! isset( $attachment->ID ) || ! wp_attachment_is_image( $attachment->ID ) ) {
				continue;
			}
			$image_elements = $selected_images[ $attachment->ID ];

			if ( ! is_array( $image_elements ) ) {
				continue;
			}

			$attributes      = $this->add_data_to_images( array(), $attachment );
			$attributes_html = '';
			foreach ( $attributes as $k => $v ) {
				$attributes_html .= esc_attr( $k ) . '="' . esc_attr( $v ) . '" ';
			}
			foreach ( $image_elements as $image_html ) {
				$find[]    = $image_html;
				$replace[] = str_replace( '<img ', "<img $attributes_html", $image_html );
			}
		}

		$content = str_replace( $find, $replace, $content );
		$this->enqueue_assets();
		return $content;
	}

	/**
	 * Adds the data attributes themselves to img tags.
	 *
	 * @see add_data_img_tags_and_enqueue_assets()
	 * @see https://developer.wordpress.org/reference/functions/wp_get_attachment_image/ Documentation about wp_get_attachment_image
	 *
	 * @param string[] $attr Array of attribute values for the image markup, keyed by attribute name.
	 * @param WP_Post  $attachment Image attachment post.
	 *
	 * @return string[] Modified image attributes.
	 */
	public function add_data_to_images( $attr, $attachment = null ) {
		if (
			class_exists( 'Jetpack_AMP_Support' )
			&& Jetpack_AMP_Support::is_amp_request()
		) {
			return $attr;
		}

		$attachment_id = (int) $attachment->ID;
		if ( ! wp_attachment_is_image( $attachment_id ) ) {
			return $attr;
		}

		$orig_file       = wp_get_attachment_image_src( $attachment_id, 'full' );
		$orig_file       = isset( $orig_file[0] ) ? $orig_file[0] : wp_get_attachment_url( $attachment_id );
		$meta            = wp_get_attachment_metadata( $attachment_id );
		$size            = isset( $meta['width'] ) ? (int) $meta['width'] . ',' . (int) $meta['height'] : '';
		$img_meta        = ( ! empty( $meta['image_meta'] ) ) ? (array) $meta['image_meta'] : array();
		$comments_opened = (int) comments_open( $attachment_id );

		/**
		 * Note: Cannot generate a filename from the width and height wp_get_attachment_image_src() returns because
		 * it takes the $content_width global variable themes can set in consideration, therefore returning sizes
		 * which when used to generate a filename will likely result in a 404 on the image.
		 * $content_width has no filter we could temporarily de-register, run wp_get_attachment_image_src(), then
		 * re-register. So using returned file URL instead, which we can define the sizes from through filename
		 * parsing in the JS, as this is a failsafe file reference.
		 *
		 * EG with Twenty Eleven activated:
		 * array(4) { [0]=> string(82) "http://vanillawpinstall.blah/wp-content/uploads/2012/06/IMG_3534-1024x764.jpg" [1]=> int(584) [2]=> int(435) [3]=> bool(true) }
		 *
		 * EG with Twenty Ten activated:
		 * array(4) { [0]=> string(82) "http://vanillawpinstall.blah/wp-content/uploads/2012/06/IMG_3534-1024x764.jpg" [1]=> int(640) [2]=> int(477) [3]=> bool(true) }
		 */

		$medium_file_info = wp_get_attachment_image_src( $attachment_id, 'medium' );
		$medium_file      = isset( $medium_file_info[0] ) ? $medium_file_info[0] : '';

		$large_file_info = wp_get_attachment_image_src( $attachment_id, 'large' );
		$large_file      = isset( $large_file_info[0] ) ? $large_file_info[0] : '';

		$attachment         = get_post( $attachment_id );
		$attachment_title   = ! empty( $attachment ) ? wptexturize( $attachment->post_title ) : '';
		$attachment_desc    = ! empty( $attachment ) ? wpautop( wptexturize( $attachment->post_content ) ) : '';
		$attachment_caption = ! empty( $attachment ) ? wpautop( wptexturize( $attachment->post_excerpt ) ) : '';

		// See https://github.com/Automattic/jetpack/issues/2765.
		if ( isset( $img_meta['keywords'] ) ) {
			unset( $img_meta['keywords'] );
		}

		$img_meta = wp_json_encode( array_map( 'strval', array_filter( $img_meta, 'is_scalar' ) ) );

		$attr['data-attachment-id']   = $attachment_id;
		$attr['data-permalink']       = esc_attr( get_permalink( $attachment_id ) );
		$attr['data-orig-file']       = esc_attr( $orig_file );
		$attr['data-orig-size']       = $size;
		$attr['data-comments-opened'] = $comments_opened;
		$attr['data-image-meta']      = esc_attr( $img_meta );
		// The lines below use `esc_attr( htmlspecialchars( ) )` because esc_attr tries to be too smart and won't double-encode, and we need that here.
		$attr['data-image-title']       = esc_attr( htmlspecialchars( $attachment_title, ENT_COMPAT ) );
		$attr['data-image-description'] = esc_attr( htmlspecialchars( $attachment_desc, ENT_COMPAT ) );
		$attr['data-image-caption']     = esc_attr( htmlspecialchars( $attachment_caption, ENT_COMPAT ) );
		$attr['data-medium-file']       = esc_attr( $medium_file );
		$attr['data-large-file']        = esc_attr( $large_file );

		return $attr;
	}

	/**
	 * Add additional attributes to the Gallery container HTML.
	 *
	 * @param string $html The HTML to which the additional attributes are added.
	 *
	 * @return string
	 */
	public function add_data_to_container( $html ) {
		global $post;
		if (
			class_exists( 'Jetpack_AMP_Support' )
			&& Jetpack_AMP_Support::is_amp_request()
		) {
			return $html;
		}

		if ( isset( $post ) ) {
			$blog_id = (int) get_current_blog_id();

			$extra_data = array(
				'data-carousel-extra' => array(
					'blog_id'   => $blog_id,
					'permalink' => get_permalink( $post->ID ),
				),
			);

			/**
			 * Filter the data added to the Gallery container.
			 *
			 * @module carousel
			 *
			 * @since 1.6.0
			 *
			 * @param array $extra_data Array of data about the site and the post.
			 */
			$extra_data = apply_filters( 'jp_carousel_add_data_to_container', $extra_data );
			foreach ( (array) $extra_data as $data_key => $data_values ) {
				$html = str_replace( '<div ', '<div ' . esc_attr( $data_key ) . "='" . wp_json_encode( $data_values ) . "' ", $html );
				$html = str_replace( '<ul class="wp-block-gallery', '<ul ' . esc_attr( $data_key ) . "='" . wp_json_encode( $data_values ) . "' class=\"wp-block-gallery", $html );
				$html = str_replace( '<ul class="blocks-gallery-grid', '<ul ' . esc_attr( $data_key ) . "='" . wp_json_encode( $data_values ) . "' class=\"blocks-gallery-grid", $html );
				$html = preg_replace( '/\<figure([^>]*)class="(wp-block-gallery[^"]*?has-nested-images.*?)"/', '<figure ' . esc_attr( $data_key ) . "='" . wp_json_encode( $data_values ) . "' $1 class=\"$2\"", $html );
			}
		}

		return $html;
	}

	/**
	 * Conditionally adds amp-lightbox to galleries and images.
	 *
	 * This applies to gallery blocks and shortcodes,
	 * in addition to images that are wrapped in a link to the page.
	 * Images wrapped in a link to the media file shouldn't get an amp-lightbox.
	 *
	 * @param string $content The content to possibly add amp-lightbox to.
	 * @return string The content, with amp-lightbox possibly added.
	 */
	public function maybe_add_amp_lightbox( $content ) {
		$content = preg_replace(
			array(
				'#(<figure)[^>]*(?=class=(["\']?)[^>]*wp-block-gallery[^>]*\2)#is', // Gallery block.
				'#(\[gallery)(?=\s+)#', // Gallery shortcode.
			),
			array(
				'\1 data-amp-lightbox="true" ', // https://github.com/ampproject/amp-wp/blob/1094ea03bd5dc92889405a47a8c41de1a88908de/includes/sanitizers/class-amp-gallery-block-sanitizer.php#L84.
				'\1 amp-lightbox="true"', // https://github.com/ampproject/amp-wp/blob/1094ea03bd5dc92889405a47a8c41de1a88908de/includes/embeds/class-amp-gallery-embed.php#L64.
			),
			$content
		);

		return preg_replace_callback(
			'#(<a[^>]* href=(["\']?)(\S+)\2>)\s*(<img[^>]*)(class=(["\']?)[^>]*wp-image-[0-9]+[^>]*\6.*>)\s*</a>#is',
			static function ( $matches ) {
				if ( ! preg_match( '#\.\w+$#', $matches[3] ) ) {
					// The a[href] doesn't end in a file extension like .jpeg, so this is not a link to the media file, and should get a lightbox.
					return $matches[4] . ' data-amp-lightbox="true" lightbox="true" ' . $matches[5]; // https://github.com/ampproject/amp-wp/blob/1094ea03bd5dc92889405a47a8c41de1a88908de/includes/sanitizers/class-amp-img-sanitizer.php#L419.
				}

				return $matches[0];
			},
			$content
		);
	}

	/**
	 * Retrieves comment information
	 *
	 * @return string
	 */
	public function get_attachment_comments() {
		if ( ! headers_sent() ) {
			header( 'Content-type: text/javascript' );
		}

		/**
		 * Allows for the checking of privileges of the blog user before comments
		 * are packaged as JSON and sent back from the get_attachment_comments
		 * AJAX endpoint
		 *
		 * @module carousel
		 *
		 * @since 1.6.0
		 */
		do_action( 'jp_carousel_check_blog_user_privileges' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- we do not need to verify the nonce for this public request for publicly accessible data (as checked below).
		$attachment_id = ( isset( $_REQUEST['id'] ) ) ? (int) $_REQUEST['id'] : 0;
		$offset        = ( isset( $_REQUEST['offset'] ) ) ? (int) $_REQUEST['offset'] : 0;
		// phpcs:enable

		if ( ! $attachment_id ) {
			wp_send_json_error(
				__( 'Missing attachment ID.', 'jetpack' ),
				403
			);
			return;
		}

		$attachment_post = get_post( $attachment_id );
		// If we have no info about that attachment, bail.
		if ( ! ( $attachment_post instanceof WP_Post ) ) {
			wp_send_json_error(
				__( 'Missing attachment info.', 'jetpack' ),
				403
			);
			return;
		}

		// This AJAX call should only be used to fetch comments of attachments.
		if ( 'attachment' !== $attachment_post->post_type ) {
			wp_send_json_error(
				__( 'You aren’t authorized to do that.', 'jetpack' ),
				403
			);
			return;
		}

		$parent_post = get_post_parent( $attachment_id );

		/*
		 * If we have no info about that parent post, no extra checks.
		 * The attachment doesn't have a parent post, so is public.
		 * If we have a parent post, let's ensure the user has access to it.
		 */
		if ( $parent_post instanceof WP_Post ) {
			/*
			 * Fetch info about user making the request.
			 * If we have no info, bail.
			 * Even logged out users should get a WP_User user with id 0.
			 */
			$current_user = wp_get_current_user();
			if ( ! ( $current_user instanceof WP_User ) ) {
				wp_send_json_error(
					__( 'Missing user info.', 'jetpack' ),
					403
				);
				return;
			}

			/*
			 * If a post is private / draft
			 * and the current user doesn't have access to it,
			 * bail.
			 */
			if (
				'publish' !== $parent_post->post_status
				&& ! current_user_can( 'read_post', $parent_post->ID )
			) {
				wp_send_json_error(
					__( 'You aren’t authorized to do that.', 'jetpack' ),
					403
				);
				return;
			}
		}

		if ( $offset < 1 ) {
			$offset = 0;
		}

		$comments = get_comments(
			array(
				'status'  => 'approve',
				'order'   => ( 'asc' === get_option( 'comment_order' ) ) ? 'ASC' : 'DESC',
				'number'  => 10,
				'offset'  => $offset,
				'post_id' => $attachment_id,
			)
		);

		$out = array();

		// Can't just send the results, they contain the commenter's email address.
		foreach ( $comments as $comment ) {
			$avatar = get_avatar( $comment->comment_author_email, 64 );
			if ( ! $avatar ) {
				$avatar = '';
			}
			$out[] = array(
				'id'              => $comment->comment_ID,
				'parent_id'       => $comment->comment_parent,
				'author_markup'   => get_comment_author_link( $comment->comment_ID ),
				'gravatar_markup' => $avatar,
				'date_gmt'        => $comment->comment_date_gmt,
				'content'         => wpautop( $comment->comment_content ),
			);
		}

		die( wp_json_encode( $out ) );
	}

	/**
	 * Adds a new comment to the database
	 */
	public function post_attachment_comment() {
		if ( ! headers_sent() ) {
			header( 'Content-type: text/javascript' );
		}

		if ( empty( $_POST['nonce'] ) || ! wp_verify_nonce( $_POST['nonce'], 'carousel_nonce' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- WP Core doesn't unslash or sanitize nonces either
			die( wp_json_encode( array( 'error' => __( 'Nonce verification failed.', 'jetpack' ) ) ) );
		}

		$_blog_id = isset( $_POST['blog_id'] ) ? (int) $_POST['blog_id'] : 0;
		$_post_id = isset( $_POST['id'] ) ? (int) $_POST['id'] : 0;
		$comment  = isset( $_POST['comment'] ) ? filter_var( wp_unslash( $_POST['comment'] ) ) : null;

		if ( empty( $_blog_id ) ) {
			die( wp_json_encode( array( 'error' => __( 'Missing target blog ID.', 'jetpack' ) ) ) );
		}

		if ( empty( $_post_id ) ) {
			die( wp_json_encode( array( 'error' => __( 'Missing target post ID.', 'jetpack' ) ) ) );
		}

		if ( empty( $comment ) ) {
			die( wp_json_encode( array( 'error' => __( 'No comment text was submitted.', 'jetpack' ) ) ) );
		}

		// Used in context like NewDash.
		$switched = false;
		if ( is_multisite() && get_current_blog_id() !== $_blog_id ) {
			switch_to_blog( $_blog_id );
			$switched = true;
		}

		/** This action is documented in modules/carousel/jetpack-carousel.php */
		do_action( 'jp_carousel_check_blog_user_privileges' );

		if ( ! comments_open( $_post_id ) ) {
			if ( $switched ) {
				restore_current_blog();
			}
			die( wp_json_encode( array( 'error' => __( 'Comments on this post are closed.', 'jetpack' ) ) ) );
		}

		if ( is_user_logged_in() ) {
			$user         = wp_get_current_user();
			$user_id      = $user->ID;
			$display_name = $user->display_name;
			$email        = $user->user_email;
			$url          = $user->user_url;

			if ( empty( $user_id ) ) {
				if ( $switched ) {
					restore_current_blog();
				}
				die( wp_json_encode( array( 'error' => __( 'Sorry, but we could not authenticate your request.', 'jetpack' ) ) ) );
			}
		} else {
			$user_id      = 0;
			$display_name = isset( $_POST['author'] ) ? sanitize_text_field( wp_unslash( $_POST['author'] ) ) : null;
			$email        = isset( $_POST['email'] ) ? wp_unslash( $_POST['email'] ) : null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Checked or sanitized below.
			$url          = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : null;

			if ( get_option( 'require_name_email' ) ) {
				if ( empty( $display_name ) ) {
					if ( $switched ) {
						restore_current_blog();
					}
					die( wp_json_encode( array( 'error' => __( 'Please provide your name.', 'jetpack' ) ) ) );
				}

				if ( empty( $email ) ) {
					if ( $switched ) {
						restore_current_blog();
					}
					die( wp_json_encode( array( 'error' => __( 'Please provide an email address.', 'jetpack' ) ) ) );
				}

				if ( ! is_email( $email ) ) {
					if ( $switched ) {
						restore_current_blog();
					}
					die( wp_json_encode( array( 'error' => __( 'Please provide a valid email address.', 'jetpack' ) ) ) );
				}
			} else {
				$email = $email !== null ? sanitize_email( $email ) : null;
			}
		}

		$comment_data = array(
			'comment_content'      => $comment,
			'comment_post_ID'      => $_post_id,
			'comment_author'       => $display_name,
			'comment_author_email' => $email,
			'comment_author_url'   => $url,
			'comment_approved'     => 0,
			'comment_type'         => 'comment',
		);

		if ( ! empty( $user_id ) ) {
			$comment_data['user_id'] = $user_id;
		}

		// Note: wp_new_comment() sanitizes and validates the values (too).
		$comment_id = wp_new_comment( $comment_data );

		/**
		 * Fires before adding a new comment to the database via the get_attachment_comments ajax endpoint.
		 *
		 * @module carousel
		 *
		 * @since 1.6.0
		 */
		do_action( 'jp_carousel_post_attachment_comment' );
		$comment_status = wp_get_comment_status( $comment_id );

		if ( $switched ) {
			restore_current_blog();
		}

		die(
			wp_json_encode(
				array(
					'comment_id'     => $comment_id,
					'comment_status' => $comment_status,
				)
			)
		);
	}

	/**
	 * Register Carousel settings
	 */
	public function register_settings() {
		add_settings_section( 'carousel_section', __( 'Image Gallery Carousel', 'jetpack' ), array( $this, 'carousel_section_callback' ), 'media' );

		if ( ! $this->in_jetpack ) {
			add_settings_field( 'carousel_enable_it', __( 'Enable carousel', 'jetpack' ), array( $this, 'carousel_enable_it_callback' ), 'media', 'carousel_section' );
			register_setting( 'media', 'carousel_enable_it', array( $this, 'carousel_enable_it_sanitize' ) );
		}

		add_settings_field( 'carousel_background_color', __( 'Background color', 'jetpack' ), array( $this, 'carousel_background_color_callback' ), 'media', 'carousel_section' );
		register_setting( 'media', 'carousel_background_color', array( $this, 'carousel_background_color_sanitize' ) );

		add_settings_field( 'carousel_display_exif', __( 'Metadata', 'jetpack' ), array( $this, 'carousel_display_exif_callback' ), 'media', 'carousel_section' );
		register_setting( 'media', 'carousel_display_exif', array( $this, 'carousel_display_exif_sanitize' ) );

		add_settings_field( 'carousel_display_comments', __( 'Comments', 'jetpack' ), array( $this, 'carousel_display_comments_callback' ), 'media', 'carousel_section' );
		register_setting( 'media', 'carousel_display_comments', array( $this, 'carousel_display_comments_sanitize' ) );
	}

	/**
	 * Fulfill the settings section callback requirement by returning nothing.
	 */
	public function carousel_section_callback() {
	}

	/**
	 * Tests if a value is set
	 *
	 * @param mixed $value The value passed into this function with which to test.
	 * @param bool  $default_to_1 Default is true.
	 *
	 * @return bool
	 */
	public function test_1or0_option( $value, $default_to_1 = true ) {
		if ( $default_to_1 ) {
			// Boolean false (===) of $value means it has not yet been set, in which case we do want to default to 1.
			if ( false === $value ) {
				$value = 1;
			}
		}
		return ( 1 == $value ) ? 1 : 0; // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
	}

	/**
	 * Ensures the value returned is in the correct format.
	 *
	 * @see test_1or0_option()
	 * @param mixed $value The value returned from the test_1or0_option function.
	 *
	 * @return int
	 */
	public function sanitize_1or0_option( $value ) {
		return ( 1 == $value ) ? 1 : 0; // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
	}

	/**
	 * Outputs a settings checkbox.
	 *
	 * @param string $name - For name attribute.
	 * @param string $label_text - For label attribute.
	 * @param string $extra_text - Additional checkbox description text. Defaults to empty.
	 * @param bool   $default_to_checked - If the checkbox is checked. Default is true.
	 */
	public function settings_checkbox( $name, $label_text, $extra_text = '', $default_to_checked = true ) {
		if ( empty( $name ) ) {
			return;
		}
		$option = $this->test_1or0_option( get_option( $name ), $default_to_checked );
		echo '<fieldset>';
		echo '<input type="checkbox" name="' . esc_attr( $name ) . '" id="' . esc_attr( $name ) . '" value="1" ';
		checked( '1', $option );
		echo '/> <label for="' . esc_attr( $name ) . '">' . wp_kses_post( $label_text ) . '</label>';
		if ( ! empty( $extra_text ) ) {
			echo '<p class="description">' . wp_kses_post( $extra_text ) . '</p>';
		}
		echo '</fieldset>';
	}

	/**
	 * Output a selection list options
	 *
	 * @param string $name - For name attribute.
	 * @param string $values - For the different option values.
	 * @param string $extra_text - Additional option section description text. Defaults to empty.
	 */
	public function settings_select( $name, $values, $extra_text = '' ) {
		if ( empty( $name ) || ! is_array( $values ) || empty( $values ) ) {
			return;
		}
		$option = get_option( $name );
		echo '<fieldset>';
		echo '<select name="' . esc_attr( $name ) . '" id="' . esc_attr( $name ) . '">';
		foreach ( $values as $key => $value ) {
			echo '<option value="' . esc_attr( $key ) . '" ';
			selected( $key, $option );
			echo '>' . esc_html( $value ) . '</option>';
		}
		echo '</select>';
		if ( ! empty( $extra_text ) ) {
			echo '<p class="description">' . wp_kses_post( $extra_text ) . '</p>';
		}
		echo '</fieldset>';
	}

	/**
	 * Callback for checkbox and label of field that allows to toggle exif display.
	 */
	public function carousel_display_exif_callback() {
		$this->settings_checkbox( 'carousel_display_exif', __( 'Show photo metadata (<a href="https://en.wikipedia.org/wiki/Exchangeable_image_file_format" rel="noopener noreferrer" target="_blank">Exif</a>) in carousel, when available.', 'jetpack' ) );
	}

	/**
	 * Callback for checkbox and label of field that allows to toggle comments.
	 */
	public function carousel_display_comments_callback() {
		$this->settings_checkbox( 'carousel_display_comments', esc_html__( 'Show comments area in carousel', 'jetpack' ) );
	}

	/**
	 * Sanitize input for the `carousel_display_exif` setting.
	 *
	 * @param mixed $value User input setting value.
	 *
	 * @return number Sanitized value, only 1 or 0.
	 */
	public function carousel_display_exif_sanitize( $value ) {
		return $this->sanitize_1or0_option( $value );
	}

	/**
	 * Return sanitized option for value that controls whether comments will be hidden or not.
	 *
	 * @param number $value Value to sanitize.
	 *
	 * @return number Sanitized value, only 1 or 0.
	 */
	public function carousel_display_comments_sanitize( $value ) {
		return $this->sanitize_1or0_option( $value );
	}

	/**
	 * Callback for the Carousel background color.
	 */
	public function carousel_background_color_callback() {
		$this->settings_select(
			'carousel_background_color',
			array(
				'black' => __( 'Black', 'jetpack' ),
				'white' => __( 'White', 'jetpack' ),
			)
		);
	}

	/**
	 * Sanitizing the Carousel backgound color selection.
	 *
	 * @param string $value The color string to sanitize.
	 *
	 * @return string Sanitized value, 'white' or 'black'.
	 */
	public function carousel_background_color_sanitize( $value ) {
		return ( 'white' === $value ) ? 'white' : 'black';
	}

	/**
	 * Callback to display text for the carousel_enable_it settings field.
	 */
	public function carousel_enable_it_callback() {
		$this->settings_checkbox( 'carousel_enable_it', __( 'Display images in full-size carousel slideshow.', 'jetpack' ) );
	}

	/**
	 * Sanitize input for the `carousel_enable_it` setting.
	 *
	 * @param mixed $value User input.
	 *
	 * @return number Sanitized value, only 1 or 0.
	 */
	public function carousel_enable_it_sanitize( $value ) {
		return $this->sanitize_1or0_option( $value );
	}
}

new Jetpack_Carousel();
