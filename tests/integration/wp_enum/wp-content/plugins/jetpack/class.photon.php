<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Class for photon functionality.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;

/**
 * Class Jetpack_Photon
 */
class Jetpack_Photon {
	/**
	 * Singleton.
	 *
	 * @var null
	 */
	private static $instance = null;

	/**
	 * Allowed extensions.
	 *
	 * @var string[] Allowed extensions must match https://code.trac.wordpress.org/browser/photon/index.php#L41
	 */
	protected static $extensions = array(
		'gif',
		'jpg',
		'jpeg',
		'png',
		'webp', // Jetpack assumes Photon_OpenCV backend class is being used on the server. See link in docblock.
	);

	/**
	 * Image sizes.
	 *
	 * Don't access this directly. Instead, use self::image_sizes() so it's actually populated with something.
	 *
	 * @var array Image sizes.
	 */
	protected static $image_sizes = null;

	/**
	 * Singleton implementation
	 *
	 * @return object
	 */
	public static function instance() {
		if ( ! is_a( self::$instance, 'Jetpack_Photon' ) ) {
			self::$instance = new Jetpack_Photon();
			self::$instance->setup();
		}

		return self::$instance;
	}

	/**
	 * Silence is golden.
	 */
	private function __construct() {}

	/**
	 * Register actions and filters, but only if basic Photon functions are available.
	 * The basic functions are found in ./functions.photon.php.
	 *
	 * @uses add_action, add_filter
	 * @return null
	 */
	private function setup() {
		if ( ! function_exists( 'jetpack_photon_url' ) ) {
			return;
		}

		// Images in post content and galleries.
		add_filter( 'the_content', array( __CLASS__, 'filter_the_content' ), 999999 );
		add_filter( 'get_post_galleries', array( __CLASS__, 'filter_the_galleries' ), 999999 );
		add_filter( 'widget_media_image_instance', array( __CLASS__, 'filter_the_image_widget' ), 999999 );

		// Core image retrieval.
		add_filter( 'image_downsize', array( $this, 'filter_image_downsize' ), 10, 3 );
		add_filter( 'rest_request_before_callbacks', array( $this, 'should_rest_photon_image_downsize' ), 10, 3 );
		add_action( 'rest_after_insert_attachment', array( $this, 'should_rest_photon_image_downsize_insert_attachment' ), 10, 2 );
		add_filter( 'rest_request_after_callbacks', array( $this, 'cleanup_rest_photon_image_downsize' ) );

		// Responsive image srcset substitution.
		add_filter( 'wp_calculate_image_srcset', array( $this, 'filter_srcset_array' ), 10, 5 );
		add_filter( 'wp_calculate_image_sizes', array( $this, 'filter_sizes' ), 1, 2 ); // Early so themes can still easily filter.

		// Helpers for maniuplated images.
		add_action( 'wp_enqueue_scripts', array( $this, 'action_wp_enqueue_scripts' ), 9 );

		/**
		 * Allow Photon to disable uploaded images resizing and use its own resize capabilities instead.
		 *
		 * @module photon
		 *
		 * @since 7.1.0
		 *
		 * @param bool false Should Photon enable noresize mode. Default to false.
		 */
		if ( apply_filters( 'jetpack_photon_noresize_mode', false ) ) {
			$this->enable_noresize_mode();
		}
	}

	/**
	 * Enables the noresize mode for Photon, allowing to avoid intermediate size files generation.
	 */
	private function enable_noresize_mode() {
		require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.jetpack-photon-image-sizes.php';

		// The main objective of noresize mode is to disable additional resized image versions creation.
		// This filter handles removal of additional sizes.
		add_filter( 'intermediate_image_sizes_advanced', array( __CLASS__, 'filter_photon_noresize_intermediate_sizes' ) );

		// Load the noresize srcset solution on priority of 20, allowing other plugins to set sizes earlier.
		add_filter( 'wp_get_attachment_metadata', array( __CLASS__, 'filter_photon_norezise_maybe_inject_sizes' ), 20, 2 );

		// Photonize thumbnail URLs in the API response.
		add_filter( 'rest_api_thumbnail_size_urls', array( __CLASS__, 'filter_photon_noresize_thumbnail_urls' ) );

		// This allows to assign the Photon domain to images that normally use the home URL as base.
		add_filter( 'jetpack_photon_domain', array( __CLASS__, 'filter_photon_norezise_domain' ), 10, 2 );

		add_filter( 'the_content', array( __CLASS__, 'filter_content_add' ), 0 );

		// Jetpack hooks in at six nines (999999) so this filter does at seven.
		add_filter( 'the_content', array( __CLASS__, 'filter_content_remove' ), 9999999 );

		// Regular Photon operation mode filter doesn't run when is_admin(), so we need an additional filter.
		// This is temporary until Jetpack allows more easily running these filters for is_admin().
		if ( is_admin() ) {
			add_filter( 'image_downsize', array( $this, 'filter_image_downsize' ), 5, 3 );

			// Allows any image that gets passed to Photon to be resized via Photon.
			add_filter( 'jetpack_photon_admin_allow_image_downsize', '__return_true' );
		}
	}

	/**
	 * This is our catch-all to strip dimensions from intermediate images in content.
	 * Since this primarily only impacts post_content we do a little dance to add the filter early
	 * to `the_content` and then remove it later on in the same hook.
	 *
	 * @param String $content the post content.
	 * @return String the post content unchanged.
	 */
	public static function filter_content_add( $content ) {
		add_filter( 'jetpack_photon_pre_image_url', array( __CLASS__, 'strip_image_dimensions_maybe' ) );
		return $content;
	}

	/**
	 * Removing the content filter that was set previously.
	 *
	 * @param String $content the post content.
	 * @return String the post content unchanged.
	 */
	public static function filter_content_remove( $content ) {
		remove_filter( 'jetpack_photon_pre_image_url', array( __CLASS__, 'strip_image_dimensions_maybe' ) );
		return $content;
	}

	/**
	 * Short circuits the Photon filter to enable Photon processing for any URL.
	 *
	 * @param String $photon_url a proposed Photon URL for the media file.
	 *
	 * @return String an URL to be used for the media file.
	 */
	public static function filter_photon_norezise_domain( $photon_url ) {
		return $photon_url;
	}

	/**
	 * Disables intermediate sizes to disallow resizing.
	 *
	 * @return array Empty array.
	 */
	public static function filter_photon_noresize_intermediate_sizes() {
		return array();
	}

	/**
	 * Filter thumbnail URLS to not generate.
	 *
	 * @param array $sizes Image sizes.
	 *
	 * @return mixed
	 */
	public static function filter_photon_noresize_thumbnail_urls( $sizes ) {
		foreach ( $sizes as $size => $url ) {
			$parts     = explode( '?', $url );
			$arguments = isset( $parts[1] ) ? $parts[1] : array();

			$sizes[ $size ] = jetpack_photon_url( $url, wp_parse_args( $arguments ) );
		}

		return $sizes;
	}

	/**
	 * Inject image sizes to attachment metadata.
	 *
	 * @param array $data          Attachment metadata.
	 * @param int   $attachment_id Attachment's post ID.
	 *
	 * @return array Attachment metadata.
	 */
	public static function filter_photon_norezise_maybe_inject_sizes( $data, $attachment_id ) {
		// Can't do much if data is empty.
		if ( empty( $data ) ) {
			return $data;
		}
		$sizes_already_exist = (
			true === is_array( $data )
			&& true === array_key_exists( 'sizes', $data )
			&& true === is_array( $data['sizes'] )
			&& false === empty( $data['sizes'] )
		);
		if ( $sizes_already_exist ) {
			return $data;
		}
		// Missing some critical data we need to determine sizes, not processing.
		if ( ! isset( $data['file'] )
			|| ! isset( $data['width'] )
			|| ! isset( $data['height'] )
		) {
			return $data;
		}

		$mime_type           = get_post_mime_type( $attachment_id );
		$attachment_is_image = preg_match( '!^image/!', $mime_type );

		if ( 1 === $attachment_is_image ) {
			$image_sizes   = new Jetpack_Photon_ImageSizes( $attachment_id, $data );
			$data['sizes'] = $image_sizes->generate_sizes_meta();
		}
		return $data;
	}

	/**
	 * Inject image sizes to Jetpack REST API responses. This wraps the filter_photon_norezise_maybe_inject_sizes function.
	 *
	 * @param array $sizes Attachment sizes data.
	 * @param int   $attachment_id Attachment's post ID.
	 *
	 * @return array Attachment sizes array.
	 */
	public static function filter_photon_norezise_maybe_inject_sizes_api( $sizes, $attachment_id ) {
		return self::filter_photon_norezise_maybe_inject_sizes( wp_get_attachment_metadata( $attachment_id ), $attachment_id );
	}

	/**
	 * * IN-CONTENT IMAGE MANIPULATION FUNCTIONS
	 **/

	/**
	 * Match all images and any relevant <a> tags in a block of HTML.
	 *
	 * @param string $content Some HTML.
	 * @return array An array of $images matches, where $images[0] is
	 *         an array of full matches, and the link_url, img_tag,
	 *         and img_url keys are arrays of those matches.
	 */
	public static function parse_images_from_html( $content ) {
		$images = array();

		if ( preg_match_all( '#(?:<a[^>]+?href=["|\'](?P<link_url>[^\s]+?)["|\'][^>]*?>\s*)?(?P<img_tag><(?:img|amp-img|amp-anim)[^>]*?\s+?src=["|\'](?P<img_url>[^\s]+?)["|\'].*?>){1}(?:\s*</a>)?#is', $content, $images ) ) {
			foreach ( $images as $key => $unused ) {
				// Simplify the output as much as possible, mostly for confirming test results.
				if ( is_numeric( $key ) && $key > 0 ) {
					unset( $images[ $key ] );
				}
			}

			return $images;
		}

		return array();
	}

	/**
	 * Try to determine height and width from strings WP appends to resized image filenames.
	 *
	 * @param string $src The image URL.
	 * @return array An array consisting of width and height.
	 */
	public static function parse_dimensions_from_filename( $src ) {
		$width_height_string = array();

		if ( preg_match( '#-(\d+)x(\d+)\.(?:' . implode( '|', self::$extensions ) . '){1}$#i', $src, $width_height_string ) ) {
			$width  = (int) $width_height_string[1];
			$height = (int) $width_height_string[2];

			if ( $width && $height ) {
				return array( $width, $height );
			}
		}

		return array( false, false );
	}

	/**
	 * Identify images in post content, and if images are local (uploaded to the current site), pass through Photon.
	 *
	 * @param string $content The content.
	 *
	 * @uses self::validate_image_url, apply_filters, jetpack_photon_url, esc_url
	 * @filter the_content
	 *
	 * @return string
	 */
	public static function filter_the_content( $content ) {
		$images = self::parse_images_from_html( $content );

		if ( ! empty( $images ) ) {
			$content_width = Jetpack::get_content_width();

			$image_sizes = self::image_sizes();

			$upload_dir = wp_get_upload_dir();

			foreach ( $images[0] as $index => $tag ) {
				// Default to resize, though fit may be used in certain cases where a dimension cannot be ascertained.
				$transform = 'resize';

				// Start with a clean attachment ID each time.
				$attachment_id = false;

				// Flag if we need to munge a fullsize URL.
				$fullsize_url = false;

				// Identify image source.
				$src_orig = $images['img_url'][ $index ];
				$src      = $src_orig;

				/**
				 * Allow specific images to be skipped by Photon.
				 *
				 * @module photon
				 *
				 * @since 2.0.3
				 *
				 * @param bool false Should Photon ignore this image. Default to false.
				 * @param string $src Image URL.
				 * @param string $tag Image Tag (Image HTML output).
				 */
				if ( apply_filters( 'jetpack_photon_skip_image', false, $src, $tag ) ) {
					continue;
				}

				// Support Automattic's Lazy Load plugin.
				// Can't modify $tag yet as we need unadulterated version later.
				if ( preg_match( '#data-lazy-src=["|\'](.+?)["|\']#i', $images['img_tag'][ $index ], $lazy_load_src ) ) {
					$placeholder_src_orig = $src;
					$placeholder_src      = $placeholder_src_orig;
					$src_orig             = $lazy_load_src[1];
					$src                  = $src_orig;
				} elseif ( preg_match( '#data-lazy-original=["|\'](.+?)["|\']#i', $images['img_tag'][ $index ], $lazy_load_src ) ) {
					$placeholder_src_orig = $src;
					$placeholder_src      = $placeholder_src_orig;
					$src_orig             = $lazy_load_src[1];
					$src                  = $src_orig;
				}

				// Check if image URL should be used with Photon.
				if ( self::validate_image_url( $src ) ) {
					// Find the width and height attributes.
					$width  = false;
					$height = false;

					// First, check the image tag. Note we only check for pixel sizes now; HTML4 percentages have never been correctly
					// supported, so we stopped pretending to support them in JP 9.1.0.
					if ( preg_match( '#[\s|"|\']width=["|\']?([\d%]+)["|\']?#i', $images['img_tag'][ $index ], $width_string ) ) {
						$width = false === strpos( $width_string[1], '%' ) ? $width_string[1] : false;
					}

					if ( preg_match( '#[\s|"|\']height=["|\']?([\d%]+)["|\']?#i', $images['img_tag'][ $index ], $height_string ) ) {
						$height = false === strpos( $height_string[1], '%' ) ? $height_string[1] : false;
					}

					// Detect WP registered image size from HTML class.
					if ( preg_match( '#class=["|\']?[^"\']*size-([^"\'\s]+)[^"\']*["|\']?#i', $images['img_tag'][ $index ], $size ) ) {
						$size = array_pop( $size );

						if ( false === $width && false === $height && 'full' !== $size && array_key_exists( $size, $image_sizes ) ) {
							$width     = (int) $image_sizes[ $size ]['width'];
							$height    = (int) $image_sizes[ $size ]['height'];
							$transform = $image_sizes[ $size ]['crop'] ? 'resize' : 'fit';
						}
					} else {
						unset( $size );
					}

					// WP Attachment ID, if uploaded to this site.
					if (
						preg_match( '#class=["|\']?[^"\']*wp-image-([\d]+)[^"\']*["|\']?#i', $images['img_tag'][ $index ], $attachment_id ) &&
						0 === strpos( $src, $upload_dir['baseurl'] ) &&
						/**
						 * Filter whether an image using an attachment ID in its class has to be uploaded to the local site to go through Photon.
						 *
						 * @module photon
						 *
						 * @since 2.0.3
						 *
						 * @param bool false Was the image uploaded to the local site. Default to false.
						 * @param array $args {
						 *   Array of image details.
						 *
						 *   @type $src Image URL.
						 *   @type tag Image tag (Image HTML output).
						 *   @type $images Array of information about the image.
						 *   @type $index Image index.
						 * }
						 */
						apply_filters( 'jetpack_photon_image_is_local', false, compact( 'src', 'tag', 'images', 'index' ) )
					) {
						$attachment_id = (int) array_pop( $attachment_id );

						if ( $attachment_id ) {
							$attachment = get_post( $attachment_id );

							// Basic check on returned post object.
							if ( is_object( $attachment ) && ! is_wp_error( $attachment ) && 'attachment' === $attachment->post_type ) {
								$src_per_wp = wp_get_attachment_image_src( $attachment_id, isset( $size ) ? $size : 'full' );

								if ( self::validate_image_url( $src_per_wp[0] ) ) {
									$src          = $src_per_wp[0];
									$fullsize_url = true;

									// Prevent image distortion if a detected dimension exceeds the image's natural dimensions.
									if ( ( false !== $width && $width > $src_per_wp[1] ) || ( false !== $height && $height > $src_per_wp[2] ) ) {
										$width  = false === $width ? false : min( $width, $src_per_wp[1] );
										$height = false === $height ? false : min( $height, $src_per_wp[2] );
									}

									// If no width and height are found, max out at source image's natural dimensions.
									// Otherwise, respect registered image sizes' cropping setting.
									if ( false === $width && false === $height ) {
										$width     = $src_per_wp[1];
										$height    = $src_per_wp[2];
										$transform = 'fit';
									} elseif ( isset( $size ) && array_key_exists( $size, $image_sizes ) && isset( $image_sizes[ $size ]['crop'] ) ) {
										$transform = (bool) $image_sizes[ $size ]['crop'] ? 'resize' : 'fit';
									}
								}
							} else {
								unset( $attachment_id );
								unset( $attachment );
							}
						}
					}

					// If image tag lacks width and height arguments, try to determine from strings WP appends to resized image filenames.
					if ( false === $width && false === $height ) {
						list( $width, $height ) = self::parse_dimensions_from_filename( $src );
					}

					$width_orig     = $width;
					$height_orig    = $height;
					$transform_orig = $transform;

					// If width is available, constrain to $content_width.
					if ( false !== $width && is_numeric( $content_width ) && $width > $content_width ) {
						if ( false !== $height ) {
							$height = round( ( $content_width * $height ) / $width );
						}
						$width = $content_width;
					}

					// Set a width if none is found and $content_width is available.
					// If width is set in this manner and height is available, use `fit` instead of `resize` to prevent skewing.
					if ( false === $width && is_numeric( $content_width ) ) {
						$width = (int) $content_width;

						if ( false !== $height ) {
							$transform = 'fit';
						}
					}

					// Detect if image source is for a custom-cropped thumbnail and prevent further URL manipulation.
					if ( ! $fullsize_url && preg_match_all( '#-e[a-z0-9]+(-\d+x\d+)?\.(' . implode( '|', self::$extensions ) . '){1}$#i', basename( $src ), $filename ) ) {
						$fullsize_url = true;
					}

					// Build URL, first maybe removing WP's resized string so we pass the original image to Photon.
					if ( ! $fullsize_url && 0 === strpos( $src, $upload_dir['baseurl'] ) ) {
						$src = self::strip_image_dimensions_maybe( $src );
					}

					// Build array of Photon args and expose to filter before passing to Photon URL function.
					$args = array();

					if ( false !== $width && false !== $height ) {
						$args[ $transform ] = $width . ',' . $height;
					} elseif ( false !== $width ) {
						$args['w'] = $width;
					} elseif ( false !== $height ) {
						$args['h'] = $height;
					}

					/**
					 * Filter the array of Photon arguments added to an image when it goes through Photon.
					 * By default, only includes width and height values.
					 *
					 * @see https://developer.wordpress.com/docs/photon/api/
					 *
					 * @module photon
					 *
					 * @since 2.0.0
					 *
					 * @param array $args Array of Photon Arguments.
					 * @param array $details {
					 *     Array of image details.
					 *
					 *     @type string    $tag            Image tag (Image HTML output).
					 *     @type string    $src            Image URL.
					 *     @type string    $src_orig       Original Image URL.
					 *     @type int|false $width          Image width.
					 *     @type int|false $height         Image height.
					 *     @type int|false $width_orig     Original image width before constrained by content_width.
					 *     @type int|false $height_orig    Original Image height before constrained by content_width.
					 *     @type string    $transform      Transform.
					 *     @type string    $transform_orig Original transform before constrained by content_width.
					 * }
					 */
					$args = apply_filters( 'jetpack_photon_post_image_args', $args, compact( 'tag', 'src', 'src_orig', 'width', 'height', 'width_orig', 'height_orig', 'transform', 'transform_orig' ) );

					$photon_url = jetpack_photon_url( $src, $args );

					// Modify image tag if Photon function provides a URL
					// Ensure changes are only applied to the current image by copying and modifying the matched tag, then replacing the entire tag with our modified version.
					if ( $src !== $photon_url ) {
						$new_tag = $tag;

						// If present, replace the link href with a Photoned URL for the full-size image.
						if ( ! empty( $images['link_url'][ $index ] ) && self::validate_image_url( $images['link_url'][ $index ] ) ) {
							$new_tag = preg_replace( '#(href=["|\'])' . preg_quote( $images['link_url'][ $index ], '#' ) . '(["|\'])#i', '\1' . jetpack_photon_url( $images['link_url'][ $index ] ) . '\2', $new_tag, 1 );
						}

						// Supplant the original source value with our Photon URL.
						$photon_url = esc_url( $photon_url );
						$new_tag    = str_replace( $src_orig, $photon_url, $new_tag );

						// If Lazy Load is in use, pass placeholder image through Photon.
						if ( isset( $placeholder_src ) && self::validate_image_url( $placeholder_src ) ) {
							$placeholder_src = jetpack_photon_url( $placeholder_src );

							if ( $placeholder_src !== $placeholder_src_orig ) {
								$new_tag = str_replace( $placeholder_src_orig, esc_url( $placeholder_src ), $new_tag );
							}

							unset( $placeholder_src );
						}

						// If we are not transforming the image with resize, fit, or letterbox (lb), then we should remove
						// the width and height arguments (including HTML4 percentages) from the image to prevent distortion.
						// Even if $args['w'] and $args['h'] are present, Photon does not crop to those dimensions. Instead,
						// it appears to favor height.
						//
						// If we are transforming the image via one of those methods, let's update the width and height attributes.
						if ( empty( $args['resize'] ) && empty( $args['fit'] ) && empty( $args['lb'] ) ) {
							$new_tag = preg_replace( '#(?<=\s)(width|height)=["|\']?[\d%]+["|\']?\s?#i', '', $new_tag );
						} else {
							$resize_args = isset( $args['resize'] ) ? $args['resize'] : false;
							if ( false === $resize_args ) {
								$resize_args = ( ! $resize_args && isset( $args['fit'] ) )
									? $args['fit']
									: false;
							}
							if ( false === $resize_args ) {
								$resize_args = ( ! $resize_args && isset( $args['lb'] ) )
									? $args['lb']
									: false;
							}

							$resize_args = array_map( 'trim', explode( ',', $resize_args ) );

							// (?<=\s)         - Ensure width or height attribute is preceded by a space
							// (width=["|\']?) - Matches, and captures, width=, width=", or width='
							// [\d%]+          - Matches 1 or more digits or percent signs
							// (["|\']?)       - Matches, and captures, ", ', or empty string
							// \s              - Ensures there's a space after the attribute
							$new_tag = preg_replace( '#(?<=\s)(width=["|\']?)[\d%]+(["|\']?)\s?#i', sprintf( '${1}%d${2} ', $resize_args[0] ), $new_tag );
							$new_tag = preg_replace( '#(?<=\s)(height=["|\']?)[\d%]+(["|\']?)\s?#i', sprintf( '${1}%d${2} ', $resize_args[1] ), $new_tag );
						}

						// Tag an image for dimension checking.
						if ( ! self::is_amp_endpoint() ) {
							$new_tag = preg_replace( '#(\s?/)?>(\s*</a>)?$#i', ' data-recalc-dims="1"\1>\2', $new_tag );
						}

						// Replace original tag with modified version.
						$content = str_replace( $tag, $new_tag, $content );
					}
				} elseif ( preg_match( '#^http(s)?://i[\d]{1}.wp.com#', $src ) && ! empty( $images['link_url'][ $index ] ) && self::validate_image_url( $images['link_url'][ $index ] ) ) {
					$new_tag = preg_replace( '#(href=["|\'])' . preg_quote( $images['link_url'][ $index ], '#' ) . '(["|\'])#i', '\1' . jetpack_photon_url( $images['link_url'][ $index ] ) . '\2', $tag, 1 );

					$content = str_replace( $tag, $new_tag, $content );
				}
			}
		}

		return $content;
	}

	/**
	 * Filter Core galleries
	 *
	 * @param array $galleries Gallery array.
	 *
	 * @return array
	 */
	public static function filter_the_galleries( $galleries ) {
		if ( empty( $galleries ) || ! is_array( $galleries ) ) {
			return $galleries;
		}

		// Pass by reference, so we can modify them in place.
		foreach ( $galleries as &$this_gallery ) {
			if ( is_string( $this_gallery ) ) {
				$this_gallery = self::filter_the_content( $this_gallery );
			}
		}
		unset( $this_gallery ); // break the reference.

		return $galleries;
	}

	/**
	 * Runs the image widget through photon.
	 *
	 * @param array $instance Image widget instance data.
	 * @return array
	 */
	public static function filter_the_image_widget( $instance ) {
		if ( Jetpack::is_module_active( 'photon' ) && ! $instance['attachment_id'] && $instance['url'] ) {
			jetpack_photon_url(
				$instance['url'],
				array(
					'w' => $instance['width'],
					'h' => $instance['height'],
				)
			);
		}

		return $instance;
	}

	/**
	 * * CORE IMAGE RETRIEVAL
	 **/

	/**
	 * Filter post thumbnail image retrieval, passing images through Photon
	 *
	 * @param string|bool  $image Image URL.
	 * @param int          $attachment_id Attachment ID.
	 * @param string|array $size Declared size or a size array.
	 * @uses is_admin, apply_filters, wp_get_attachment_url, self::validate_image_url, this::image_sizes, jetpack_photon_url
	 * @filter image_downsize
	 * @return string|bool
	 */
	public function filter_image_downsize( $image, $attachment_id, $size ) {
		// Don't foul up the admin side of things, unless a plugin wants to.
		if ( is_admin() &&
			/**
			 * Provide plugins a way of running Photon for images in the WordPress Dashboard (wp-admin).
			 *
			 * Note: enabling this will result in Photon URLs added to your post content, which could make migrations across domains (and off Photon) a bit more challenging.
			 *
			 * @module photon
			 *
			 * @since 4.8.0
			 *
			 * @param bool false Stop Photon from being run on the Dashboard. Default to false.
			 * @param array $args {
			 *   Array of image details.
			 *
			 *   @type $image Image URL.
			 *   @type $attachment_id Attachment ID of the image.
			 *   @type $size Image size. Can be a string (name of the image size, e.g. full) or an array of width and height.
			 * }
			 */
			false === apply_filters( 'jetpack_photon_admin_allow_image_downsize', false, compact( 'image', 'attachment_id', 'size' ) )
		) {
			return $image;
		}

		/**
		 * Provide plugins a way of preventing Photon from being applied to images retrieved from WordPress Core.
		 *
		 * @module photon
		 *
		 * @since 2.0.0
		 *
		 * @param bool false Stop Photon from being applied to the image. Default to false.
		 * @param array $args {
		 *   Array of image details.
		 *
		 *   @type $image Image URL.
		 *   @type $attachment_id Attachment ID of the image.
		 *   @type $size Image size. Can be a string (name of the image size, e.g. full) or an array of width and height.
		 * }
		 */
		if ( apply_filters( 'jetpack_photon_override_image_downsize', false, compact( 'image', 'attachment_id', 'size' ) ) ) {
			return $image;
		}

		// Get the image URL and proceed with Photon-ification if successful.
		$image_url = wp_get_attachment_url( $attachment_id );

		// Set this to true later when we know we have size meta.
		$has_size_meta = false;

		if ( $image_url ) {
			// Check if image URL should be used with Photon.
			if ( ! self::validate_image_url( $image_url ) ) {
				return $image;
			}

			$intermediate = true; // For the fourth array item returned by the image_downsize filter.

			// If an image is requested with a size known to WordPress, use that size's settings with Photon.
			// WP states that `add_image_size()` should use a string for the name, but doesn't enforce that.
			// Due to differences in how Core and Photon check for the registered image size, we check both types.
			if ( ( is_string( $size ) || is_int( $size ) ) && array_key_exists( $size, self::image_sizes() ) ) {
				$image_args = self::image_sizes();
				$image_args = $image_args[ $size ];

				$photon_args = array();

				$image_meta = image_get_intermediate_size( $attachment_id, $size );

				// 'full' is a special case: We need consistent data regardless of the requested size.
				if ( 'full' === $size ) {
					$image_meta   = wp_get_attachment_metadata( $attachment_id );
					$intermediate = false;
				} elseif ( ! $image_meta ) {
					// If we still don't have any image meta at this point, it's probably from a custom thumbnail size
					// for an image that was uploaded before the custom image was added to the theme.  Try to determine the size manually.
					$image_meta = wp_get_attachment_metadata( $attachment_id );

					if ( isset( $image_meta['width'], $image_meta['height'] ) ) {
						$image_resized = image_resize_dimensions( $image_meta['width'], $image_meta['height'], $image_args['width'], $image_args['height'], $image_args['crop'] );
						if ( $image_resized ) { // This could be false when the requested image size is larger than the full-size image.
							$image_meta['width']  = $image_resized[6];
							$image_meta['height'] = $image_resized[7];
						}
					}
				}

				if ( isset( $image_meta['width'], $image_meta['height'] ) ) {
					$image_args['width']  = (int) $image_meta['width'];
					$image_args['height'] = (int) $image_meta['height'];

					list( $image_args['width'], $image_args['height'] ) = image_constrain_size_for_editor( $image_args['width'], $image_args['height'], $size, 'display' );
					$has_size_meta                                      = true;
				}

				// Expose determined arguments to a filter before passing to Photon.
				$transform = $image_args['crop'] ? 'resize' : 'fit';

				// Check specified image dimensions and account for possible zero values; photon fails to resize if a dimension is zero.
				if ( 0 === $image_args['width'] || 0 === $image_args['height'] ) {
					if ( 0 === $image_args['width'] && 0 < $image_args['height'] ) {
						$photon_args['h'] = $image_args['height'];
					} elseif ( 0 === $image_args['height'] && 0 < $image_args['width'] ) {
						$photon_args['w'] = $image_args['width'];
					}
				} else {
					$image_meta = wp_get_attachment_metadata( $attachment_id );
					if ( ( 'resize' === $transform ) && $image_meta ) {
						if ( isset( $image_meta['width'], $image_meta['height'] ) ) {
							// Lets make sure that we don't upscale images since wp never upscales them as well.
							$smaller_width  = ( ( $image_meta['width'] < $image_args['width'] ) ? $image_meta['width'] : $image_args['width'] );
							$smaller_height = ( ( $image_meta['height'] < $image_args['height'] ) ? $image_meta['height'] : $image_args['height'] );

							$photon_args[ $transform ] = $smaller_width . ',' . $smaller_height;
						}
					} else {
						$photon_args[ $transform ] = $image_args['width'] . ',' . $image_args['height'];
					}
				}

				/**
				 * Filter the Photon Arguments added to an image when going through Photon, when that image size is a string.
				 * Image size will be a string (e.g. "full", "medium") when it is known to WordPress.
				 *
				 * @module photon
				 *
				 * @since 2.0.0
				 *
				 * @param array $photon_args Array of Photon arguments.
				 * @param array $args {
				 *   Array of image details.
				 *
				 *   @type array $image_args Array of Image arguments (width, height, crop).
				 *   @type string $image_url Image URL.
				 *   @type int $attachment_id Attachment ID of the image.
				 *   @type string|int $size Image size. Can be a string (name of the image size, e.g. full) or an integer.
				 *   @type string $transform Value can be resize or fit.
				 *                    @see https://developer.wordpress.com/docs/photon/api
				 * }
				 */
				$photon_args = apply_filters( 'jetpack_photon_image_downsize_string', $photon_args, compact( 'image_args', 'image_url', 'attachment_id', 'size', 'transform' ) );

				// Generate Photon URL.
				$image = array(
					jetpack_photon_url( $image_url, $photon_args ),
					$has_size_meta ? $image_args['width'] : false,
					$has_size_meta ? $image_args['height'] : false,
					$intermediate,
				);
			} elseif ( is_array( $size ) ) {
				// Pull width and height values from the provided array, if possible.
				$width  = isset( $size[0] ) ? (int) $size[0] : false;
				$height = isset( $size[1] ) ? (int) $size[1] : false;

				// Don't bother if necessary parameters aren't passed.
				if ( ! $width || ! $height ) {
					return $image;
				}

				$image_meta = wp_get_attachment_metadata( $attachment_id );
				if ( isset( $image_meta['width'], $image_meta['height'] ) ) {
					$image_resized = image_resize_dimensions( $image_meta['width'], $image_meta['height'], $width, $height );

					if ( $image_resized ) { // This could be false when the requested image size is larger than the full-size image.
						$width  = $image_resized[6];
						$height = $image_resized[7];
					} else {
						$width  = $image_meta['width'];
						$height = $image_meta['height'];
					}

					$has_size_meta = true;
				}

				list( $width, $height ) = image_constrain_size_for_editor( $width, $height, $size );

				// Expose arguments to a filter before passing to Photon.
				$photon_args = array(
					'fit' => $width . ',' . $height,
				);

				/**
				 * Filter the Photon Arguments added to an image when going through Photon,
				 * when the image size is an array of height and width values.
				 *
				 * @module photon
				 *
				 * @since 2.0.0
				 *
				 * @param array $photon_args Array of Photon arguments.
				 * @param array $args {
				 *   Array of image details.
				 *
				 *   @type $width Image width.
				 *   @type height Image height.
				 *   @type $image_url Image URL.
				 *   @type $attachment_id Attachment ID of the image.
				 * }
				 */
				$photon_args = apply_filters( 'jetpack_photon_image_downsize_array', $photon_args, compact( 'width', 'height', 'image_url', 'attachment_id' ) );

				// Generate Photon URL.
				$image = array(
					jetpack_photon_url( $image_url, $photon_args ),
					$has_size_meta ? $width : false,
					$has_size_meta ? $height : false,
					$intermediate,
				);
			}
		}

		return $image;
	}

	/**
	 * Filters an array of image `srcset` values, replacing each URL with its Photon equivalent.
	 *
	 * @since 3.8.0
	 * @since 4.0.4 Added automatically additional sizes beyond declared image sizes.
	 *
	 * @param array $sources An array of image urls and widths.
	 * @param array $size_array The size array for srcset.
	 * @param array $image_src The image srcs.
	 * @param array $image_meta The image meta.
	 * @param int   $attachment_id Attachment ID.
	 *
	 * @uses self::validate_image_url, jetpack_photon_url, Jetpack_Photon::parse_from_filename
	 * @uses Jetpack_Photon::strip_image_dimensions_maybe, Jetpack::get_content_width
	 *
	 * @return array An array of Photon image urls and widths.
	 */
	public function filter_srcset_array( $sources = array(), $size_array = array(), $image_src = array(), $image_meta = array(), $attachment_id = 0 ) {
		if ( ! is_array( $sources ) || array() === $sources ) {
			return $sources;
		}
		$upload_dir = wp_get_upload_dir();

		foreach ( $sources as $i => $source ) {
			if ( ! self::validate_image_url( $source['url'] ) ) {
				continue;
			}

			/** This filter is already documented in class.photon.php */
			if ( apply_filters( 'jetpack_photon_skip_image', false, $source['url'], $source ) ) {
				continue;
			}

			$url                    = $source['url'];
			list( $width, $height ) = self::parse_dimensions_from_filename( $url );

			// It's quicker to get the full size with the data we have already, if available.
			if ( ! empty( $attachment_id ) ) {
				$url = wp_get_attachment_url( $attachment_id );
			} else {
				$url = self::strip_image_dimensions_maybe( $url );
			}

			$args = array();
			if ( 'w' === $source['descriptor'] ) {
				if ( $height && ( (int) $source['value'] === $width ) ) {
					$args['resize'] = $width . ',' . $height;
				} else {
					$args['w'] = $source['value'];
				}
			}

			$sources[ $i ]['url'] = jetpack_photon_url( $url, $args );
		}

		/**
		 * At this point, $sources is the original srcset with Photonized URLs.
		 * Now, we're going to construct additional sizes based on multiples of the content_width.
		 * This will reduce the gap between the largest defined size and the original image.
		 */

		/**
		 * Filter the multiplier Photon uses to create new srcset items.
		 * Return false to short-circuit and bypass auto-generation.
		 *
		 * @module photon
		 *
		 * @since 4.0.4
		 *
		 * @param array|bool $multipliers Array of multipliers to use or false to bypass.
		 */
		$multipliers = apply_filters( 'jetpack_photon_srcset_multipliers', array( 2, 3 ) );
		$url         = trailingslashit( $upload_dir['baseurl'] ) . $image_meta['file'];

		if (
			/** Short-circuit via jetpack_photon_srcset_multipliers filter. */
			is_array( $multipliers )
			/** This filter is already documented in class.photon.php */
			&& ! apply_filters( 'jetpack_photon_skip_image', false, $url, null )
			/** Verify basic meta is intact. */
			&& isset( $image_meta['width'] ) && isset( $image_meta['height'] ) && isset( $image_meta['file'] )
			/** Verify we have the requested width/height. */
			&& isset( $size_array[0] ) && isset( $size_array[1] )
			) {

			$fullwidth  = $image_meta['width'];
			$fullheight = $image_meta['height'];
			$reqwidth   = $size_array[0];
			$reqheight  = $size_array[1];

			$constrained_size = wp_constrain_dimensions( $fullwidth, $fullheight, $reqwidth );
			$expected_size    = array( $reqwidth, $reqheight );

			if ( abs( $constrained_size[0] - $expected_size[0] ) <= 1 && abs( $constrained_size[1] - $expected_size[1] ) <= 1 ) {
				$crop = 'soft';
				$base = Jetpack::get_content_width() ? Jetpack::get_content_width() : 1000; // Provide a default width if none set by the theme.
			} else {
				$crop = 'hard';
				$base = $reqwidth;
			}

			$currentwidths = array_keys( $sources );
			$newsources    = null;

			foreach ( $multipliers as $multiplier ) {

				$newwidth = $base * $multiplier;
				foreach ( $currentwidths as $currentwidth ) {
					// If a new width would be within 100 pixes of an existing one or larger than the full size image, skip.
					if ( abs( $currentwidth - $newwidth ) < 50 || ( $newwidth > $fullwidth ) ) {
						continue 2; // Bump out back to the $multipliers as $multiplier.
					}
				} //end foreach ( $currentwidths as $currentwidth ){

				if ( 'soft' === $crop ) {
					$args = array(
						'w' => $newwidth,
					);
				} else { // hard crop, e.g. add_image_size( 'example', 200, 200, true ).
					$args = array(
						'zoom'   => $multiplier,
						'resize' => $reqwidth . ',' . $reqheight,
					);
				}

				$newsources[ $newwidth ] = array(
					'url'        => jetpack_photon_url( $url, $args ),
					'descriptor' => 'w',
					'value'      => $newwidth,
				);
			} //end foreach ( $multipliers as $multiplier )
			if ( is_array( $newsources ) ) {
				$sources = array_replace( $sources, $newsources );
			}
		} //end if isset( $image_meta['width'] ) && isset( $image_meta['file'] ) )

		return $sources;
	}

	/**
	 * Filters an array of image `sizes` values, using $content_width instead of image's full size.
	 *
	 * @since 4.0.4
	 * @since 4.1.0 Returns early for images not within the_content.
	 * @param array $sizes An array of media query breakpoints.
	 * @param array $size  Width and height of the image.
	 * @uses Jetpack::get_content_width
	 * @return array An array of media query breakpoints.
	 */
	public function filter_sizes( $sizes, $size ) {
		if ( ! doing_filter( 'the_content' ) ) {
			return $sizes;
		}
		$content_width = Jetpack::get_content_width();
		if ( ! $content_width ) {
			$content_width = 1000;
		}

		if ( ( is_array( $size ) && $size[0] < $content_width ) ) {
			return $sizes;
		}

		return sprintf( '(max-width: %1$dpx) 100vw, %1$dpx', $content_width );
	}

	/**
	 * * GENERAL FUNCTIONS
	 **/

	/**
	 * Ensure image URL is valid for Photon.
	 * Though Photon functions address some of the URL issues, we should avoid unnecessary processing if we know early on that the image isn't supported.
	 *
	 * @param string $url Image URL.
	 * @uses wp_parse_args
	 * @return bool
	 */
	protected static function validate_image_url( $url ) {
		$parsed_url = wp_parse_url( $url );

		if ( ! $parsed_url ) {
			return false;
		}

		// Parse URL and ensure needed keys exist, since the array returned by `wp_parse_url` only includes the URL components it finds.
		$url_info = wp_parse_args(
			$parsed_url,
			array(
				'scheme' => null,
				'host'   => null,
				'port'   => null,
				'path'   => null,
			)
		);

		// Bail if scheme isn't http or port is set that isn't port 80.
		if (
			( 'http' !== $url_info['scheme'] || ! in_array( $url_info['port'], array( 80, null ), true ) ) &&
			/**
			 * Allow Photon to fetch images that are served via HTTPS.
			 *
			 * @module photon
			 *
			 * @since 2.4.0
			 * @since 3.9.0 Default to false.
			 *
			 * @param bool $reject_https Should Photon ignore images using the HTTPS scheme. Default to false.
			 */
			apply_filters( 'jetpack_photon_reject_https', false )
		) {
			return false;
		}

		// Bail if no host is found.
		if ( $url_info['host'] === null ) {
			return false;
		}

		// Bail if the image already went through Photon.
		if ( preg_match( '#^i[\d]{1}.wp.com$#i', $url_info['host'] ) ) {
			return false;
		}

		// Bail if no path is found.
		if ( $url_info['path'] === null ) {
			return false;
		}

		// Ensure image extension is acceptable.
		if ( ! in_array( strtolower( pathinfo( $url_info['path'], PATHINFO_EXTENSION ) ), self::$extensions, true ) ) {
			return false;
		}

		// If we got this far, we should have an acceptable image URL
		// But let folks filter to decline if they prefer.
		/**
		 * Overwrite the results of the validation steps an image goes through before to be considered valid to be used by Photon.
		 *
		 * @module photon
		 *
		 * @since 3.0.0
		 *
		 * @param bool true Is the image URL valid and can it be used by Photon. Default to true.
		 * @param string $url Image URL.
		 * @param array $parsed_url Array of information about the image.
		 */
		return apply_filters( 'photon_validate_image_url', true, $url, $parsed_url );
	}

	/**
	 * Checks if the file exists before it passes the file to photon.
	 *
	 * @param string $src The image URL.
	 * @return string
	 **/
	public static function strip_image_dimensions_maybe( $src ) {
		$stripped_src = $src;

		// Build URL, first removing WP's resized string so we pass the original image to Photon.
		if ( preg_match( '#(-\d+x\d+)\.(' . implode( '|', self::$extensions ) . '){1}$#i', $src, $src_parts ) ) {
			$stripped_src = str_replace( $src_parts[1], '', $src );
			$upload_dir   = wp_get_upload_dir();

			// Extracts the file path to the image minus the base url.
			$file_path = substr( $stripped_src, strlen( $upload_dir['baseurl'] ) );

			if ( file_exists( $upload_dir['basedir'] . $file_path ) ) {
				$src = $stripped_src;
			}
		}

		return $src;
	}

	/**
	 * Provide an array of available image sizes and corresponding dimensions.
	 * Similar to get_intermediate_image_sizes() except that it includes image sizes' dimensions, not just their names.
	 *
	 * @global $wp_additional_image_sizes
	 * @uses get_option
	 * @return array
	 */
	protected static function image_sizes() {
		if ( null === self::$image_sizes ) {
			global $_wp_additional_image_sizes;

			// Populate an array matching the data structure of $_wp_additional_image_sizes so we have a consistent structure for image sizes.
			$images = array(
				'thumb'        => array(
					'width'  => (int) get_option( 'thumbnail_size_w' ),
					'height' => (int) get_option( 'thumbnail_size_h' ),
					'crop'   => (bool) get_option( 'thumbnail_crop' ),
				),
				'medium'       => array(
					'width'  => (int) get_option( 'medium_size_w' ),
					'height' => (int) get_option( 'medium_size_h' ),
					'crop'   => false,
				),
				'medium_large' => array(
					'width'  => (int) get_option( 'medium_large_size_w' ),
					'height' => (int) get_option( 'medium_large_size_h' ),
					'crop'   => false,
				),
				'large'        => array(
					'width'  => (int) get_option( 'large_size_w' ),
					'height' => (int) get_option( 'large_size_h' ),
					'crop'   => false,
				),
				'full'         => array(
					'width'  => null,
					'height' => null,
					'crop'   => false,
				),
			);

			// Compatibility mapping as found in wp-includes/media.php.
			$images['thumbnail'] = $images['thumb'];

			// Update class variable, merging in $_wp_additional_image_sizes if any are set.
			if ( is_array( $_wp_additional_image_sizes ) && ! empty( $_wp_additional_image_sizes ) ) {
				self::$image_sizes = array_merge( $images, $_wp_additional_image_sizes );
			} else {
				self::$image_sizes = $images;
			}
		}

		return is_array( self::$image_sizes ) ? self::$image_sizes : array();
	}

	/**
	 * Pass og:image URLs through Photon
	 *
	 * @param array $tags Open graph tags.
	 * @param array $parameters Image parameters.
	 * @uses jetpack_photon_url
	 * @return array Open graph tags.
	 */
	public function filter_open_graph_tags( $tags, $parameters ) {
		if ( empty( $tags['og:image'] ) ) {
			return $tags;
		}

		$photon_args = array(
			'fit' => sprintf( '%d,%d', 2 * $parameters['image_width'], 2 * $parameters['image_height'] ),
		);

		if ( is_array( $tags['og:image'] ) ) {
			$images = array();
			foreach ( $tags['og:image'] as $image ) {
				$images[] = jetpack_photon_url( $image, $photon_args );
			}
			$tags['og:image'] = $images;
		} else {
			$tags['og:image'] = jetpack_photon_url( $tags['og:image'], $photon_args );
		}

		return $tags;
	}

	/**
	 * Enqueue Photon helper script
	 *
	 * @uses wp_enqueue_script, plugins_url
	 * @action wp_enqueue_script
	 * @return null
	 */
	public function action_wp_enqueue_scripts() {
		if ( self::is_amp_endpoint() ) {
			return;
		}
		wp_enqueue_script(
			'jetpack-photon',
			Assets::get_file_url_for_environment(
				'_inc/build/photon/photon.min.js',
				'modules/photon/photon.js'
			),
			array(),
			20191001,
			true
		);
	}

	/**
	 * Determine if image_downsize should utilize Photon via REST API.
	 *
	 * The WordPress Block Editor (Gutenberg) and other REST API consumers using the wp/v2/media endpoint, especially in the "edit"
	 * context is more akin to the is_admin usage of Photon (see filter_image_downsize). Since consumers are trying to edit content in posts,
	 * Photon should not fire as it will fire later on display. By aborting an attempt to Photonize an image here, we
	 * prevents issues like https://github.com/Automattic/jetpack/issues/10580 .
	 *
	 * To determine if we're using the wp/v2/media endpoint, we hook onto the `rest_request_before_callbacks` filter and
	 * if determined we are using it in the edit context, we'll false out the `jetpack_photon_override_image_downsize` filter.
	 *
	 * @see Jetpack_Photon::filter_image_downsize()
	 *
	 * @param null|WP_Error   $response REST API response.
	 * @param array           $endpoint_data Endpoint data. Not used, but part of the filter.
	 * @param WP_REST_Request $request  Request used to generate the response.
	 *
	 * @return null|WP_Error The original response object without modification.
	 */
	public function should_rest_photon_image_downsize( $response, $endpoint_data, $request ) {
		if ( ! is_a( $request, 'WP_REST_Request' ) ) {
			return $response; // Something odd is happening. Do nothing and return the response.
		}

		if ( is_wp_error( $response ) ) {
			// If we're going to return an error, we don't need to do anything with Photon.
			return $response;
		}

		$this->should_rest_photon_image_downsize_override( $request );

		return $response;
	}

	/**
	 * Helper function to check if a WP_REST_Request is the media endpoint in the edit context.
	 *
	 * @param WP_REST_Request $request The current REST request.
	 */
	private function should_rest_photon_image_downsize_override( WP_REST_Request $request ) {
		$route = $request->get_route();

		if (
			(
				false !== strpos( $route, 'wp/v2/media' )
				&& 'edit' === $request->get_param( 'context' )
			)
			|| false !== strpos( $route, 'wpcom/v2/external-media/copy' )
			|| (bool) $request->get_header( 'x-wp-api-fetch-from-editor' )
		) {
			// Don't use `__return_true()`: Use something unique. See ::_override_image_downsize_in_rest_edit_context()
			// Late execution to avoid conflict with other plugins as we really don't want to run in this situation.
			add_filter(
				'jetpack_photon_override_image_downsize',
				array(
					$this,
					'override_image_downsize_in_rest_edit_context',
				),
				999999
			);
		}
	}

	/**
	 * Brings in should_rest_photon_image_downsize for the rest_after_insert_attachment hook.
	 *
	 * @since 8.7.0
	 *
	 * @param WP_Post         $attachment Inserted or updated attachment object.
	 * @param WP_REST_Request $request    Request object.
	 */
	public function should_rest_photon_image_downsize_insert_attachment( WP_Post $attachment, WP_REST_Request $request ) {
		if ( ! is_a( $request, 'WP_REST_Request' ) ) {
			// Something odd is happening.
			return;
		}

		$this->should_rest_photon_image_downsize_override( $request );
	}

	/**
	 * Remove the override we may have added in ::should_rest_photon_image_downsize()
	 * Since ::_override_image_downsize_in_rest_edit_context() is only
	 * every used here, we can always remove it without ever worrying
	 * about breaking any other configuration.
	 *
	 * @param mixed $response REST API Response.
	 * @return mixed Unchanged $response
	 */
	public function cleanup_rest_photon_image_downsize( $response ) {
		remove_filter(
			'jetpack_photon_override_image_downsize',
			array(
				$this,
				'override_image_downsize_in_rest_edit_context',
			),
			999999
		);
		return $response;
	}

	/**
	 * Used internally by ::should_rest_photon_image_downsize() to not photonize
	 * image URLs in ?context=edit REST requests.
	 * MUST NOT be used anywhere else.
	 * We use a unique function instead of __return_true so that we can clean up
	 * after ourselves without breaking anyone else's filters.
	 *
	 * @internal
	 * @return true
	 */
	public function override_image_downsize_in_rest_edit_context() {
		return true;
	}

	/**
	 * Return whether the current page is AMP.
	 *
	 * This is only present for the sake of WordPress.com where the Jetpack_AMP_Support
	 * class does not yet exist. This mehod may only be called at the wp action or later.
	 *
	 * @return bool Whether AMP page.
	 */
	private static function is_amp_endpoint() {
		return class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request();
	}
}
