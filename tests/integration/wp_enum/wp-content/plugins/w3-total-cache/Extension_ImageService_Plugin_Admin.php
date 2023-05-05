<?php
/**
 * File: Extension_ImageService_Plugin_Admin.php
 *
 * @since 2.2.0
 *
 * @package W3TC
 *
 * phpcs:disable Squiz.PHP.EmbeddedPhp.ContentBeforeOpen, Squiz.PHP.EmbeddedPhp.ContentAfterEnd
 */

namespace W3TC;

/**
 * Class: Extension_ImageService_Plugin_Admin
 *
 * @since 2.2.0
 */
class Extension_ImageService_Plugin_Admin {
	/**
	 * Image MIME types available for optimization.
	 *
	 * @since 2.2.0
	 * @static
	 *
	 * @var array
	 */
	public static $mime_types = array(
		'gif'  => 'image/gif',
		'jpeg' => 'image/jpeg',
		'jpg'  => 'image/jpg',
		'png'  => 'image/png',
	);

	/**
	 * Configuration.
	 *
	 * @since 2.2.0
	 * @access private
	 *
	 * @var Config
	 */
	private $config;

	/**
	 * Image Service API class object.
	 *
	 * @since 2.2.0
	 * @access private
	 *
	 * @var Extension_ImageService_API
	 */
	private $api;

	/**
	 * Constructor.
	 *
	 * @since 2.2.0
	 */
	public function __construct() {
		$this->config = Dispatcher::config();
	}

	/**
	 * Get extension information.
	 *
	 * @since 2.2.0
	 * @static
	 *
	 * @global $wp_version WordPress core version.
	 *
	 * @param  array $extensions Extensions.
	 * @param  array $config Configuration.
	 * @return array
	 */
	public static function w3tc_extensions( $extensions, $config ) {
		global $wp_version;

		$description = __(
			'Adds the ability to convert images in the Media Library to the modern WebP format for better performance.',
			'w3-total-cache'
		);

		if ( version_compare( $wp_version, '5.8', '<' ) ) {
			$description .= sprintf(
				// translators: 1: HTML break, 2: WordPress version string, 3: HTML archor open tag, 4: HTML archor close tag.
				__(
					'%1$sThis extension works best in WordPress version 5.8 and higher.  You are running WordPress version %2$s.  Please %3$supdate now%4$s to benefit from this feature.',
					'w3-total-cache'
				),
				'<br />',
				$wp_version,
				'<a href="' . esc_url( admin_url( 'update-core.php' ) ) . '">',
				'</a>'
			);
		}

		$settings_url = esc_url( Util_Ui::admin_url( 'upload.php?page=w3tc_extension_page_imageservice&w3tc_imageservice_action=dismiss_activation_notice' ) );
		$library_url  = esc_url( Util_Ui::admin_url( 'upload.php?mode=list' ) );

		$extensions['imageservice'] = array(
			'name'             => 'Image Service',
			'author'           => 'BoldGrid',
			'description'      => esc_html( $description ),
			'author_uri'       => 'https://www.boldgrid.com/',
			'extension_uri'    => 'https://www.boldgrid.com/w3-total-cache/',
			'extension_id'     => 'imageservice',
			'settings_exists'  => false,
			'version'          => '1.0',
			'enabled'          => true,
			'disabled_message' => '',
			'requirements'     => '',
			'path'             => 'w3-total-cache/Extension_ImageService_Plugin.php',
			'notice'           => sprintf(
				// translators: 1: HTML anchor open tag, 2: HTML anchor close tag, 3: HTML anchor open tag, 4: HTML anchor open tag.
				__(
					'Total Cache Image Service has been activated. Now, you can %1$sadjust the settings%2$s or go to the %3$sMedia Library%2$s to convert images to WebP.  %4$sLearn more%2$s.',
					'w3-total-cache'
				),
				'<a class="edit" href="' . $settings_url . '">',
				'</a>',
				'<a class="edit" href="' . $library_url . '">',
				'<a target="_blank" href="' . esc_url(
					'https://www.boldgrid.com/support/w3-total-cache/image-service/?utm_source=w3tc&utm_medium=activation_notice&utm_campaign=imageservice'
				) . '">'
			),
		);

		// The settings and Media Library links are only valid for single and network sites; not the admin section.
		if ( ! is_network_admin() ) {
			$extensions['imageservice']['extra_links'] = array(
				'<a class="edit" href="' . $settings_url . '">' . esc_html__( 'Settings', 'w3-total-cache' ) . '</a>',
				'<a class="edit" href="' . $library_url . '">' . esc_html__( 'Media Library', 'w3-total-cache' ) . '</a>',
			);
		}

		return $extensions;
	}

	/**
	 * Load the admin extension.
	 *
	 * Runs on the "wp_loaded" action.
	 *
	 * @since 2.2.0
	 * @static
	 */
	public static function w3tc_extension_load_admin() {
		$o = new Extension_ImageService_Plugin_Admin();

		// Enqueue scripts.
		add_action( 'admin_enqueue_scripts', array( $o, 'admin_enqueue_scripts' ) );

		/**
		 * Filters the Media list table columns.
		 *
		 * @since 2.5.0
		 *
		 * @param string[] $posts_columns An array of columns displayed in the Media list table.
		 * @param bool     $detached      Whether the list table contains media not attached
		 *                                to any posts. Default true.
		 */
		add_filter( 'manage_media_columns', array( $o, 'add_media_column' ) );

		/**
		 * Fires for each custom column in the Media list table.
		 *
		 * Custom columns are registered using the {@see 'manage_media_columns'} filter.
		 *
		 * @since 2.5.0
		 *
		 * @param string $column_name Name of the custom column.
		 * @param int    $post_id     Attachment ID.
		 */
		add_action( 'manage_media_custom_column', array( $o, 'media_column_row' ), 10, 2 );

		// AJAX hooks.
		add_action( 'wp_ajax_w3tc_imageservice_submit', array( $o, 'ajax_submit' ) );
		add_action( 'wp_ajax_w3tc_imageservice_postmeta', array( $o, 'ajax_get_postmeta' ) );
		add_action( 'wp_ajax_w3tc_imageservice_revert', array( $o, 'ajax_revert' ) );
		add_action( 'wp_ajax_w3tc_imageservice_all', array( $o, 'ajax_convert_all' ) );
		add_action( 'wp_ajax_w3tc_imageservice_revertall', array( $o, 'ajax_revert_all' ) );
		add_action( 'wp_ajax_w3tc_imageservice_counts', array( $o, 'ajax_get_counts' ) );
		add_action( 'wp_ajax_w3tc_imageservice_usage', array( $o, 'ajax_get_usage' ) );

		// Admin notices.
		add_action( 'admin_notices', array( $o, 'display_notices' ) );

		/**
		 * Ensure all network sites include WebP support.
		 *
		 * @link https://make.wordpress.org/core/2021/06/07/wordpress-5-8-adds-webp-support/
		 */
		add_filter(
			'site_option_upload_filetypes',
			function ( $filetypes ) {
				$filetypes = explode( ' ', $filetypes );
				if ( ! in_array( 'webp', $filetypes, true ) ) {
					$filetypes[] = 'webp';
				}

				return implode( ' ', $filetypes );
			}
		);

		// Add bulk actions.
		add_filter( 'bulk_actions-upload', array( $o, 'add_bulk_actions' ) );

		/**
		 * Fires when a custom bulk action should be handled.
		 *
		 * The redirect link should be modified with success or failure feedback
		 * from the action to be used to display feedback to the user.
		 *
		 * The dynamic portion of the hook name, `$screen`, refers to the current screen ID.
		 *
		 * @since 4.7.0
		 *
		 * @link https://core.trac.wordpress.org/browser/tags/5.8/src/wp-admin/upload.php#L206
		 *
		 * @param string $sendback The redirect URL.
		 * @param string $doaction The action being taken.
		 * @param array  $items    The items to take the action on. Accepts an array of IDs of posts,
		 *                         comments, terms, links, plugins, attachments, or users.
		 */
		add_filter( 'handle_bulk_actions-upload', array( $o, 'handle_bulk_actions' ), 10, 3 );

		/**
		 * Handle auto-optimization on upload.
		 *
		 * @link https://core.trac.wordpress.org/browser/tags/5.8/src/wp-includes/post.php#L4401
		 * @link https://developer.wordpress.org/reference/hooks/add_attachment/
		 *
		 * Fires once an attachment has been added.
		 *
		 * @since 2.0.0
		 *
		 * @param int $post_ID Attachment ID.
		 */
		add_action( 'add_attachment', array( $o, 'auto_convert' ) );

		/**
		 * Delete optimizations on parent image delation.
		 *
		 * @link https://core.trac.wordpress.org/browser/tags/5.8/src/wp-includes/post.php#L6134
		 * @link https://developer.wordpress.org/reference/hooks/pre_delete_attachment/
		 *
		 * Filters whether an attachment deletion should take place.
		 *
		 * @since 5.5.0
		 *
		 * @param bool|null $delete       Whether to go forward with deletion.
		 * @param WP_Post   $post         Post object.
		 * @param bool      $force_delete Whether to bypass the Trash.
		 */
		add_filter( 'pre_delete_attachment', array( $o, 'cleanup_optimizations' ), 10, 3 );

		// Add admin menu items.
		add_action( 'admin_menu', array( $o, 'admin_menu' ) );
	}

	/**
	 * Get all images with postmeta key "w3tc_imageservice".
	 *
	 * @since 2.2.0
	 * @static
	 *
	 * @link https://developer.wordpress.org/reference/classes/wp_query/
	 *
	 * @return WP_Query
	 */
	public static function get_imageservice_attachments() {
		return new \WP_Query(
			array(
				'post_type'           => 'attachment',
				'post_status'         => 'inherit',
				'post_mime_type'      => self::$mime_types,
				'posts_per_page'      => -1,
				'ignore_sticky_posts' => true,
				'suppress_filters'    => true,
				'meta_key'            => 'w3tc_imageservice', // phpcs:ignore WordPress.DB.SlowDBQuery
			)
		);
	}

	/**
	 * Get all images without postmeta key "w3tc_imageservice".
	 *
	 * @since 2.2.0
	 * @static
	 *
	 * @link https://developer.wordpress.org/reference/classes/wp_query/
	 *
	 * @return WP_Query
	 */
	public static function get_eligible_attachments() {
		return new \WP_Query(
			array(
				'post_type'           => 'attachment',
				'post_status'         => 'inherit',
				'post_mime_type'      => self::$mime_types,
				'posts_per_page'      => -1,
				'ignore_sticky_posts' => true,
				'suppress_filters'    => true,
				'meta_key'            => 'w3tc_imageservice', // phpcs:ignore WordPress.DB.SlowDBQuery
				'meta_compare'        => 'NOT EXISTS',
			)
		);
	}

	/**
	 * Get an attachment filesize.
	 *
	 * @since 2.2.0
	 *
	 * @global $wp_filesystem
	 *
	 * @param int $post_id Post id.
	 * @return int
	 */
	public function get_attachment_filesize( $post_id ) {
		WP_Filesystem();
		global $wp_filesystem;

		$size     = 0;
		$filepath = get_attached_file( $post_id );

		if ( $wp_filesystem->exists( $filepath ) ) {
			$size = $wp_filesystem->size( $filepath );
		}

		return $size;
	}

	/**
	 * Get image counts by status.
	 *
	 * @since 2.2.0
	 *
	 * @see self::get_imageservice_attachments()
	 * @see self::get_eligible_attachments()
	 *
	 * @return array
	 */
	public function get_counts() {
		$unconverted_posts  = self::get_eligible_attachments();
		$counts             = array(
			'sending'      => 0,
			'processing'   => 0,
			'converted'    => 0,
			'notconverted' => 0,
			'unconverted'  => $unconverted_posts->post_count,
			'total'        => 0,
		);
		$bytes              = array(
			'sending'      => 0,
			'processing'   => 0,
			'converted'    => 0,
			'notconverted' => 0,
			'unconverted'  => 0,
			'total'        => 0,
		);
		$imageservice_posts = self::get_imageservice_attachments()->posts;

		foreach ( $imageservice_posts as $post ) {
			$imageservice_data = get_post_meta( $post->ID, 'w3tc_imageservice', true );
			$status            = isset( $imageservice_data['status'] ) ? $imageservice_data['status'] : null;
			$filesize_in       = isset( $imageservice_data['download']["\0*\0data"]['x-filesize-in'] ) ?
				$imageservice_data['download']["\0*\0data"]['x-filesize-in'] : 0;
			$filesize_out      = isset( $imageservice_data['download']["\0*\0data"]['x-filesize-out'] ) ?
				$imageservice_data['download']["\0*\0data"]['x-filesize-out'] : 0;

			switch ( $status ) {
				case 'sending':
					$size = $this->get_attachment_filesize( $post->ID );
					$counts['sending']++;
					$bytes['sending'] += $size;
					$bytes['total']   += $size;
					break;
				case 'processing':
					$size = $this->get_attachment_filesize( $post->ID );
					$counts['processing']++;
					$bytes['processing'] += $size;
					$bytes['total']      += $size;
					break;
				case 'converted':
					$counts['converted']++;
					$bytes['converted'] += $filesize_in - $filesize_out;
					$bytes['total']     += $filesize_in - $filesize_out;
					break;
				case 'notconverted':
					$size = $this->get_attachment_filesize( $post->ID );
					$counts['notconverted']++;
					$bytes['notconverted'] += $size;
					$bytes['total']        += $size;
					break;
				case 'unconverted':
					$size = $this->get_attachment_filesize( $post->ID );
					$counts['unconverted']++;
					$bytes['unconverted'] += $size;
					$bytes['total']       += $size;
					break;
				default:
					break;
			}
		}

		foreach ( $unconverted_posts->posts as $post ) {
			$size = $this->get_attachment_filesize( $post->ID );

			if ( $size ) {
				$bytes['unconverted'] += $size;
				$bytes['total']       += $size;
			}
		}

		$counts['total']             = array_sum( $counts );
		$counts['totalbytes']        = $bytes['total'];
		$counts['sendingbytes']      = $bytes['sending'];
		$counts['processingbytes']   = $bytes['processing'];
		$counts['convertedbytes']    = $bytes['converted'];
		$counts['notconvertedbytes'] = $bytes['notconverted'];
		$counts['unconvertedbytes']  = $bytes['unconverted'];

		return $counts;
	}

	/**
	 * Load the extension settings page view.
	 *
	 * @since 2.2.0
	 *
	 * @see Extension_ImageService_Plugin::get_api()
	 * @see Extension_ImageService_Api::get_usage()
	 */
	public function settings_page() {
		$c      = $this->config;
		$counts = $this->get_counts();
		$usage  = get_transient( 'w3tc_imageservice_usage' );

		// Delete transient for displaying activation notice.
		delete_transient( 'w3tc_activation_imageservice' );

		// Save submitted settings.
		$nonce_val                    = Util_Request::get_string( '_wpnonce' );
		$imageservice_compression_val = Util_Request::get_string( 'imageservice___compression' );
		if ( ! empty( $imageservice_compression_val ) && ! empty( $nonce_val ) && wp_verify_nonce( $nonce_val, 'w3tc' ) ) {
			$settings                = $c->get_array( 'imageservice' );
			$settings['compression'] = $imageservice_compression_val;

			$imageservice_auto_val = Util_Request::get_string( 'imageservice___auto' );
			if ( ! empty( $imageservice_auto_val ) ) {
				$settings['auto'] = $imageservice_auto_val;
			}

			$imageservice_visibility_val = Util_Request::get_string( 'imageservice___visibility' );
			if ( ! empty( $imageservice_visibility_val ) ) {
				$settings['visibility'] = $imageservice_visibility_val;
			}

			$c->set( 'imageservice', $settings );
			$c->save();

			// Display notice when saving settings.
			?>
			<div class="notice notice-success is-dismissible">
				<p><?php esc_html_e( 'Settings saved.', 'w3-total-cache' ); ?></p>
			</div>
			<?php
		}

		// If usage is not stored, then retrieve it from the API.
		if ( empty( $usage ) ) {
			$usage = Extension_ImageService_Plugin::get_api()->get_usage();
		}

		// Ensure that the monthly limit is represented correctly.
		$usage['limit_monthly'] = $usage['limit_monthly'] ? $usage['limit_monthly'] : __( 'Unlimited', 'w3-total-cache' );

		require W3TC_DIR . '/Extension_ImageService_Page_View.php';
	}

	/**
	 * Add admin menu items.
	 *
	 * @since 2.2.0
	 */
	public function admin_menu() {
		// Add settings submenu to Media top-level menu.
		add_submenu_page(
			'upload.php',
			esc_html__( 'Total Cache Image Service', 'w3-total-cache' ),
			esc_html__( 'Total Cache Image Service', 'w3-total-cache' ),
			'edit_posts',
			'w3tc_extension_page_imageservice',
			array( $this, 'settings_page' )
		);
	}

	/**
	 * Enqueue scripts and styles for admin pages.
	 *
	 * Runs on the "admin_enqueue_scripts" action.
	 *
	 * @since 2.2.0
	 *
	 * @see Util_Ui::admin_url()
	 * @see Licensing_Core::get_tos_choice()
	 */
	public function admin_enqueue_scripts() {
		// Enqueue JavaScript for the Media Library (upload) and extension settings admin pages.
		$page_val         = Util_Request::get_string( 'page' );
		$is_settings_page = ! empty( $page_val ) && 'w3tc_extension_page_imageservice' === $page_val;
		$is_media_page    = 'upload' === get_current_screen()->id;

		if ( $is_settings_page ) {
			wp_enqueue_style( 'w3tc-options' );
		}

		if ( $is_settings_page || $is_media_page ) {
			wp_localize_script( 'w3tc-lightbox', 'w3tc_nonce', array( wp_create_nonce( 'w3tc' ) ) );
			wp_enqueue_script( 'w3tc-lightbox' );
			wp_enqueue_style( 'w3tc-lightbox' );

			wp_register_script(
				'w3tc-imageservice',
				esc_url( plugin_dir_url( __FILE__ ) . 'Extension_ImageService_Plugin_Admin.js' ),
				array( 'jquery' ),
				W3TC_VERSION,
				true
			);

			wp_localize_script(
				'w3tc-imageservice',
				'w3tcData',
				array(
					'nonces'      => array(
						'submit'   => wp_create_nonce( 'w3tc_imageservice_submit' ),
						'postmeta' => wp_create_nonce( 'w3tc_imageservice_postmeta' ),
						'revert'   => wp_create_nonce( 'w3tc_imageservice_revert' ),
					),
					'lang'        => array(
						'convert'          => __( 'Convert', 'w3-total-cache' ),
						'sending'          => __( 'Sending...', 'w3-total-cache' ),
						'submitted'        => __( 'Submitted', 'w3-total-cache' ),
						'processing'       => __( 'Processing...', 'w3-total-cache' ),
						'converted'        => __( 'Converted', 'w3-total-cache' ),
						'notConverted'     => __( 'Not converted', 'w3-total-cache' ),
						'reverting'        => __( 'Reverting...', 'w3-total-cache' ),
						'reverted'         => __( 'Reverted', 'w3-total-cache' ),
						'revert'           => __( 'Revert', 'w3-total-cache' ),
						'error'            => __( 'Error', 'w3-total-cache' ),
						'ajaxFail'         => __( 'Failed to retrieve a response.  Please reload the page to try again.', 'w3-total-cache' ),
						'apiError'         => __( 'API error.  Please reload the page to try again,', 'w3-total-cache' ),
						'refresh'          => __( 'Refresh', 'w3-total-cache' ),
						'refreshing'       => __( 'Refreshing...', 'w3-total-cache' ),
						'settings'         => __( 'Settings', 'w3-total-cache' ),
						'submittedAllDesc' => sprintf(
							// translators: 1: HTML anchor open tag, 2: HTML anchor close tag.
							__( 'Images queued for conversion.  Progress can be seen in the %1$sMedia Library%2$s.', 'w3-total-cache' ),
							'<a href="' . esc_url( Util_Ui::admin_url( 'upload.php?mode=list' ) ) . '">',
							'</a>'
						),
						'notConvertedDesc' => sprintf(
							// translators: 1: HTML anchor open tag, 2: HTML anchor close tag.
							__( 'The converted image would be larger than the original; conversion canceled.  %1$sLearn more%2$s.', 'w3-total-cache' ),
							'<a target="_blank" href="' . esc_url(
								'https://www.boldgrid.com/support/w3-total-cache/image-service#conversion-canceled/?utm_source=w3tc&utm_medium=conversion_canceled&utm_campaign=imageservice'
							) . '">',
							'</a>'
						),
					),
					'tos_choice'  => Licensing_Core::get_tos_choice(),
					'track_usage' => $this->config->get_boolean( 'common.track_usage' ),
					'ga_profile'  => ( defined( 'W3TC_DEBUG' ) && W3TC_DEBUG ) ? 'UA-2264433-7' : 'UA-2264433-8',
					'settings'    => $this->config->get_array( 'imageservice' ),
					'settingsUrl' => esc_url( Util_Ui::admin_url( 'upload.php?page=w3tc_extension_page_imageservice' ) ),
				)
			);

			wp_enqueue_script( 'w3tc-imageservice' );

			wp_enqueue_style(
				'w3tc-imageservice',
				esc_url( plugin_dir_url( __FILE__ ) . 'Extension_ImageService_Plugin_Admin.css' ),
				array(),
				W3TC_VERSION,
				'all'
			);
		}
	}

	/**
	 * Add image service controls to the Media Library table in list view.
	 *
	 * Runs on the "manage_media_columns" filter.
	 *
	 * @since 2.2.0
	 *
	 * @param string[] $posts_columns An array of columns displayed in the Media list table.
	 * @param bool     $detached      Whether the list table contains media not attached
	 *                                to any posts. Default true.
	 */
	public function add_media_column( $posts_columns, $detached = true ) {
		// Delete transient for displaying activation notice.
		delete_transient( 'w3tc_activation_imageservice' );

		$posts_columns['imageservice'] = '<span class="w3tc-convert"></span> ' . esc_html__( 'Image Service', 'w3-total-cache' );

		return $posts_columns;
	}

	/**
	 * Fires for each custom column in the Media list table.
	 *
	 * Custom columns are registered using the {@see 'manage_media_columns'} filter.
	 * Runs on the "manage_media_custom_column" action.
	 *
	 * @since 2.5.0
	 *
	 * @see self::remove_optimizations()
	 *
	 * @link https://developer.wordpress.org/reference/functions/size_format/
	 *
	 * @param string $column_name Name of the custom column.
	 * @param int    $post_id     Attachment ID.
	 */
	public function media_column_row( $column_name, $post_id ) {
		static $settings;

		if ( 'imageservice' === $column_name ) {
			$post              = get_post( $post_id );
			$imageservice_data = get_post_meta( $post_id, 'w3tc_imageservice', true );

			$settings = isset( $settings ) ? $settings : $this->config->get_array( 'imageservice' );

			// Display controls and info for eligible images.
			if ( in_array( $post->post_mime_type, self::$mime_types, true ) ) {
				$filepath = get_attached_file( $post_id );
				$status   = isset( $imageservice_data['status'] ) ? $imageservice_data['status'] : null;

				// Check if image still has the converted file.  It could have been deleted.
				if ( 'converted' === $status && isset( $imageservice_data['post_child'] ) ) {
					$child_data = get_post_meta( $imageservice_data['post_child'], 'w3tc_imageservice', true );

					if ( empty( $child_data['is_converted_file'] ) ) {
						$status = null;
						$this->remove_optimizations( $post_id );
					}
				}

				// If processed, then show information.
				if ( 'converted' === $status ) {
					$converted_percent = isset( $imageservice_data['download']["\0*\0data"]['x-filesize-out-percent'] ) ?
						$imageservice_data['download']["\0*\0data"]['x-filesize-out-percent'] : null;
					$reduced_percent   = isset( $imageservice_data['download']["\0*\0data"]['x-filesize-reduced'] ) ?
						$imageservice_data['download']["\0*\0data"]['x-filesize-reduced'] : null;
					$filesize_in       = isset( $imageservice_data['download']["\0*\0data"]['x-filesize-in'] ) ?
						$imageservice_data['download']["\0*\0data"]['x-filesize-in'] : null;
					$filesize_out      = isset( $imageservice_data['download']["\0*\0data"]['x-filesize-out'] ) ?
						$imageservice_data['download']["\0*\0data"]['x-filesize-out'] : null;

					if ( $converted_percent ) {
						$converted_class = rtrim( $converted_percent, '%' ) > 100 ? 'w3tc-converted-increased' : 'w3tc-converted-reduced';
						?>
						<div class="<?php echo esc_attr( $converted_class ); ?>">
						<?php
						printf(
							'%1$s &#8594; %2$s (%3$s)',
							esc_html( size_format( $filesize_in ) ),
							esc_html( size_format( $filesize_out ) ),
							esc_html( $reduced_percent )
						);
						?>
						</div>
						<?php
					}
				} elseif ( 'notconverted' === $status ) {
					?>
					<div class="w3tc-notconverted">
					<?php
					printf(
						// translators: 1: HTML anchor open tag, 2: HTML anchor close tag.
						esc_html__( 'The converted image would be larger than the original; conversion canceled.  %1$sLearn more%2$s.', 'w3-total-cache' ),
						'<a target="_blank" href="' . esc_url(
							'https://www.boldgrid.com/support/w3-total-cache/image-service#conversion-canceled/?utm_source=w3tc&utm_medium=conversion_canceled&utm_campaign=imageservice'
						) . '">',
						'</a>'
					);
					?>
					</div>
					<?php
				}

				// Determine classes.
				$link_classes = 'w3tc-convert';

				switch ( $status ) {
					case 'processing':
						$link_classes  .= ' w3tc-convert-processing';
						$disabled_class = 'w3tc-disabled';
						$aria_attr      = 'true';
						break;
					case 'converted':
						$disabled_class = 'w3tc-disabled';
						$aria_attr      = 'true';
						break;
					default:
						$disabled_class = '';
						$aria_attr      = 'false';
						break;
				}

				// Print action links.
				?>
				<span class="<?php echo esc_attr( $disabled_class ); ?>">
					<a class="<?php echo esc_attr( $link_classes ); ?>" data-post-id="<?php echo esc_attr( $post_id ); ?>"
						data-status="<?php echo esc_attr( $status ); ?>" aria-disabled="<?php echo esc_attr( $aria_attr ); ?>">
				<?php
				// phpcs:disable Generic.WhiteSpace.ScopeIndent.IncorrectExact
				switch ( $status ) {
					case 'sending':
						esc_html_e( 'Sending...', 'w3-total-cache' );
						break;
					case 'processing':
						esc_html_e( 'Processing...', 'w3-total-cache' );
						break;
					case 'converted':
						esc_html_e( 'Converted', 'w3-total-cache' );
						break;
					case 'notconverted':
						if ( isset( $settings['compression'] ) && 'lossless' === $settings['compression'] ) {
							esc_html_e( 'Settings', 'w3-total-cache' );
						} else {
							esc_html_e( 'Convert', 'w3-total-cache' );
						}
						break;
					default:
						esc_html_e( 'Convert', 'w3-total-cache' );
						break;
				}
				// phpcs:enable Generic.WhiteSpace.ScopeIndent.IncorrectExact
				?>
					</a>
				</span>
				<?php

				// If converted, then show revert link.
				if ( 'converted' === $status ) {
					?>
					<span class="w3tc-revert"> | <a><?php esc_attr_e( 'Revert', 'w3-total-cache' ); ?></a></span>
					<?php
				}
			} elseif ( isset( $imageservice_data['is_converted_file'] ) && $imageservice_data['is_converted_file'] ) {
				// W3TC converted image.
				echo esc_html__( 'Attachment id: ', 'w3-total-cache' ) . esc_html( $post->post_parent );
			}
		}
	}

	/**
	 * Add bulk actions.
	 *
	 * @since 2.2.0
	 *
	 * @param array $actions Bulk actions.
	 * @return array
	 */
	public function add_bulk_actions( array $actions ) {
		$actions['w3tc_imageservice_convert'] = 'W3 Total Convert';
		$actions['w3tc_imageservice_revert']  = 'W3 Total Convert Revert';

		return $actions;
	}

	/**
	 * Handle bulk actions.
	 *
	 * @since 2.2.0
	 *
	 * @see self::submit_images()
	 * @see self::revert_optimizations()
	 *
	 * @link https://developer.wordpress.org/reference/hooks/handle_bulk_actions-screen/
	 * @link https://make.wordpress.org/core/2016/10/04/custom-bulk-actions/
	 * @link https://core.trac.wordpress.org/browser/tags/5.8/src/wp-admin/upload.php#L206
	 *
	 * @since WordPress 4.7.0
	 *
	 * @param string $location The redirect URL.
	 * @param string $doaction The action being taken.
	 * @param array  $post_ids The items to take the action on. Accepts an array of IDs of attachments.
	 * @return string
	 */
	public function handle_bulk_actions( $location, $doaction, array $post_ids ) {
		// Remove custom query args.
		$location = remove_query_arg( array( 'w3tc_imageservice_submitted', 'w3tc_imageservice_reverted' ), $location );

		switch ( $doaction ) {
			case 'w3tc_imageservice_convert':
				$stats = $this->submit_images( $post_ids );

				$location = add_query_arg(
					array(
						'w3tc_imageservice_submitted'  => $stats['submitted'],
						'w3tc_imageservice_successful' => $stats['successful'],
						'w3tc_imageservice_skipped'    => $stats['skipped'],
						'w3tc_imageservice_errored'    => $stats['errored'],
						'w3tc_imageservice_invalid'    => $stats['invalid'],
					),
					$location
				);

				break;
			case 'w3tc_imageservice_revert':
				$this->revert_optimizations( $post_ids );

				$location = add_query_arg( 'w3tc_imageservice_reverted', 1, $location );

				break;
			default:
				break;
		}

		return $location;
	}

	/**
	 * Display bulk action results admin notice.
	 *
	 * @since 2.2.0
	 *
	 * @uses $_GET['w3tc_imageservice_submitted']  Number of submittions.
	 * @uses $_GET['w3tc_imageservice_successful'] Number of successful submissions.
	 * @uses $_GET['w3tc_imageservice_skipped']    Number of skipped submissions.
	 * @uses $_GET['w3tc_imageservice_errored']    Number of errored submissions.
	 * @uses $_GET['w3tc_imageservice_invalid']    Number of invalid submissions.
	 */
	public function display_notices() {
		$submitted = Util_Request::get_integer( 'w3tc_imageservice_submitted' );
		if ( ! empty( $submitted ) ) {
			$successful_val = Util_Request::get_integer( 'w3tc_imageservice_successful' );
			$successful     = ! empty( $successful_val ) ? $successful_val : 0;

			$skipped_val = Util_Request::get_integer( 'w3tc_imageservice_skipped' );
			$skipped     = ! empty( $skipped_val ) ? $skipped_val : 0;

			$errored_val = Util_Request::get_integer( 'w3tc_imageservice_errored' );
			$errored     = ! empty( $errored_val ) ? $errored_val : 0;

			$invalid_val = Util_Request::get_integer( 'w3tc_imageservice_invalid' );
			$invalid     = ! empty( $invalid_val ) ? $invalid_val : 0;

			?>
			<script>history.pushState( null, '', location.href.split( '?' )[0] );</script>

			<div class="updated notice notice-success is-dismissible">
				<p>Total Cache Image Service</p>
				<p>
			<?php

			printf(
				esc_html(
					// translators: 1: Submissions.
					_n(
						'Submitted %1$u image for processing.',
						'Submitted %1$u images for processing.',
						$submitted,
						'w3-total-cache'
					)
				) . '</p>',
				esc_attr( $submitted )
			);

			// Print extra stats if debug is on.
			if ( defined( 'W3TC_DEBUG' ) && W3TC_DEBUG ) {
				?>
				<p>
				<?php

				printf(
					// translators: 1: Successes, 2: Skipped, 3: Errored, 4: Invalid.
					esc_html__(
						'Successful: %1$u | Skipped: %2$u | Errored: %3$u | Invalid: %4$u',
						'w3-total-cache'
					),
					esc_attr( $successful ),
					esc_attr( $skipped ),
					esc_attr( $errored ),
					esc_attr( $invalid )
				);
			}

			?>
				</p>
			</div>
			<?php

		} elseif ( ! empty( Util_Request::get_string( 'w3tc_imageservice_reverted' ) ) ) {
			?>
			<script>history.pushState( null, '', location.href.split( '?' )[0] );</script>

			<div class="updated notice notice-success is-dismissible"><p>Total Cache Image Service</p>
				<p><?php esc_html_e( 'All selected optimizations have been reverted.', 'w3-total-cache' ); ?></p>
			</div>
			<?php
		} elseif ( 'upload' === get_current_screen()->id ) {
			// Media Library: Get the display mode.
			$mode = get_user_option( 'media_library_mode', get_current_user_id() ) ?
				get_user_option( 'media_library_mode', get_current_user_id() ) : 'grid';

			// If not in list mode, then print a notice to switch to it.
			if ( 'list' !== $mode ) {
				?>
				<div class="notice notice-warning is-dismissible"><p>Total Cache Image Service -
				<?php
						printf(
							// translators: 1: HTML anchor open tag, 2: HTML anchor close tag.
							esc_html__( 'Switch to %1$slist mode%2$s for WebP conversions.', 'w3-total-cache' ),
							'<a href="' . esc_attr( Util_Ui::admin_url( 'upload.php?mode=list' ) ) . '">',
							'</a>'
						);
				?>
					</p>
				</div>
				<?php
			}
		}
	}

	/**
	 * Submit images to the API for processing.
	 *
	 * @since 2.2.0
	 *
	 * @global $wp_filesystem
	 *
	 * @see Extension_ImageService_Plugin::get_api()
	 *
	 * @param array $post_ids Post ids.
	 * @return array
	 */
	public function submit_images( array $post_ids ) {
		// Check WP_Filesystem credentials.
		Util_WpFile::ajax_check_credentials(
			sprintf(
				// translators: 1: HTML achor open tag, 2: HTML anchor close tag.
				__( '%1$sLearn more%2$s.', 'w3-total-cache' ),
				'<a target="_blank" href="' . esc_url(
					'https://www.boldgrid.com/support/w3-total-cache/image-service/?utm_source=w3tc&utm_medium=conversion_error&utm_campaign=imageservice#unable-to-connect-to-the-filesystem-error'
				) . '">',
				'</a>'
			)
		);

		global $wp_filesystem;

		$stats = array(
			'skipped'    => 0,
			'submitted'  => 0,
			'successful' => 0,
			'errored'    => 0,
			'invalid'    => 0,
		);

		foreach ( $post_ids as $post_id ) {
			// Skip silently (do not count) if not an allowed MIME type.
			if ( ! in_array( get_post_mime_type( $post_id ), self::$mime_types, true ) ) {
				continue;
			}

			$filepath = get_attached_file( $post_id );

			// Skip if attachment file does not exist.
			if ( ! $wp_filesystem->exists( $filepath ) ) {
				$stats['skipped']++;
				continue;
			}

			// Submit current image.
			$response = Extension_ImageService_Plugin::get_api()->convert( $filepath );
			$stats['submitted']++;

			if ( isset( $response['error'] ) ) {
				$stats['errored']++;
				continue;
			}

			if ( empty( $response['job_id'] ) || empty( $response['signature'] ) ) {
				$stats['invalid']++;
				continue;
			}

			// Remove old optimizations.
			$this->remove_optimizations( $post_id );

			// Save the job info.
			self::update_postmeta(
				$post_id,
				array(
					'status'     => 'processing',
					'processing' => $response,
				)
			);

			$stats['successful']++;
		}

		return $stats;
	}

	/**
	 * Revert optimizations of images.
	 *
	 * @since 2.2.0
	 *
	 * @param array $post_ids Attachment post ids.
	 */
	public function revert_optimizations( array $post_ids ) {
		foreach ( $post_ids as $post_id ) {
			// Skip if not an allowed MIME type.
			if ( ! in_array( get_post_mime_type( $post_id ), self::$mime_types, true ) ) {
				continue;
			}

			$this->remove_optimizations( $post_id );
		}
	}

	/**
	 * Update postmeta.
	 *
	 * @since 2.2.0
	 * @static
	 *
	 * @link https://developer.wordpress.org/reference/functions/update_post_meta/
	 *
	 * @param int   $post_id  Post id.
	 * @param array $data Postmeta data.
	 * @return int|bool Meta ID if the key didn't exist, true on successful update, false on failure or if the value
	 *                  passed to the function is the same as the one that is already in the database.
	 */
	public static function update_postmeta( $post_id, array $data ) {
		$postmeta = (array) get_post_meta( $post_id, 'w3tc_imageservice', true );
		$postmeta = array_merge( $postmeta, $data );

		return update_post_meta( $post_id, 'w3tc_imageservice', $postmeta );
	}

	/**
	 * Copy postmeta from one post to another.
	 *
	 * @since 2.2.0
	 * @static
	 *
	 * @link https://developer.wordpress.org/reference/functions/update_post_meta/
	 *
	 * @param int $post_id_1 Post id 1.
	 * @param int $post_id_2 Post id 2.
	 * @return int|bool Meta ID if the key didn't exist, true on successful update, false on failure or if the value
	 *                  passed to the function is the same as the one that is already in the database.
	 */
	public static function copy_postmeta( $post_id_1, $post_id_2 ) {
		$postmeta = (array) get_post_meta( $post_id_1, 'w3tc_imageservice', true );

		// Do not copy "post_child".
		unset( $postmeta['post_child'] );

		return update_post_meta( $post_id_2, 'w3tc_imageservice', $postmeta );
	}

	/**
	 * Remove optimizations.
	 *
	 * @since 2.2.0
	 *
	 * @link https://developer.wordpress.org/reference/functions/wp_delete_attachment/
	 *
	 * @param int $post_id Parent post id.
	 * @return WP_Post|false|null Post data on success, false or null on failure.
	 */
	public function remove_optimizations( $post_id ) {
		$result = null;

		// Get child post id.
		$postmeta = (array) get_post_meta( $post_id, 'w3tc_imageservice', true );
		$child_id = isset( $postmeta['post_child'] ) ? $postmeta['post_child'] : null;

		if ( $child_id ) {
			// Delete optimization.
			$result = wp_delete_attachment( $child_id, true );
		}

		// Delete postmeta.
		delete_post_meta( $post_id, 'w3tc_imageservice' );

		return $result;
	}

	/**
	 * Handle auto-optimization on image upload.
	 *
	 * @since 2.2.0
	 *
	 * @param int $post_id Post id.
	 */
	public function auto_convert( $post_id ) {
		$settings = $this->config->get_array( 'imageservice' );
		$enabled  = isset( $settings['auto'] ) && 'enabled' === $settings['auto'];

		if ( $enabled && in_array( get_post_mime_type( $post_id ), self::$mime_types, true ) ) {
			$this->submit_images( array( $post_id ) );
		}
	}

	/**
	 * Delete optimizations on parent image delation.
	 *
	 * Does not filter the WordPress operation.  We use this as an action trigger.
	 *
	 * @since 2.2.0
	 *
	 * @param bool|null $delete       Whether to go forward with deletion.
	 * @param WP_Post   $post         Post object.
	 * @param bool      $force_delete Whether to bypass the Trash.
	 * @return null
	 */
	public function cleanup_optimizations( $delete, $post, $force_delete ) {
		if ( $force_delete ) {
			$this->remove_optimizations( $post->ID );
		}

		return null;
	}

	/**
	 * AJAX: Submit an image for processing.
	 *
	 * @since 2.2.0
	 *
	 * @global $wp_filesystem
	 *
	 * @see Extension_ImageService_Plugin::get_api()
	 *
	 * @uses $_POST['post_id'] Post id.
	 */
	public function ajax_submit() {
		check_ajax_referer( 'w3tc_imageservice_submit' );

		// Check WP_Filesystem credentials.
		Util_WpFile::ajax_check_credentials(
			sprintf(
				// translators: 1: HTML achor open tag, 2: HTML anchor close tag.
				__( '%1$sLearn more%2$s.', 'w3-total-cache' ),
				'<a target="_blank" href="' . esc_url(
					'https://www.boldgrid.com/support/w3-total-cache/image-service/?utm_source=w3tc&utm_medium=conversion_error&utm_campaign=imageservice#unable-to-connect-to-the-filesystem-error'
				) . '">',
				'</a>'
			)
		);

		// Check for post id.
		$post_id_val = Util_Request::get_integer( 'post_id' );
		$post_id     = ! empty( $post_id_val ) ? $post_id_val : null;

		if ( ! $post_id ) {
			wp_send_json_error(
				array(
					'error' => __( 'Missing input post id.', 'w3-total-cache' ),
				),
				400
			);
		}

		global $wp_filesystem;

		// Verify the image file exists.
		$filepath = get_attached_file( $post_id );

		if ( ! $wp_filesystem->exists( $filepath ) ) {
			wp_send_json_error(
				array(
					'error' => sprintf(
						// translators: 1: Image filepath.
						__( 'File "%1$s" does not exist.', 'w3-total-cache' ),
						$filepath
					),
				),
				412
			);
		}

		// Submit the job request.
		$response = Extension_ImageService_Plugin::get_api()->convert( $filepath );

		// Check for non-200 status code.
		if ( isset( $response['code'] ) && 200 !== $response['code'] ) {
			wp_send_json_error(
				$response,
				$response['code']
			);
		}

		// Check for error.
		if ( isset( $response['error'] ) ) {
			wp_send_json_error(
				$response,
				417
			);
		}

		// Check for valid response data.
		if ( empty( $response['job_id'] ) || empty( $response['signature'] ) ) {
			wp_send_json_error(
				array(
					'error' => __( 'Invalid API response.', 'w3-total-cache' ),
				),
				417
			);
		}

		// Remove old optimizations.
		$this->remove_optimizations( $post_id );

		// Save the job info.
		self::update_postmeta(
			$post_id,
			array(
				'status'     => 'processing',
				'processing' => $response,
			)
		);

		wp_send_json_success( $response );
	}

	/**
	 * AJAX: Get the status of an image, from postmeta.
	 *
	 * @since 2.2.0
	 *
	 * @uses $_POST['post_id'] Post id.
	 */
	public function ajax_get_postmeta() {
		check_ajax_referer( 'w3tc_imageservice_postmeta' );

		$post_id_val = Util_Request::get_integer( 'post_id' );
		$post_id     = ! empty( $post_id_val ) ? $post_id_val : null;

		if ( $post_id ) {
			wp_send_json_success( (array) get_post_meta( $post_id, 'w3tc_imageservice', true ) );
		} else {
			wp_send_json_error(
				array(
					'error' => __( 'Missing input post id.', 'w3-total-cache' ),
				),
				400
			);
		}
	}

	/**
	 * AJAX: Revert an optimization.
	 *
	 * @since 2.2.0
	 *
	 * @uses $_POST['post_id'] Parent post id.
	 */
	public function ajax_revert() {
		check_ajax_referer( 'w3tc_imageservice_revert' );

		$post_id_val = Util_Request::get_integer( 'post_id' );
		$post_id     = ! empty( $post_id_val ) ? $post_id_val : null;

		if ( $post_id ) {
			$result = $this->remove_optimizations( $post_id );

			if ( $result ) {
				wp_send_json_success( $result );
			} else {
				wp_send_json_error(
					array(
						'error' => __( 'Missing converted attachment id.', 'w3-total-cache' ),
					),
					410
				);
			}
		} else {
			wp_send_json_error(
				array(
					'error' => __( 'Missing input post id.', 'w3-total-cache' ),
				),
				400
			);
		}
	}

	/**
	 * AJAX: Convert all images.
	 *
	 * @since 2.2.0
	 *
	 * @see self::get_eligible_attachments()
	 * @see self::submit_images()
	 */
	public function ajax_convert_all() {
		check_ajax_referer( 'w3tc_imageservice_submit' );

		$results = $this->get_eligible_attachments();

		$post_ids = array();

		// Allow plenty of time to complete.
		ignore_user_abort( true );
		set_time_limit( 0 );

		foreach ( $results->posts as $post ) {
			$post_ids[] = $post->ID;
		}

		$stats = $this->submit_images( $post_ids );

		wp_send_json_success( $stats );
	}

	/**
	 * AJAX: Revert all converted images.
	 *
	 * @since 2.2.0
	 *
	 * @see self::get_imageservice_attachments()
	 * @see self::remove_optimizations()
	 */
	public function ajax_revert_all() {
		check_ajax_referer( 'w3tc_imageservice_submit' );

		$results = $this->get_imageservice_attachments();

		$revert_count = 0;

		// Allow plenty of time to complete.
		ignore_user_abort( true );
		set_time_limit( 0 );

		foreach ( $results->posts as $post ) {
			if ( $this->remove_optimizations( $post->ID ) ) {
				$revert_count++;
			}
		}

		wp_send_json_success( array( 'revert_count' => $revert_count ) );
	}

	/**
	 * AJAX: Get image counts by status.
	 *
	 * @since 2.2.0
	 *
	 * @see get_counts()
	 */
	public function ajax_get_counts() {
		check_ajax_referer( 'w3tc_imageservice_submit' );

		wp_send_json_success( $this->get_counts() );
	}

	/**
	 * AJAX: Get image API usage.
	 *
	 * @since 2.2.0
	 *
	 * @see Extension_ImageService_Plugin::get_api()
	 * @see Extension_ImageService_Api::get_usage()
	 */
	public function ajax_get_usage() {
		check_ajax_referer( 'w3tc_imageservice_submit' );

		wp_send_json_success( Extension_ImageService_Plugin::get_api()->get_usage() );
	}
}
