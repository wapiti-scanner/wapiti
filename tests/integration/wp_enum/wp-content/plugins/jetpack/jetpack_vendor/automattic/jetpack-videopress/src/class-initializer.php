<?php
/**
 * The initializer class for the videopress package
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Assets;

/**
 * Initialized the VideoPress package
 */
class Initializer {

	const JETPACK_VIDEOPRESS_VIDEO_HANDLER      = 'jetpack-videopress-video-block';
	const JETPACK_VIDEOPRESS_VIDEO_VIEW_HANDLER = 'jetpack-videopress-video-block-view';
	const JETPACK_VIDEOPRESS_IFRAME_API_HANDLER = 'jetpack-videopress-iframe-api';

	/**
	 * Initialization optinos
	 *
	 * @var array
	 */
	protected static $init_options = array();

	/**
	 * Initializes the VideoPress package
	 *
	 * This method is called by Config::ensure.
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! did_action( 'videopress_init' ) ) {

			self::unconditional_initialization();

			if ( Status::is_active() ) {
				self::active_initialization();
			}
		}

		/**
		 * Fires after the VideoPress package is initialized
		 *
		 * @since 0.1.1
		 */
		do_action( 'videopress_init' );
	}

	/**
	 * Update the initialization options
	 *
	 * This method is called by the Config class
	 *
	 * @param array $options The initialization options.
	 * @return void
	 */
	public static function update_init_options( array $options ) {
		if ( empty( $options['admin_ui'] ) || self::should_initialize_admin_ui() ) { // do not overwrite if already set to true.
			return;
		}

		self::$init_options['admin_ui'] = $options['admin_ui'];
	}

	/**
	 * Checks the initialization options and returns whether the admin_ui should be initialized or not
	 *
	 * @return boolean
	 */
	public static function should_initialize_admin_ui() {
		return isset( self::$init_options['admin_ui'] ) && true === self::$init_options['admin_ui'];
	}

	/**
	 * Initialize VideoPress features that should be initialized whenever VideoPress is present, even if the module is not active
	 *
	 * @return void
	 */
	private static function unconditional_initialization() {
		if ( self::should_include_utilities() ) {
			require_once __DIR__ . '/utility-functions.php';
		}

		// Set up package version hook.
		add_filter( 'jetpack_package_versions', __NAMESPACE__ . '\Package_Version::send_package_version_to_tracker' );

		Module_Control::init();

		new WPCOM_REST_API_V2_Endpoint_VideoPress();
		new WPCOM_REST_API_V2_Attachment_VideoPress_Field();
		new WPCOM_REST_API_V2_Attachment_VideoPress_Data();

		if ( is_admin() ) {
			AJAX::init();
		}
	}

	/**
	 * This avoids conflicts when running VideoPress plugin with older versions of the Jetpack plugin
	 *
	 * On version 11.3-a.7 utility functions include were removed from the plugin and it is safe to include it from the package
	 *
	 * @return boolean
	 */
	private static function should_include_utilities() {
		if ( ! class_exists( 'Jetpack' ) || ! defined( 'JETPACK__VERSION' ) ) {
			return true;
		}

		return version_compare( JETPACK__VERSION, '11.3-a.7', '>=' );
	}

	/**
	 * Initialize VideoPress features that should be initialized only when the module is active
	 *
	 * @return void
	 */
	private static function active_initialization() {
		Attachment_Handler::init();
		Jwt_Token_Bridge::init();
		Uploader_Rest_Endpoints::init();
		VideoPress_Rest_Api_V1_Stats::init();
		VideoPress_Rest_Api_V1_Site::init();
		VideoPress_Rest_Api_V1_Settings::init();
		XMLRPC::init();
		Block_Editor_Content::init();
		self::register_oembed_providers();

		// Enqueuethe VideoPress Iframe API script in the front-end.
		add_filter( 'embed_oembed_html', array( __CLASS__, 'enqueue_videopress_iframe_api_script' ), 10, 4 );

		if ( self::should_initialize_admin_ui() ) {
			Admin_UI::init();
		}
	}

	/**
	 * Explicitly register VideoPress oembed provider for patterns not supported by core
	 *
	 * @return void
	 */
	public static function register_oembed_providers() {
		$host = rawurlencode( home_url() );
		// videopress.com/v is already registered in core.
		// By explicitly declaring the provider here, we can speed things up by not relying on oEmbed discovery.
		wp_oembed_add_provider( '#^https?://video.wordpress.com/v/.*#', 'https://public-api.wordpress.com/oembed/?for=' . $host, true );
		// This is needed as it's not supported in oEmbed discovery
		wp_oembed_add_provider( '|^https?://v\.wordpress\.com/([a-zA-Z\d]{8})(.+)?$|i', 'https://public-api.wordpress.com/oembed/?for=' . $host, true ); // phpcs:ignore WordPress.WP.CapitalPDangit.Misspelled

		add_filter( 'embed_oembed_html', array( __CLASS__, 'video_enqueue_bridge_when_oembed_present' ), 10, 4 );
	}

	/**
	 * Enqueues VideoPress token bridge when a VideoPress oembed is present on the current page.
	 *
	 * @param string|false $cache   The cached HTML result, stored in post meta.
	 * @param string       $url     The attempted embed URL.
	 * @param array        $attr    An array of shortcode attributes.
	 * @param int          $post_ID Post ID.
	 *
	 * @return string|false
	 */
	public static function video_enqueue_bridge_when_oembed_present( $cache, $url, $attr, $post_ID ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( preg_match( '/^https?:\/\/(video\.wordpress\.com|videopress\.com)\/(v|embed)\//', $url ) // phpcs:ignore WordPress.WP.CapitalPDangit.Misspelled
			|| preg_match( '|^https?://v\.wordpress\.com/([a-zA-Z\d]{8})(.+)?$|i', $url ) ) { // phpcs:ignore WordPress.WP.CapitalPDangit.Misspelled
			Jwt_Token_Bridge::enqueue_jwt_token_bridge();
		}
		return $cache;
	}

	/**
	 * Register all VideoPress blocks
	 *
	 * @return void
	 */
	public static function register_videopress_blocks() {
		// Register VideoPress Video block.
		self::register_videopress_video_block();
	}

	/**
	 * VideoPress video block render method
	 *
	 * @param array  $block_attributes - Block attributes.
	 * @param string $content          - Current block markup.
	 * @return string                    Block markup.
	 */
	public static function render_videopress_video_block( $block_attributes, $content ) {
		global $wp_embed;

		// CSS classes
		$align        = isset( $block_attributes['align'] ) ? $block_attributes['align'] : null;
		$align_class  = $align ? ' align' . $align : '';
		$custom_class = isset( $block_attributes['className'] ) ? ' ' . $block_attributes['className'] : '';
		$classes      = 'wp-block-jetpack-videopress jetpack-videopress-player' . $custom_class . $align_class;

		// Inline style
		$style     = '';
		$max_width = isset( $block_attributes['maxWidth'] ) ? $block_attributes['maxWidth'] : null;
		if ( $max_width && $max_width !== '100%' ) {
			$style = sprintf( 'max-width: %s; margin: auto;', $max_width );
		}

		/*
		 * <figcaption /> element
		 * Caption is stored into the block attributes,
		 * but also it was stored into the <figcaption /> element,
		 * meaning that it could be stored in two different places.
		 */
		$figcaption = '';

		// Caption from block attributes
		$caption = isset( $block_attributes['caption'] ) ? $block_attributes['caption'] : null;

		/*
		 * If the caption is not stored into the block attributes,
		 * try to get it from the <figcaption /> element.
		 */
		if ( $caption === null ) {
			preg_match( '/<figcaption>(.*?)<\/figcaption>/', $content, $matches );
			$caption = isset( $matches[1] ) ? $matches[1] : null;
		}

		// If we have a caption, create the <figcaption /> element.
		if ( $caption !== null ) {
			$figcaption = sprintf( '<figcaption>%s</figcaption>', wp_kses_post( $caption ) );
		}

		// Custom anchor from block content
		$id_attribute = '';

		// Try to get the custom anchor from the block attributes.
		if ( isset( $block_attributes['anchor'] ) && $block_attributes['anchor'] ) {
			$id_attribute = sprintf( 'id="%s"', $block_attributes['anchor'] );
		} elseif ( preg_match( '/<figure[^>]*id="([^"]+)"/', $content, $matches ) ) {
			// Othwerwise, try to get the custom anchor from the <figure /> element.
			$id_attribute = sprintf( 'id="%s"', $matches[1] );
		}

		// Preview On Hover data
		$is_poh_enabled =
			isset( $block_attributes['posterData']['previewOnHover'] ) &&
			$block_attributes['posterData']['previewOnHover'];

		$autoplay = isset( $block_attributes['autoplay'] ) ? $block_attributes['autoplay'] : false;
		$controls = isset( $block_attributes['controls'] ) ? $block_attributes['controls'] : false;
		$poster   = isset( $block_attributes['posterData']['url'] ) ? $block_attributes['posterData']['url'] : null;

		$preview_on_hover = '';
		$play_button      = '';

		if ( $is_poh_enabled ) {
			$preview_on_hover = array(
				'previewAtTime'       => $block_attributes['posterData']['previewAtTime'],
				'previewLoopDuration' => $block_attributes['posterData']['previewLoopDuration'],
				'autoplay'            => $autoplay,
				'showControls'        => $controls,
			);

			// Create inlione style in case video has a custom poster.
			$inline_style = '';
			if ( $poster ) {
				$inline_style = sprintf(
					'style="background-image: url(%s); background-size: cover;
				background-position: center center;"',
					$poster
				);
			}

			/*
			 * Add a child element to show the play button
			 * when the controls is enabled
			 */
			if ( $controls ) {
				$play_button = '<div class="jetpack-videopress-player__play-button"></div>';
			}

			// Expose the preview on hover data to the client.
			$preview_on_hover = sprintf(
				'<div class="jetpack-videopress-player__overlay" %s></div><script type="application/json">%s</script>',
				$inline_style,
				wp_json_encode( $preview_on_hover )
			);

			// Set `autoplay` and `muted` attributes to the video element.
			$block_attributes['autoplay'] = true;
			$block_attributes['muted']    = true;
		}

		$figure_template = '
		<figure class="%1$s" style="%2$s" %3$s>
			%4$s
			%5$s
		</figure>
		';

		// VideoPress URL
		$guid           = isset( $block_attributes['guid'] ) ? $block_attributes['guid'] : null;
		$videopress_url = Utils::get_video_press_url( $guid, $block_attributes );

		$video_wrapper         = '';
		$video_wrapper_classes = 'jetpack-videopress-player__wrapper';
		if ( $controls ) {
			$video_wrapper_classes .= ' has-controls';
		}

		if ( $videopress_url ) {
			$videopress_url = wp_kses_post( $videopress_url );
			$oembed_html    = apply_filters( 'video_embed_html', $wp_embed->shortcode( array(), $videopress_url ) );
			$video_wrapper  = sprintf(
				'<div class="%s">%s %s %s</div>',
				$video_wrapper_classes,
				$play_button,
				$preview_on_hover,
				$oembed_html
			);
		}

		return sprintf(
			$figure_template,
			esc_attr( $classes ),
			esc_attr( $style ),
			$id_attribute,
			$video_wrapper,
			$figcaption
		);
	}

	/**
	 * Register the VideoPress block editor block,
	 * AKA "VideoPress Block v6".
	 *
	 * @return void
	 */
	public static function register_videopress_video_block() {
		$videopress_video_metadata_file        = __DIR__ . '/../build/block-editor/blocks/video/block.json';
		$videopress_video_metadata_file_exists = file_exists( $videopress_video_metadata_file );
		if ( ! $videopress_video_metadata_file_exists ) {
			return;
		}

		$videopress_video_metadata = json_decode(
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			file_get_contents( $videopress_video_metadata_file )
		);

		// Pick the block name straight from the block metadata .json file.
		$videopress_video_block_name = $videopress_video_metadata->name;

		// Register and enqueue scripts used by the VideoPress video block.
		Block_Editor_Extensions::init( self::JETPACK_VIDEOPRESS_VIDEO_HANDLER );

		// Do not register if the block is already registered.
		if ( \WP_Block_Type_Registry::get_instance()->is_registered( $videopress_video_block_name ) ) {
			return;
		}

		// Register script used by the VideoPress video block in the editor.
		Assets::register_script(
			self::JETPACK_VIDEOPRESS_VIDEO_HANDLER,
			'../build/block-editor/blocks/video/index.js',
			__FILE__,
			array(
				'in_footer'  => false,
				'textdomain' => 'jetpack-videopress-pkg',
			)
		);

		// Register script used by the VideoPress video block in the front-end.
		Assets::register_script(
			self::JETPACK_VIDEOPRESS_VIDEO_VIEW_HANDLER,
			'../build/block-editor/blocks/video/view.js',
			__FILE__,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack-videopress-pkg',
			)
		);

		// Register VideoPress video block.
		register_block_type(
			$videopress_video_metadata_file,
			array(
				'render_callback' => array( __CLASS__, 'render_videopress_video_block' ),
			)
		);
	}

	/**
	 * Enqueue the VideoPress Iframe API script
	 * when the URL of oEmbed HTML is a VideoPress URL.
	 *
	 * @param string|false $cache   The cached HTML result, stored in post meta.
	 * @param string       $url     The attempted embed URL.
	 * @param array        $attr    An array of shortcode attributes.
	 * @param int          $post_ID Post ID.
	 *
	 * @return string|false
	 */
	public static function enqueue_videopress_iframe_api_script( $cache, $url, $attr, $post_ID ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( Utils::is_videopress_url( $url ) ) {
			// Enqueue the VideoPress IFrame API in the front-end.
			wp_enqueue_script(
				self::JETPACK_VIDEOPRESS_IFRAME_API_HANDLER,
				'https://s0.wp.com/wp-content/plugins/video/assets/js/videojs/videopress-iframe-api.js',
				array(),
				gmdate( 'YW' ),
				false
			);
		}

		return $cache;
	}
}
