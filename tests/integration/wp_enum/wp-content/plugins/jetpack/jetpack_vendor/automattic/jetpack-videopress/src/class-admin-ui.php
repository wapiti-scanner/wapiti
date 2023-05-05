<?php
/**
 * The initializer class for Admin UI elements
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Admin_UI\Admin_Menu;
use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Connection\Initial_State as Connection_Initial_State;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Current_Plan;
use Automattic\Jetpack\My_Jetpack\Products as My_Jetpack_Products;
use Automattic\Jetpack\Status as Status;
use Automattic\Jetpack\Terms_Of_Service;
use Automattic\Jetpack\Tracking;

/**
 * Initialized the VideoPress package
 */
class Admin_UI {

	const JETPACK_VIDEOPRESS_PKG_NAMESPACE = 'jetpack-videopress-pkg';

	const ADMIN_PAGE_SLUG = 'jetpack-videopress';

	/**
	 * Initializes the Admin UI of VideoPress
	 *
	 * This method is called only once by the Initializer class
	 *
	 * @return void
	 */
	public static function init() {
		$page_suffix = Admin_Menu::add_menu(
			__( 'Jetpack VideoPress', 'jetpack-videopress-pkg' ),
			_x( 'VideoPress', 'The Jetpack VideoPress product name, without the Jetpack prefix', 'jetpack-videopress-pkg' ),
			'manage_options',
			self::ADMIN_PAGE_SLUG,
			array( __CLASS__, 'plugin_settings_page' ),
			99
		);
		add_action( 'load-' . $page_suffix, array( __CLASS__, 'admin_init' ) );

		add_action( 'admin_footer-upload.php', array( __CLASS__, 'attachment_details_two_column_template' ) );
		add_action( 'admin_footer-post.php', array( __CLASS__, 'attachment_details_template' ), 20 );

		add_filter( 'get_edit_post_link', array( __CLASS__, 'edit_video_link' ), 10, 3 );

		add_action( 'admin_init', array( __CLASS__, 'remove_jetpack_hooks' ) );
	}

	/**
	 * Gets the URL for the VideoPress admin page
	 *
	 * @return string
	 */
	public static function get_admin_page_url() {
		return admin_url( 'admin.php?page=' . self::ADMIN_PAGE_SLUG );
	}

	/**
	 * Gets the list of allowed video extensions
	 *
	 * @return array
	 */
	public static function get_allowed_video_extensions() {
		return array(
			'3g2'  => 'video/3gpp2',
			'3gp'  => 'video/3gpp',
			'3gp2' => 'video/3gpp2',
			'3gpp' => 'video/3gpp',
			'avi'  => 'video/avi',
			'm4v'  => 'video/mp4',
			'mov'  => 'video/quicktime',
			'mp4'  => 'video/mp4',
			'mpe'  => 'video/mpeg',
			'mpeg' => 'video/mpeg',
			'mpg'  => 'video/mpeg',
			'ogv'  => 'video/ogg',
			'wmv'  => 'video/x-ms-wmv',
		);
	}

	/**
	 * Initialize the admin resources.
	 */
	public static function admin_init() {
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_admin_scripts' ) );
	}

	/**
	 * Main plugin settings page.
	 */
	public static function plugin_settings_page() {
		?>
			<div id="jetpack-videopress-root"></div>
		<?php
	}

	/**
	 * Remove extra fields from Attachment details modal
	 *
	 * @return void
	 */
	public static function remove_jetpack_hooks() {
		if ( class_exists( '\VideoPress_Edit_Attachment' ) ) {
			$edit_attachment = \VideoPress_Edit_Attachment::init();
			remove_filter( 'attachment_fields_to_edit', array( $edit_attachment, 'fields_to_edit' ) );
			remove_filter( 'attachment_fields_to_save', array( $edit_attachment, 'save_fields' ) );
		}
	}

	/**
	 * Returns whether we are in condition to track to use
	 * Analytics functionality like Tracks, MC, or GA.
	 */
	public static function can_use_analytics() {
		$status     = new Status();
		$connection = new Connection_Manager();
		$tracking   = new Tracking( 'jetpack', $connection );

		return $tracking->should_enable_tracking( new Terms_Of_Service(), $status );
	}

	/**
	 * Enqueue plugin admin scripts and styles.
	 */
	public static function enqueue_admin_scripts() {
		Assets::register_script(
			self::JETPACK_VIDEOPRESS_PKG_NAMESPACE,
			'../build/admin/index.js',
			__FILE__,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack-videopress-pkg',
			)
		);
		Assets::enqueue_script( self::JETPACK_VIDEOPRESS_PKG_NAMESPACE );

		// Required for Media Library access
		wp_enqueue_media();

		// Required for Analytics.
		if ( self::can_use_analytics() ) {
			Tracking::register_tracks_functions_scripts( true );
		}

		// Initial JS state including JP Connection data.
		wp_add_inline_script( self::JETPACK_VIDEOPRESS_PKG_NAMESPACE, Connection_Initial_State::render(), 'before' );
		wp_add_inline_script( self::JETPACK_VIDEOPRESS_PKG_NAMESPACE, self::render_initial_state(), 'before' );
	}

	/**
	 * Render the initial state into a JavaScript variable.
	 *
	 * @return string
	 */
	public static function render_initial_state() {
		return 'var jetpackVideoPressInitialState=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( self::initial_state() ) ) . '"));';
	}

	/**
	 * Get the initial state data for hydrating the React UI.
	 *
	 * @return array
	 */
	public static function initial_state() {
		return array(
			'apiRoot'                => esc_url_raw( rest_url() ),
			'apiNonce'               => wp_create_nonce( 'wp_rest' ),
			'registrationNonce'      => wp_create_nonce( 'jetpack-registration-nonce' ),
			'adminUrl'               => self::get_admin_page_url(),
			'adminUri'               => 'admin.php?page=' . self::ADMIN_PAGE_SLUG,
			'paidFeatures'           => array(
				'isVideoPressSupported'          => Current_Plan::supports( 'videopress' ),
				'isVideoPress1TBSupported'       => Current_Plan::supports( 'videopress-1tb-storage' ),
				'isVideoPressUnlimitedSupported' => Current_Plan::supports( 'videopress-unlimited-storage' ),
			),
			'siteSuffix'             => ( new Status() )->get_site_suffix(),
			'productData'            => Plan::get_product(),
			'productPrice'           => Plan::get_product_price(),
			'siteProductData'        => My_Jetpack_Products::get_product( 'videopress' ),
			'allowedVideoExtensions' => self::get_allowed_video_extensions(),
			'initialState'           => Data::get_initial_state(),
			'contentNonce'           => wp_create_nonce( 'videopress-content-nonce' ),
		);
	}

	/**
	 * Replaces the edit link for videopress videos
	 *
	 * @param string $link - the post link.
	 * @param int    $post_id - the post ID.
	 * @param string $context - the context.
	 *
	 * @return string
	 */
	public static function edit_video_link( $link, $post_id, $context ) {
		$post_id = (int) $post_id;
		if ( ! $post_id ) {
			return $link;
		}

		$post = get_post( $post_id );
		if ( ! $post ) {
			return $link;
		}

		if ( 'attachment' !== $post->post_type || 'video/videopress' !== $post->post_mime_type ) {
			return $link;
		}

		$route = sprintf( '#/video/%d/edit', $post_id );
		$url   = self::get_admin_page_url() . $route;

		if ( 'display' === $context ) {
			return esc_url( $url );
		}

		return esc_url_raw( $url );
	}

	/**
	 * Gets the SVG for the sub brand Jetpack VideoPress logo
	 *
	 * @return string
	 */
	protected static function get_logo_svg() {
		return '<svg width="212" height="27" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M110.441 16.294c.479-1.458.995-2.93 1.547-4.414l2.545-6.87h1.687l-5.09 13.361h-1.427l-5.09-13.361h1.687l2.545 6.87a109.628 109.628 0 0 1 1.556 4.414h.04ZM117.919 18.371V8.884h1.547v9.487h-1.547Zm-.04-11.694V4.95h1.627v1.727h-1.627ZM123.331 13.728c0 .546.06 1.042.179 1.488.127.439.306.815.539 1.128.233.306.519.543.858.71.34.166.729.249 1.168.249.326 0 .622-.044.888-.13.266-.087.503-.196.709-.33a3.045 3.045 0 0 0 .898-.838V11.04a3.706 3.706 0 0 0-1.108-.779c-.419-.2-.871-.3-1.357-.3a2.83 2.83 0 0 0-.928.17 2.26 2.26 0 0 0-.898.59c-.273.286-.499.672-.679 1.158-.179.48-.269 1.095-.269 1.848Zm-1.617.02c0-.66.063-1.242.19-1.748.133-.513.306-.959.519-1.338.212-.38.462-.696.748-.949.286-.26.582-.47.888-.629.306-.16.616-.273.928-.34.32-.073.619-.11.898-.11.579 0 1.082.097 1.507.29.426.193.809.476 1.148.85h.03V3.91h1.547v14.46h-1.168l-.319-1.058h-.04c-.12.153-.26.31-.419.47-.16.152-.349.292-.569.419a2.83 2.83 0 0 1-.749.3 3.57 3.57 0 0 1-.978.119 4.63 4.63 0 0 1-1.526-.26 3.666 3.666 0 0 1-1.338-.849c-.386-.392-.698-.895-.938-1.507-.239-.62-.359-1.372-.359-2.257ZM136.626 9.963c-.352 0-.682.07-.988.21a2.57 2.57 0 0 0-.788.569c-.226.24-.409.522-.549.849-.14.32-.226.662-.259 1.028h4.79c0-.373-.05-.719-.15-1.038a2.474 2.474 0 0 0-.419-.85 1.935 1.935 0 0 0-.689-.559 2.046 2.046 0 0 0-.948-.21Zm.849 7.31c.512 0 .978-.04 1.397-.12a8.775 8.775 0 0 0 1.267-.36v1.289c-.339.166-.758.296-1.257.39-.499.1-1.035.149-1.607.149a6.871 6.871 0 0 1-1.916-.26 4.108 4.108 0 0 1-1.557-.838c-.446-.387-.798-.89-1.058-1.508-.253-.626-.379-1.379-.379-2.257 0-.866.12-1.615.359-2.247.24-.64.559-1.172.958-1.598.4-.426.859-.746 1.378-.959a4.238 4.238 0 0 1 1.626-.32c.532 0 1.028.09 1.487.27.466.173.868.45 1.208.83.339.379.605.868.798 1.467.2.6.299 1.318.299 2.157v.21c0 .053-.003.18-.009.38h-6.507c0 .605.09 1.121.269 1.547.187.42.436.763.749 1.029.319.26.692.45 1.117.57.426.119.885.179 1.378.179ZM149.623 13.638c0-.586-.074-1.105-.22-1.558a3.288 3.288 0 0 0-.599-1.159 2.421 2.421 0 0 0-.908-.718 2.674 2.674 0 0 0-1.157-.25c-.42 0-.806.083-1.158.25a2.5 2.5 0 0 0-.918.719c-.253.312-.453.699-.599 1.158-.14.453-.21.972-.21 1.558 0 .579.07 1.098.21 1.558.146.452.349.835.609 1.148.259.313.565.553.918.72.352.159.738.239 1.157.239.42 0 .802-.08 1.148-.24a2.56 2.56 0 0 0 .908-.719c.26-.313.459-.696.599-1.148.146-.46.22-.979.22-1.558Zm1.616 0a6.17 6.17 0 0 1-.319 2.037 4.617 4.617 0 0 1-.908 1.578 3.987 3.987 0 0 1-1.407 1.009c-.552.24-1.171.359-1.857.359-.705 0-1.337-.12-1.896-.36a4.09 4.09 0 0 1-1.417-1.008 4.562 4.562 0 0 1-.888-1.578 6.361 6.361 0 0 1-.309-2.037c0-.752.106-1.435.319-2.047a4.697 4.697 0 0 1 .898-1.578c.393-.44.865-.78 1.417-1.019a4.69 4.69 0 0 1 1.867-.36c.698 0 1.327.12 1.886.36.559.24 1.031.58 1.417 1.019.386.44.682.965.888 1.578.206.612.309 1.295.309 2.047ZM155.204 18.371h-1.627V5.01h3.703c.552 0 1.061.033 1.527.1.472.066.905.17 1.297.309.798.286 1.404.716 1.816 1.288.413.566.619 1.265.619 2.097 0 .68-.136 1.279-.409 1.798a3.473 3.473 0 0 1-1.168 1.288c-.512.346-1.137.61-1.876.79-.732.172-1.563.259-2.495.259-.446 0-.908-.02-1.387-.06v5.492Zm0-6.98a12.234 12.234 0 0 0 1.367.08c.765 0 1.417-.06 1.956-.18.539-.12.978-.293 1.318-.52.339-.232.585-.512.738-.838.153-.333.23-.71.23-1.129 0-.519-.127-.945-.38-1.278-.246-.333-.598-.586-1.057-.759a4.097 4.097 0 0 0-.988-.22 10.59 10.59 0 0 0-1.298-.07h-1.886v4.914ZM169.62 10.143h-.12c-.365 0-.725.033-1.077.1a4.45 4.45 0 0 0-.998.309c-.306.133-.586.3-.839.5a2.74 2.74 0 0 0-.618.708v6.611h-1.547V8.884h1.197l.3 1.508h.03c.153-.246.339-.476.559-.689.226-.213.479-.4.758-.56a3.72 3.72 0 0 1 .918-.369c.333-.093.682-.14 1.048-.14.067 0 .133.004.2.01.073 0 .136.004.189.01v1.489ZM174.673 9.963c-.353 0-.682.07-.988.21-.3.14-.562.33-.789.569-.226.24-.409.522-.549.849-.139.32-.226.662-.259 1.028h4.79c0-.373-.05-.719-.149-1.038a2.476 2.476 0 0 0-.42-.85 1.931 1.931 0 0 0-.688-.559 2.052 2.052 0 0 0-.948-.21Zm.848 7.31c.512 0 .978-.04 1.397-.12a8.824 8.824 0 0 0 1.268-.36v1.289c-.34.166-.759.296-1.258.39-.499.1-1.034.149-1.607.149a6.876 6.876 0 0 1-1.916-.26 4.108 4.108 0 0 1-1.557-.838c-.445-.387-.798-.89-1.057-1.508-.253-.626-.38-1.379-.38-2.257 0-.866.12-1.615.36-2.247.239-.64.559-1.172.958-1.598a3.9 3.9 0 0 1 1.377-.959 4.243 4.243 0 0 1 1.627-.32c.532 0 1.027.09 1.487.27.465.173.868.45 1.207.83.339.379.606.868.798 1.467.2.6.3 1.318.3 2.157v.21c0 .053-.003.18-.01.38h-6.507c0 .605.09 1.121.27 1.547.186.42.435.763.748 1.029.319.26.692.45 1.118.57.426.119.885.179 1.377.179ZM181.831 11.41c0 .26.056.473.17.64.113.166.262.303.449.41.193.1.412.182.658.25.253.066.513.126.779.179.366.08.712.17 1.038.27.326.093.625.236.898.429.279.193.502.456.668.789.173.326.26.752.26 1.278 0 .48-.093.906-.28 1.278a2.64 2.64 0 0 1-.788.929 3.66 3.66 0 0 1-1.217.56c-.473.132-.992.199-1.557.199-.346 0-.662-.02-.948-.06a5.2 5.2 0 0 1-.749-.14 4.56 4.56 0 0 1-.549-.17 3.646 3.646 0 0 1-.379-.17v-1.297c.399.16.795.286 1.188.379.392.093.825.14 1.297.14.373 0 .709-.034 1.008-.1.299-.067.555-.163.768-.29.22-.133.386-.296.499-.489.12-.2.18-.43.18-.69 0-.265-.053-.485-.16-.658a1.315 1.315 0 0 0-.429-.43 2.582 2.582 0 0 0-.629-.28 9.795 9.795 0 0 0-.738-.199c-.339-.073-.685-.16-1.038-.26-.346-.1-.662-.24-.948-.419a2.102 2.102 0 0 1-.699-.729c-.173-.313-.259-.712-.259-1.198 0-.5.09-.932.269-1.299.18-.366.423-.669.729-.908.306-.24.662-.42 1.068-.54.406-.12.835-.18 1.287-.18.526 0 1.011.05 1.457.15.453.1.862.227 1.228.38v1.318a8.85 8.85 0 0 0-1.218-.37 5.61 5.61 0 0 0-1.257-.16c-.366 0-.679.037-.938.11a1.78 1.78 0 0 0-.639.31c-.166.127-.289.28-.369.46a1.46 1.46 0 0 0-.11.579ZM189.787 11.41c0 .26.057.473.17.64.113.166.263.303.449.41.193.1.413.182.659.25.253.066.512.126.778.179.366.08.712.17 1.038.27.326.093.626.236.898.429.28.193.503.456.669.789.173.326.259.752.259 1.278 0 .48-.093.906-.279 1.278a2.64 2.64 0 0 1-.788.929c-.34.246-.746.433-1.218.56-.472.132-.991.199-1.557.199-.346 0-.662-.02-.948-.06a5.185 5.185 0 0 1-.748-.14 4.56 4.56 0 0 1-.549-.17 3.552 3.552 0 0 1-.379-.17v-1.297c.399.16.795.286 1.187.379.393.093.825.14 1.298.14.372 0 .708-.034 1.007-.1.3-.067.556-.163.769-.29.219-.133.386-.296.499-.489.12-.2.18-.43.18-.69 0-.265-.054-.485-.16-.658a1.334 1.334 0 0 0-.429-.43 2.6 2.6 0 0 0-.629-.28 9.925 9.925 0 0 0-.738-.199c-.34-.073-.686-.16-1.038-.26-.346-.1-.662-.24-.948-.419a2.102 2.102 0 0 1-.699-.729c-.173-.313-.259-.712-.259-1.198 0-.5.089-.932.269-1.299.18-.366.422-.669.729-.908a3.16 3.16 0 0 1 1.067-.54c.406-.12.835-.18 1.288-.18.525 0 1.011.05 1.457.15.452.1.861.227 1.227.38v1.318a8.837 8.837 0 0 0-1.217-.37 5.612 5.612 0 0 0-1.258-.16 3.49 3.49 0 0 0-.938.11 1.797 1.797 0 0 0-.639.31c-.166.127-.289.28-.369.46-.073.173-.11.366-.11.579Z" fill="#000"/><path d="M13.491 27c7.451 0 13.492-6.044 13.492-13.5 0-7.457-6.04-13.5-13.492-13.5C6.041 0 0 6.044 0 13.5 0 20.957 6.04 27 13.491 27Z" fill="#069E08"/><path d="M14.16 11.233v13.088l6.746-13.088H14.16ZM12.798 15.742V2.679l-6.72 13.063h6.72Z" fill="#fff"/><path d="M34.834 22.414c-.387-.593-.747-1.184-1.107-1.751 1.905-1.16 2.548-2.087 2.548-3.84V6.699h-2.24V4.767H38.8v11.542c0 2.937-.85 4.586-3.965 6.105ZM54.787 15.51c0 .979.695 1.082 1.159 1.082.464 0 1.133-.155 1.647-.31v1.804c-.72.232-1.467.412-2.497.412-1.236 0-2.678-.464-2.678-2.628v-5.308h-1.313v-1.83h1.313V6.029h2.369v2.706h2.986v1.83h-2.986v4.946ZM59.73 23.316V8.708h2.266v.876c.901-.696 1.906-1.134 3.141-1.134 2.137 0 3.837 1.494 3.837 4.715 0 3.195-1.853 5.307-4.918 5.307-.746 0-1.338-.103-1.957-.232v5.05h-2.368v.026Zm4.789-12.908c-.695 0-1.57.335-2.395 1.057v4.973a8.59 8.59 0 0 0 1.777.18c1.673 0 2.626-1.057 2.626-3.272 0-2.036-.695-2.938-2.008-2.938ZM78.294 18.266H76.08V17.21h-.052c-.772.592-1.725 1.236-3.14 1.236-1.237 0-2.576-.902-2.576-2.731 0-2.447 2.086-2.911 3.553-3.117l2.085-.283v-.283c0-1.289-.514-1.7-1.725-1.7-.593 0-1.982.18-3.115.643l-.206-1.906a11.91 11.91 0 0 1 3.63-.618c2.317 0 3.811.928 3.811 3.684v6.131h-.05Zm-2.369-4.457-1.957.31c-.592.076-1.21.437-1.21 1.313 0 .773.438 1.21 1.081 1.21.696 0 1.442-.411 2.085-.875v-1.958h.001ZM88.079 17.957c-.978.335-1.853.541-2.961.541-3.553 0-4.97-2.035-4.97-4.998 0-3.117 1.958-5.05 5.124-5.05 1.184 0 1.905.207 2.703.465v2.01c-.695-.259-1.7-.542-2.677-.542-1.442 0-2.678.773-2.678 2.989 0 2.447 1.236 3.195 2.806 3.195.747 0 1.571-.155 2.678-.593v1.983h-.025ZM92.558 12.83c.205-.231.36-.463 3.346-4.096h3.09l-3.863 4.535 4.222 5.023h-3.089l-3.681-4.535v4.535h-2.368V4.767h2.369v8.064h-.026ZM49.328 17.957c-1.236.387-2.292.541-3.528.541-3.038 0-4.917-1.52-4.917-5.076 0-2.602 1.596-4.972 4.66-4.972 3.038 0 4.094 2.112 4.094 4.122 0 .67-.052 1.03-.077 1.416h-6.128c.052 2.087 1.236 2.577 3.013 2.577.978 0 1.853-.232 2.858-.593v1.983h.025v.002Zm-2.162-5.54c0-1.159-.387-2.164-1.647-2.164-1.184 0-1.906.85-2.06 2.165h3.707Z" fill="#000"/></svg>';
	}

	// phpcs:disable WordPress.Security.EscapeOutput.UnsafePrintingFunction
	// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped

	/**
	 * Overwrites the backbone template for the attachment details modal
	 *
	 * This template is originally added in WP core in wp-includes/media-templates.php
	 *
	 * We override the initialize method of the TwoColumn view class (located at core's js/media/view/attachment/detail-two-column.js)
	 * and use the custom template only for VideoPress videos.
	 *
	 * @return void
	 */
	public static function attachment_details_two_column_template() {

		?>
		<script type="text/html" id="tmpl-videopress_iframe_vnext">
			<iframe class="videopress-iframe" style="display: block; max-width: 100%; max-height: 100%;" width="{{ data.width }}" height="{{ data.height }}" src="https://videopress.com/embed/{{ data.guid }}?{{ data.urlargs }}" frameborder='0' allowfullscreen></iframe>
		</script>
		<script type="text/html" id="tmpl-attachment-details-two-column-videopress">
			<div class="attachment-media-view {{ data.orientation }}">
				<h2 class="screen-reader-text"><?php _e( 'Attachment Preview', 'jetpack-videopress-pkg' ); ?></h2>
				<div class="thumbnail thumbnail-{{ data.type }}">
				</div>
			</div>
			<div class="attachment-info">
				<h2>
					<?php echo self::get_logo_svg(); ?>
				</h2>
				<?php self::attachment_info_template_part(); ?>
			</div>
		</script>
		<script>
			jQuery(document).ready( function($) {
				if( typeof wp.media.view.Attachment.Details.TwoColumn != 'undefined' ){
					var TwoColumn   = wp.media.view.Attachment.Details.TwoColumn,
						old_render  = TwoColumn.prototype.render,
						vp_template = wp.template('videopress_iframe_vnext');

					TwoColumn.prototype.initialize = function() {
						if ( 'video' === this.model.attributes.type && 'videopress' === this.model.attributes.subtype ) {
							this.template = wp.template( 'attachment-details-two-column-videopress' );
						} else {
							this.template = wp.template( 'attachment-details-two-column' );
						}
						// From this point on, we are just copying the function from core.
						this.controller.on( 'content:activate:edit-details', _.bind( this.editAttachment, this ) );
						wp.media.view.Attachment.Details.prototype.initialize.apply( this, arguments );
					}

					// Add the VideoPress player
					TwoColumn.prototype.render = function() {
						// Have the original renderer run first.
						old_render.apply( this, arguments );

						// Now our stuff!
						if ( 'video' === this.model.get('type') ) {
							if ( this.model.get('videopress_guid') ) {
								this.$('.attachment-media-view .thumbnail-video').html( vp_template( {
									guid   : this.model.get('videopress_guid'),
									width  : this.model.get('width') > 0 ? this.model.get('width') : '100%',
									height : this.model.get('height') > 0 ? this.model.get('height') : '100%'
								}));
							}
						}
					};
				}
			});
		</script>
		<?php
	}

	/**
	 * Overwrites the backbone template for the attachment details modal
	 *
	 * This template is originally added in WP core in wp-includes/media-templates.php
	 *
	 * We override the initialize method of the TwoColumn view class (located at core's js/media/view/attachment/detail-two-column.js)
	 * and use the custom template only for VideoPress videos.
	 *
	 * @return void
	 */
	public static function attachment_details_template() {
		?>
		<script type="text/html" id="tmpl-videopress_iframe_vnext">
			<iframe class="videopress-iframe" style="display: block; max-width: 100%; max-height: 180px;" width="{{ data.width }}" height="{{ data.height }}" src="https://videopress.com/embed/{{ data.guid }}?{{ data.urlargs }}" frameborder='0' allowfullscreen></iframe>
		</script>
		<script type="text/html" id="tmpl-attachment-details-videopress">
			<h2>
				<?php echo self::get_logo_svg(); ?>
			</h2>
			<div class="attachment-info">
				<div class="wp-media-wrapper wp-video">
				</div>
				<?php self::attachment_info_template_part(); ?>
			</div>
		</script>
		<script>
			jQuery(document).ready( function($) {
				if( typeof wp.media.view.Attachment.Details != 'undefined' ){
					var DetailsTemplate = wp.media.view.Attachment.Details,
						old_render      = DetailsTemplate.prototype.render,
						vp_template     = wp.template('videopress_iframe_vnext');

						DetailsTemplate.prototype.initialize = function() {
							if ( 'video' === this.model.attributes.type && 'videopress' === this.model.attributes.subtype ) {
								this.template = wp.template( 'attachment-details-videopress' );
							} else {
								this.template = wp.template( 'attachment-details' );
							}
							// From this point on, we are just copying the function from core.
							this.options = _.defaults( this.options, {
								rerenderOnModelChange: false
							});

							// Call 'initialize' directly on the parent class.
							wp.media.view.Attachment.prototype.initialize.apply( this, arguments );

							this.copyAttachmentDetailsURLClipboard();
						}

						// Add the VideoPress player
						DetailsTemplate.prototype.render = function() {
							// Have the original renderer run first.
							old_render.apply( this, arguments );

							// Now our stuff!
							if ( 'video' === this.model.get('type') ) {
								if ( this.model.get('videopress_guid') ) {
									this.$('.attachment-info .wp-video').html( vp_template( {
										guid   : this.model.get('videopress_guid'),
										// width  : this.model.get('width') > 0 ? this.model.get('width') : '100%',
										// height : this.model.get('height') > 0 ? this.model.get('height') : '100%'
									}));
								}
							}
						};
				}
			});
		</script>
		<?php
	}

	/**
	 * Echoes the piece of the custom template that is shared between the two templates above
	 *
	 * @return void
	 */
	protected static function attachment_info_template_part() {
		?>
		<span class="setting" data-setting="filename">
			<label for="attachment-details-filename" class="name"><?php _e( 'File name', 'jetpack-videopress-pkg' ); ?></label>
			<input type="text" id="attachment-details-filename" value="{{ data.filename }}" readonly />
		</span>
		<span class="setting" data-setting="fileurl">
			<label for="attachment-details-copy-link" class="name"><?php _e( 'File URL:', 'jetpack-videopress-pkg' ); ?></label>
			<input type="text" class="attachment-details-copy-link" id="attachment-details-copy-link" value="{{ data.url }}" readonly />
			<div class="copy-to-clipboard-container">
				<button type="button" class="button button-small copy-attachment-url" data-clipboard-target="#attachment-details-copy-link"><?php _e( 'Copy URL to clipboard', 'jetpack-videopress-pkg' ); ?></button>
				<span class="success hidden" aria-hidden="true"><?php _e( 'Copied!', 'jetpack-videopress-pkg' ); ?></span>
			</div>
		</span>
		<p><a href="{{ data.editLink }}" class="button button-medium" target="_blank"><?php _e( 'Edit video details', 'jetpack-videopress-pkg' ); ?></a></p>
		<?php
	}
	// phpcs:enable WordPress.Security.EscapeOutput.UnsafePrintingFunction
	// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
}
