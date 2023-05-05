<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Module Name: Jetpack Social
 * Module Description: Jetpack Social makes it easy to share your site’s posts on several social media networks automatically when you publish a new post.
 * Sort Order: 10
 * Recommendation Order: 7
 * First Introduced: 2.0
 * Requires Connection: Yes
 * Requires User Connection: Yes
 * Auto Activate: No
 * Module Tags: Social, Recommended
 * Feature: Engagement
 * Additional Search Queries: facebook, jetpack publicize, twitter, tumblr, linkedin, social, tweet, connections, sharing, social media, automated, automated sharing, auto publish, auto tweet and like, auto tweet, facebook auto post, facebook posting
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Class Jetpack_Publicize
 */
class Jetpack_Publicize {

	/**
	 * If Publicize is executing within Jetpack.
	 *
	 * @var bool
	 */
	public $in_jetpack = true;

	/**
	 * Jetpack_Publicize constructor.
	 */
	public function __construct() {
		global $publicize_ui;

		$this->modules    = new Automattic\Jetpack\Modules();
		$this->in_jetpack = ( class_exists( 'Jetpack' ) && method_exists( 'Jetpack', 'enable_module_configurable' ) ) ? true : false;

		if ( $this->in_jetpack ) {
			Jetpack::enable_module_configurable( __FILE__ );

			// if sharedaddy isn't active, the sharing menu hasn't been added yet.
			if ( $this->modules->is_active( 'publicize' ) && ! $this->modules->is_active( 'sharedaddy' ) ) {
				add_action( 'admin_menu', array( &$publicize_ui, 'sharing_menu' ) );
			}

			/*
			 * The Publicize Options array does not currently have UI since it is being added
			 * for a specific purpose and not part of a broader Publicize sprint.
			 *
			 * In order to pass the settings up to WordPress.com, we are updating an option to Sync will pass it up.
			 * To make it relatively easy for use, we are creating a filter that checks if the option and filter match.
			 *
			 * This only runs when a post is saved to avoid it running too much.
			 */
			add_action(
				'save_post',
				function () {
					$publicize_options = get_option( 'jetpack_publicize_options', array() );

					/**
					 * Filters the options for Publicize.
					 *
					 * As of Jetpack 8.5, the array keys could be:
					 * attach_media bool If Publicize should send the image to the social media platform. Default false.
					 *
					 * @module publicize
					 *
					 * @since 8.5.0
					 *
					 * @param array $options Array of Publicize options.
					 */
					$filtered = (array) apply_filters( 'jetpack_publicize_options', $publicize_options );

					if ( $publicize_options !== $filtered ) {
						update_option( 'jetpack_publicize_options', $filtered, false );
					}
				}
			);
		} else {
			global $publicize;
			require_once WP_CONTENT_DIR . '/mu-plugins/keyring/keyring.php';
			require_once WP_CONTENT_DIR . '/admin-plugins/publicize/publicize-wpcom.php';
			$publicize    = new Publicize();
			$publicize_ui = new Automattic\Jetpack\Publicize\Publicize_UI();
		}

		add_action(
			'jetpack_register_gutenberg_extensions',
			function () {
				global $publicize;
				if ( $publicize->current_user_can_access_publicize_data() ) {
					Jetpack_Gutenberg::set_extension_available( 'jetpack/publicize' );
				} else {
					Jetpack_Gutenberg::set_extension_unavailable( 'jetpack/publicize', 'unauthorized' );
				}
			}
		);
		$publicize_ui->in_jetpack = $this->in_jetpack;
	}
}

// On Jetpack, we instantiate Jetpack_Publicize only if the Publicize module is active.
if ( ! ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ) {
	global $publicize;

	// None of this should be the case, but we can get here with a broken user connection. If that's the case
	// then we want to stop loading any more of the module code.
	if (
		! ( new Automattic\Jetpack\Modules() )->is_active( 'publicize' )
		|| ! Jetpack::connection()->has_connected_user()
		|| ! $publicize
	) {
		return;
	}

	new Jetpack_Publicize();

	if ( ! function_exists( 'publicize_init' ) ) {
		/**
		 * Helper for grabbing a Publicize object from the "front-end" (non-admin) of
		 * a site. Normally Publicize is only loaded in wp-admin, so there's a little
		 * set up that you might need to do if you want to use it on the front end.
		 * Just call this function and it returns a Publicize object.
		 *
		 * @return Publicize Object
		 */
		function publicize_init() {
			global $publicize;

			return $publicize;
		}
	}
} else {
	// On wpcom, instantiate Jetpack_Publicize without any other checks.
	new Jetpack_Publicize();
}
