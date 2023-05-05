<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * This file defines the base class for the Site Abstraction Layer (SAL).
 * Note that this is the site "as seen by user $user_id with token $token", which
 * is why we pass the token to the platform; these site instances are value objects
 * to be used in the context of a single request for a single user.
 * Also note that at present this class _assumes_ you've "switched to"
 * the site in question, and functions like `get_bloginfo( 'name' )` will
 * therefore return the correct value.
 *
 * @package automattic/jetpack
 **/

use Automattic\Jetpack\Blaze;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Status\Host;

require_once __DIR__ . '/class.json-api-date.php';
require_once __DIR__ . '/class.json-api-post-base.php';

/**
 * Base class for SAL_Site.
 * The abstract functions here are extended by Abstract_Jetpack_Site in class.json-api-site-jetpack-base.php.
 */
abstract class SAL_Site {

	/**
	 *  The Jetpack blog ID for the site.
	 *
	 * @var int
	 */
	public $blog_id;

	/**
	 * A new WPORG_Platform instance.
	 *
	 * @see class.json-api-platform-jetpack.php.
	 *
	 * @var WPORG_Platform
	 */
	public $platform;

	/**
	 * Contructs the SAL_Site instance.
	 *
	 * @param int            $blog_id The Jetpack blog ID for the site.
	 * @param WPORG_Platform $platform  A new WPORG_Platform instance.
	 */
	public function __construct( $blog_id, $platform ) {
		$this->blog_id  = $blog_id;
		$this->platform = $platform;
	}

	/**
	 * Get the blog_id property.
	 *
	 * @return int
	 */
	public function get_id() {
		return $this->blog_id;
	}

	/**
	 * Returns the site name.
	 *
	 * @return string
	 */
	public function get_name() {
		return (string) htmlspecialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
	}

	/**
	 * Returns the site description.
	 *
	 * @return string
	 */
	public function get_description() {
		return (string) htmlspecialchars_decode( get_bloginfo( 'description' ), ENT_QUOTES );
	}

	/**
	 * Returns the URL for the current site.
	 *
	 * @return string
	 */
	public function get_url() {
		return (string) home_url();
	}

	/**
	 * Returns the number of published posts with the 'post' post-type.
	 *
	 * @return int
	 */
	public function get_post_count() {
		return (int) wp_count_posts( 'post' )->publish;
	}

	/**
	 * A prototype function for get_quota - currently returns null.
	 *
	 * @return null
	 */
	public function get_quota() {
		return null;
	}

	/**
	 * Returns an array of blogging prompt settings. Only applicable on WordPress.com.
	 *
	 * Data comes from .com since the fearture requires a .com connection to work.
	 *
	 * @param int $user_id the current user_id.
	 * @param int $blog_id the blog id in this context.
	 */
	public function get_blogging_prompts_settings( $user_id, $blog_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return false;
	}

	/**
	 * Returns true if a site has the 'videopress' option enabled, false otherwise.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function has_videopress();

	/**
	 * Returns VideoPress storage used, in MB.
	 *
	 * @see class.json-api-site-jetpack-shadow.php on WordPress.com for implementation. Only applicable on WordPress.com.
	 */
	abstract public function get_videopress_storage_used();

	/**
	 * Sets the upgraded_filetypes_enabled Jetpack option to true as a default. Only relevant for WordPress.com sites.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function upgraded_filetypes_enabled();

	/**
	 * Sets the is_mapped_domain Jetpack option to true as a default.
	 *
	 * Primarily used in WordPress.com to confirm the current blog's domain does or doesn't match the primary redirect.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_mapped_domain();

	/**
	 * Fallback to the home URL since all Jetpack sites don't have an unmapped *.wordpress.com domain.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_unmapped_url();

	/**
	 * Whether the domain is a site redirect or not. Defaults to false on a Jetpack site.
	 *
	 * Primarily used in WordPress.com where it is determined if a HTTP status check is a redirect or not and whether an exception should be thrown.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_redirect();

	/**
	 * Defaults to false on Jetpack sites, however is used on WordPress.com sites, where it returns true if the headstart-fresh blog sticker is present.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_headstart_fresh();

	/**
	 * If the site's current theme supports post thumbnails, return true (otherwise return false).
	 *
	 * @see class.json-api-site-jetpack-base.php for implementation.
	 */
	abstract public function featured_images_enabled();

	/**
	 * Whether or not the Jetpack 'wordads' module is active on the site.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function has_wordads();

	/**
	 * Defaults to false on Jetpack sites, however is used on WordPress.com sites. This nonce is used for previews on Jetpack sites.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_frame_nonce();

	/**
	 * Defaults to false on Jetpack sites, however is used on WordPress.com sites where
	 * it creates a nonce to be used with iframed block editor requests to a Jetpack site.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_jetpack_frame_nonce();

	/**
	 * Returns the allowed mime types and file extensions for a site.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function allowed_file_types();

	/**
	 * Returns an array of supported post formats.
	 *
	 * @see class.json-api-site-jetpack-base.php for implementation.
	 */
	abstract public function get_post_formats();

	/**
	 * Return site's privacy status.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_private();

	/**
	 * Return site's coming soon status.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_coming_soon();

	/**
	 * Whether or not the current user is following this blog. Defaults to false.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_following();

	/**
	 * Defaults to 0 for the number of WordPress.com subscribers - this is filled in on the WordPress.com side.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_subscribers_count();

	/**
	 * Returns the language code for the current site.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_locale();

	/**
	 * The flag indicates that the site has Jetpack installed.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_jetpack();

	/**
	 * The flag indicates that the site is connected to WP.com via Jetpack Connection.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_jetpack_connection();

	/**
	 * This function returns the values of any active Jetpack modules.
	 *
	 * @see class.json-api-site-jetpack-base.php for implementation.
	 */
	abstract public function get_jetpack_modules();

	/**
	 * This function returns true if a specified Jetpack module is active, false otherwise.
	 *
	 * @see class.json-api-site-jetpack-base.php for implementation.
	 *
	 * @param string $module The Jetpack module name to check.
	 */
	abstract public function is_module_active( $module );

	/**
	 * This function returns false for a check as to whether a site is a VIP site or not.
	 *
	 * @see class.json-api-site-jetpack-base.php for implementation.
	 */
	abstract public function is_vip();

	/**
	 * Returns true if Multisite is enabled, false otherwise.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_multisite();

	/**
	 * Points to the user ID of the site owner
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_site_owner();

	/**
	 * Returns true if the current site is a single user site, false otherwise.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function is_single_user_site();

	/**
	 * Defaults to false instead of returning the current site plan.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_plan();

	/**
	 * Empty function declaration - this function is filled out on the WordPress.com side, returning true if the site has an AK / VP bundle.
	 *
	 * @see class.json-api-site-jetpack.php and /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 */
	abstract public function get_ak_vp_bundle_enabled();

	/**
	 * Returns null for Jetpack sites. For WordPress.com sites this returns the value of the 'podcasting_archive' option.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_podcasting_archive();

	/**
	 * Return the last engine used for an import on the site. Not used in Jetpack.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_import_engine();

	/**
	 * Returns the front page meta description for current site.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_jetpack_seo_front_page_description();

	/**
	 * Returns custom title formats from site option.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_jetpack_seo_title_formats();

	/**
	 * Returns website verification codes. Allowed keys include: google, pinterest, bing, yandex, facebook.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_verification_services_codes();

	/**
	 * This function is implemented on WPCom sites, where a filter is removed which forces the URL to http.
	 *
	 * @see class.json-api-site-jetpack-base.php and /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 */
	abstract public function before_render();

	/**
	 * If a user has manage options permissions and the site is the main site of the network, make updates visible.
	 *
	 * Called after response_keys have been rendered, which itself is used to return all the necessary information for a site’s response.
	 *
	 * @see class.json-api-site-jetpack-base.php for implementation.
	 *
	 * @param array $response an array of the response keys.
	 */
	abstract public function after_render( &$response );

	/**
	 * Extends the Jetpack options array with details including site constraints, WordPress and Jetpack versions, and plugins using the Jetpack connection.
	 *
	 * @see class.json-api-site-jetpack-base.php for implementation.
	 * @todo factor this out? Seems an odd thing to have on a site
	 *
	 * @param array $options an array of the Jetpack options.
	 */
	abstract public function after_render_options( &$options );

	/**
	 * Wrap a WP_Post object with SAL methods, returning a Jetpack_Post object.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 *
	 * @param WP_Post $post A WP_Post object.
	 * @param string  $context The post request context (for example 'edit' or 'display').
	 */
	abstract public function wrap_post( $post, $context );

	/**
	 * For Jetpack sites this will always return false.
	 *
	 * @see class.json-api-site-jetpack-base.php for implementation.
	 *
	 * @param int $post_id The post id.
	 */
	abstract protected function is_a8c_publication( $post_id );

	/**
	 * Return the user interactions with a site. Not used in Jetpack.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_user_interactions();

	/**
	 * Defines a filter to set whether a site is an automated_transfer site or not.
	 *
	 * Default is false.
	 *
	 * @return bool
	 */
	public function is_automated_transfer() {
		/**
		 * Filter if a site is an automated-transfer site.
		 *
		 * @module json-api
		 *
		 * @since 6.4.0
		 *
		 * @param bool is_automated_transfer( $this->blog_id )
		 * @param int  $blog_id Blog identifier.
		 */
		return apply_filters(
			'jetpack_site_automated_transfer',
			false,
			$this->blog_id
		);
	}

	/**
	 * Defaulting to false and not relevant for Jetpack sites, this is expanded on the WordPress.com side for a specific wp.com/start 'WP for teams' flow.
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract protected function is_wpforteams_site();

	/**
	 * Get hub blog id for P2 sites.
	 *
	 * @return null
	 */
	public function get_p2_hub_blog_id() {
		return null;
	}

	/**
	 * Getter for the p2 organization ID.
	 *
	 * @return int
	 */
	public function get_p2_organization_id() {
		return 0; // WPForTeams\Constants\NO_ORG_ID not loaded.
	}

	/**
	 * Get details used to render a thumbnail of the site. P2020 themed sites only.
	 *
	 * @return ?array
	 */
	public function get_p2_thumbnail_elements() {
		return null;
	}

	/**
	 * Detect whether a site is a WordPress.com on Atomic site.
	 *
	 * @return bool
	 */
	public function is_wpcom_atomic() {
		return ( new Host() )->is_woa_site();
	}

	/**
	 * Detect whether a site is WordPress.com Staging Site.
	 *
	 * @return bool
	 */
	public function is_wpcom_staging_site() {
		if ( function_exists( 'is_blog_wpcom_staging' ) ) {
			return is_blog_wpcom_staging( $this->blog_id );
		}
		return false;
	}

	/**
	 * Detect whether a site is an automated transfer site and WooCommerce is active.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 *
	 * @return bool - False for Jetpack-connected sites.
	 */
	public function is_wpcom_store() {
		return false;
	}

	/**
	 * Indicate whether this site was ever an eCommerce trial.
	 *
	 * @return bool
	 */
	public function was_ecommerce_trial() {
		if ( function_exists( 'has_blog_sticker' ) ) {
			return has_blog_sticker( 'had-ecommerce-trial' );
		}
		return false;
	}

	/**
	 * Detect whether a site has the WooCommerce plugin active.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 *
	 * @return bool - Default false for Jetpack-connected sites.
	 */
	public function woocommerce_is_active() {
		return false;
	}

	/**
	 * Whether the Editing Toolkit plugin is active (relevant only on WordPress.com).
	 *
	 * @return true
	 */
	public function editing_toolkit_is_active() {
		return true;
	}

	/**
	 * Detect whether a site has access to the Jetpack cloud.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 *
	 * @return bool - Default false for Jetpack-connected sites.
	 */
	public function is_cloud_eligible() {
		return false;
	}

	/**
	 * Returns an array of WPCOM_Store products.
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php.
	 *
	 * @return bool - Default empty array for Jetpack-connected sites.
	 */
	public function get_products() {
		return array();
	}

	/**
	 * Get post by ID
	 *
	 * @param int    $post_id The ID of the post.
	 * @param string $context The context by which the post data is required (display or edit).
	 *
	 * @return Jetpack_Post Post object on success, WP_Error object on failure
	 **/
	public function get_post_by_id( $post_id, $context ) {
		$post = get_post( $post_id, OBJECT, $context );

		if ( ! $post ) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		$wrapped_post = $this->wrap_post( $post, $context );
		// validate access
		return $this->validate_access( $wrapped_post );
	}

	/**
	 * Validate current user can access the post
	 *
	 * @param Jetpack_Post $post Post object.
	 *
	 * @return WP_Error|Jetpack_Post
	 */
	private function validate_access( $post ) {
		$context = $post->context;

		if (
			! $this->is_post_type_allowed( $post->post_type )
			&& ! $this->is_a8c_publication( $post->ID )
		) {
			return new WP_Error( 'unknown_post', 'Unknown post', 404 );
		}

		switch ( $context ) {
			case 'edit':
				if ( ! current_user_can( 'edit_post', $post->ID ) ) {
					return new WP_Error( 'unauthorized', 'User cannot edit post', 403 );
				}
				break;
			case 'display':
				$can_view = $this->user_can_view_post( $post );
				if ( is_wp_error( $can_view ) ) {
					return $can_view;
				}
				break;
			default:
				return new WP_Error( 'invalid_context', 'Invalid API CONTEXT', 400 );
		}

		return $post;
	}

	/**
	 * Validate whether the current user can access the specified post type.
	 *
	 * @param string $post_type The post type to check.
	 * @param string $context The context by which the post data is required (display or edit).
	 *
	 * @return bool
	 */
	public function current_user_can_access_post_type( $post_type, $context ) {
		$post_type_object = $this->get_post_type_object( $post_type );
		if ( ! $post_type_object ) {
			return false;
		}

		switch ( $context ) {
			case 'edit':
				return current_user_can( $post_type_object->cap->edit_posts );
			case 'display':
				return $post_type_object->public || current_user_can( $post_type_object->cap->read_private_posts );
			default:
				return false;
		}
	}

	/**
	 * Retrieves a post type object by name.
	 *
	 * @param string $post_type The post type to check.
	 *
	 * @return WP_Post_Type|null
	 */
	protected function get_post_type_object( $post_type ) {
		return get_post_type_object( $post_type );
	}

	/**
	 * Is the post type allowed?
	 *
	 * Function copied from class.json-api-endpoints.php.
	 *
	 * @param string $post_type Post type.
	 *
	 * @return bool
	 */
	public function is_post_type_allowed( $post_type ) {
		// if the post type is empty, that's fine, WordPress will default to post
		if ( empty( $post_type ) ) {
			return true;
		}

		// allow special 'any' type
		if ( 'any' === $post_type ) {
			return true;
		}

		// check for allowed types
		if ( in_array( $post_type, $this->get_whitelisted_post_types(), true ) ) {
			return true;
		}

		$post_type_object = get_post_type_object( $post_type );
		if ( $post_type_object ) {
			if ( ! empty( $post_type_object->show_in_rest ) ) {
				return $post_type_object->show_in_rest;
			}
			if ( ! empty( $post_type_object->publicly_queryable ) ) {
				return $post_type_object->publicly_queryable;
			}
		}

		return ! empty( $post_type_object->public );
	}

	/**
	 * Gets the whitelisted post types that JP should allow access to.
	 *
	 * Function copied from class.json-api-endpoints.php.
	 *
	 * @return array Whitelisted post types.
	 */
	public function get_whitelisted_post_types() {
		$allowed_types = array( 'post', 'page', 'revision' );

		/**
		 * Filter the post types Jetpack has access to, and can synchronize with WordPress.com.
		 *
		 * @module json-api
		 *
		 * @since 2.2.3
		 *
		 * @param array $allowed_types Array of whitelisted post types. Default to `array( 'post', 'page', 'revision' )`.
		 */
		$allowed_types = apply_filters( 'rest_api_allowed_post_types', $allowed_types );

		return array_unique( $allowed_types );
	}

	/**
	 * Can the user view the post?
	 *
	 * Function copied from class.json-api-endpoints.php and modified.
	 *
	 * @param Jetpack_Post $post Post object.
	 * @return bool|WP_Error
	 */
	private function user_can_view_post( $post ) {
		if ( ! $post || is_wp_error( $post ) ) {
			return false;
		}

		if ( 'inherit' === $post->post_status ) {
			$parent_post     = get_post( $post->post_parent );
			$post_status_obj = get_post_status_object( $parent_post->post_status );
		} else {
			$post_status_obj = get_post_status_object( $post->post_status );
		}

		$authorized = (
			$post_status_obj->public ||
			( is_user_logged_in() &&
				(
					( $post_status_obj->protected && current_user_can( 'edit_post', $post->ID ) ) ||
					( $post_status_obj->private && current_user_can( 'read_post', $post->ID ) ) ||
					( 'trash' === $post->post_status && current_user_can( 'edit_post', $post->ID ) ) ||
					'auto-draft' === $post->post_status
				)
			)
		);

		if ( ! $authorized ) {
			return new WP_Error( 'unauthorized', 'User cannot view post', 403 );
		}

		if (
			( new Status() )->is_private_site() &&
			/**
			 * Filter access to a specific post.
			 *
			 * @module json-api
			 *
			 * @since 3.4.0
			 *
			 * @param bool current_user_can( 'read_post', $post->ID ) Can the current user access the post.
			 * @param WP_Post $post Post data.
			 */
			! apply_filters(
				'wpcom_json_api_user_can_view_post',
				current_user_can( 'read_post', $post->ID ),
				$post
			)
		) {
			return new WP_Error(
				'unauthorized',
				'User cannot view post',
				array(
					'status_code' => 403,
					'error'       => 'private_blog',
				)
			);
		}

		if ( strlen( $post->post_password ) && ! current_user_can( 'edit_post', $post->ID ) ) {
			return new WP_Error(
				'unauthorized',
				'User cannot view password protected post',
				array(
					'status_code' => 403,
					'error'       => 'password_protected',
				)
			);
		}

		return true;
	}

	/**
	 * Get post ID by name
	 *
	 * Attempts to match name on post title and page path
	 *
	 * @param string $name The post name.
	 *
	 * @return int|WP_Error Post ID on success, WP_Error object on failure
	 */
	public function get_post_id_by_name( $name ) {
		$name = sanitize_title( $name );

		if ( ! $name ) {
			return new WP_Error( 'invalid_post', 'Invalid post', 400 );
		}

		$posts = get_posts(
			array(
				'name'        => $name,
				'numberposts' => 1,
				'post_type'   => $this->get_whitelisted_post_types(),
			)
		);

		if ( ! $posts || ! isset( $posts[0]->ID ) || ! $posts[0]->ID ) {
			$page = get_page_by_path( $name );

			if ( ! $page ) {
				return new WP_Error( 'unknown_post', 'Unknown post', 404 );
			}

			return $page->ID;
		}

		return (int) $posts[0]->ID;
	}

	/**
	 * Get post by name
	 *
	 * Attempts to match name on post title and page path
	 *
	 * @param string $name The post name.
	 * @param string $context (display or edit).
	 *
	 * @return Jetpack_Post|WP_Error Post object on success, WP_Error object on failure
	 **/
	public function get_post_by_name( $name, $context ) {
		$post_id = $this->get_post_id_by_name( $name );
		if ( is_wp_error( $post_id ) ) {
			return $post_id;
		}

		return $this->get_post_by_id( $post_id, $context );
	}

	/**
	 * Whether or not the current user is an admin (has option management capabilities).
	 *
	 * @return bool
	 **/
	public function user_can_manage() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Returns the XMLRPC URL - the site URL including the URL scheme that is used when querying your site's REST API endpoint.
	 *
	 * @return string
	 **/
	public function get_xmlrpc_url() {
		$xmlrpc_scheme = apply_filters( 'wpcom_json_api_xmlrpc_scheme', wp_parse_url( get_option( 'home' ), PHP_URL_SCHEME ) );
		return site_url( 'xmlrpc.php', $xmlrpc_scheme );
	}

	/**
	 * Returns a date/time string with the date the site was registered, or a default date/time string otherwise.
	 *
	 * @return string
	 **/
	public function get_registered_date() {
		if ( function_exists( 'get_blog_details' ) ) {
			$blog_details = get_blog_details();
			if ( ! empty( $blog_details->registered ) ) {
				return WPCOM_JSON_API_Date::format_date( $blog_details->registered );
			}
		}

		return '0000-00-00T00:00:00+00:00';
	}

	/**
	 * Returns a date/time string with the date the site was last updated, or a default date/time string otherwise.
	 *
	 * @return string
	 **/
	public function get_last_update_date() {
		if ( function_exists( 'get_blog_details' ) ) {
			$blog_details = get_blog_details();
			if ( ! empty( $blog_details->last_updated ) ) {
				return WPCOM_JSON_API_Date::format_date( $blog_details->last_updated );
			}
		}

		return '0000-00-00T00:00:00+00:00';
	}

	/**
	 * Returns an array including the current users relevant capabilities.
	 *
	 * @return array
	 **/
	public function get_capabilities() {
		$is_wpcom_blog_owner = wpcom_get_blog_owner() === (int) get_current_user_id();

		return array(
			'edit_pages'          => current_user_can( 'edit_pages' ),
			'edit_posts'          => current_user_can( 'edit_posts' ),
			'edit_others_posts'   => current_user_can( 'edit_others_posts' ),
			'edit_others_pages'   => current_user_can( 'edit_others_pages' ),
			'delete_posts'        => current_user_can( 'delete_posts' ),
			'delete_others_posts' => current_user_can( 'delete_others_posts' ),
			'edit_theme_options'  => current_user_can( 'edit_theme_options' ),
			'edit_users'          => current_user_can( 'edit_users' ),
			'list_users'          => current_user_can( 'list_users' ),
			'manage_categories'   => current_user_can( 'manage_categories' ),
			'manage_options'      => current_user_can( 'manage_options' ),
			'moderate_comments'   => current_user_can( 'moderate_comments' ),
			'activate_wordads'    => $is_wpcom_blog_owner,
			'promote_users'       => current_user_can( 'promote_users' ),
			'publish_posts'       => current_user_can( 'publish_posts' ),
			'upload_files'        => current_user_can( 'upload_files' ),
			'delete_users'        => current_user_can( 'delete_users' ),
			'remove_users'        => current_user_can( 'remove_users' ),
			'own_site'            => $is_wpcom_blog_owner,
			/**
			 * Filter whether the Hosting section in Calypso should be available for site.
			 *
			 * @module json-api
			 *
			 * @since 8.2.0
			 *
			 * @param bool $view_hosting Can site access Hosting section. Default to false.
			 */
			'view_hosting'        => apply_filters( 'jetpack_json_api_site_can_view_hosting', false ),
			'view_stats'          => stats_is_blog_user( $this->blog_id ),
			'activate_plugins'    => current_user_can( 'activate_plugins' ),
		);
	}

	/**
	 * Whether or not a site is public.
	 *
	 * @return bool
	 **/
	public function is_visible() {
		if ( is_user_logged_in() ) {
			$current_user = wp_get_current_user();
			$visible      = (array) get_user_meta( $current_user->ID, 'blog_visibility', true );

			$is_visible = true;
			if ( isset( $visible[ $this->blog_id ] ) ) {
				$is_visible = (bool) $visible[ $this->blog_id ];
			}

			// null and true are visible
			return $is_visible;
		}

		return null;
	}

	/**
	 * Creates and returns an array with logo settings.
	 *
	 * @return array
	 **/
	public function get_logo() {
		// Set an empty response array.
		$logo_setting = array(
			'id'    => (int) 0,
			'sizes' => array(),
			'url'   => '',
		);

		// Get current site logo values.
		$logo_id = get_option( 'site_logo' );

		// Update the response array if there's a site logo currenty active.
		if ( $logo_id ) {
			$logo_setting['id']  = $logo_id;
			$logo_setting['url'] = wp_get_attachment_url( $logo_id );
		}

		return $logo_setting;
	}

	/**
	 * Returns the timezone string from the site's settings (eg. 'Europe/London').
	 *
	 * @return string
	 **/
	public function get_timezone() {
		return (string) get_option( 'timezone_string' );
	}

	/**
	 * Returns the GMT offset from the site's settings (eg. 5.5).
	 *
	 * @return float
	 **/
	public function get_gmt_offset() {
		return (float) get_option( 'gmt_offset' );
	}

	/**
	 * Returns the site's login URL.
	 *
	 * @return string
	 **/
	public function get_login_url() {
		return wp_login_url();
	}

	/**
	 * Returns the URL for a site's admin area.
	 *
	 * @return string
	 **/
	public function get_admin_url() {
		return get_admin_url();
	}

	/**
	 * Returns the theme's slug (eg. 'twentytwentytwo')
	 *
	 * @return string
	 **/
	public function get_theme_slug() {
		return get_option( 'stylesheet' );
	}

	/**
	 * Gets the header image data.
	 *
	 * @return bool|object
	 **/
	public function get_header_image() {
		return get_theme_mod( 'header_image_data' );
	}

	/**
	 * Gets the theme background color.
	 *
	 * @return bool|string
	 **/
	public function get_background_color() {
		return get_theme_mod( 'background_color' );
	}

	/**
	 * Get the image default link type.
	 *
	 * @return string
	 **/
	public function get_image_default_link_type() {
		return get_option( 'image_default_link_type' );
	}

	/**
	 * Gets the image thumbnails width.
	 *
	 * @return int
	 **/
	public function get_image_thumbnail_width() {
		return (int) get_option( 'thumbnail_size_w' );
	}

	/**
	 * Gets the image thumbnails height.
	 *
	 * @return int
	 **/
	public function get_image_thumbnail_height() {
		return (int) get_option( 'thumbnail_size_h' );
	}

	/**
	 * Whether cropping is enabled for thumbnails.
	 *
	 * @return string
	 **/
	public function get_image_thumbnail_crop() {
		return get_option( 'thumbnail_crop' );
	}

	/**
	 * Gets the medium sized image setting's width.
	 *
	 * @return int
	 **/
	public function get_image_medium_width() {
		return (int) get_option( 'medium_size_w' );
	}

	/**
	 * Gets the medium sized image setting's height.
	 *
	 * @return int
	 **/
	public function get_image_medium_height() {
		return (int) get_option( 'medium_size_h' );
	}

	/**
	 * Gets the large sized image setting's width.
	 *
	 * @return int
	 **/
	public function get_image_large_width() {
		return (int) get_option( 'large_size_w' );
	}

	/**
	 * Gets the large sized image setting's height.
	 *
	 * @return int
	 **/
	public function get_image_large_height() {
		return (int) get_option( 'large_size_h' );
	}

	/**
	 * Gets the permalink structure as defined in the site's settings.
	 *
	 * @return string
	 **/
	public function get_permalink_structure() {
		return get_option( 'permalink_structure' );
	}

	/**
	 * Gets the default post format
	 *
	 * @return string
	 **/
	public function get_default_post_format() {
		return get_option( 'default_post_format' );
	}

	/**
	 * Gets the default post category
	 *
	 * @return int
	 **/
	public function get_default_category() {
		return (int) get_option( 'default_category' );
	}

	/**
	 * Returns what should be shown on the front page (eg. page or posts)
	 *
	 * @return string
	 **/
	public function get_show_on_front() {
		return get_option( 'show_on_front' );
	}

	/**
	 * Whether or not the front page is set as 'page' to allow a custom front page
	 *
	 * @return bool
	 **/
	public function is_custom_front_page() {
		return ( 'page' === $this->get_show_on_front() );
	}

	/**
	 * Whether or not likes have been enabled on all site posts
	 *
	 * @return bool
	 **/
	public function get_default_likes_enabled() {
		return (bool) apply_filters( 'wpl_is_enabled_sitewide', ! get_option( 'disabled_likes' ) );
	}

	/**
	 * If sharing has been enabled and there are visible blog services (eg. 'facebook', 'twitter'), returns true.
	 *
	 * @return bool
	 **/
	public function get_default_sharing_status() {
		$default_sharing_status = false;
		if ( class_exists( 'Sharing_Service' ) ) {
			$ss                     = new Sharing_Service();
			$blog_services          = $ss->get_blog_services();
			$default_sharing_status = ! empty( $blog_services['visible'] );
		}
		return (bool) $default_sharing_status;
	}

	/**
	 * Displays the current comment status
	 *
	 * @return bool  False if closed, true for all other comment statuses.
	 **/
	public function get_default_comment_status() {
		return 'closed' !== get_option( 'default_comment_status' );
	}

	/**
	 * Displays the current site-wide post ping status (for pingbacks and trackbacks)
	 *
	 * @return bool  False if closed, true for all other ping statuses.
	 **/
	public function default_ping_status() {
		return 'closed' !== get_option( 'default_ping_status' );
	}

	/**
	 * Whether or not Publicize has been permanently disabled on the site
	 *
	 * @see wpcom/wp-content/admin-plugins/publicize/publicize-wpcom.php
	 *
	 * @return bool  Default false.
	 **/
	public function is_publicize_permanently_disabled() {
		$publicize_permanently_disabled = false;
		if ( function_exists( 'is_publicize_permanently_disabled' ) ) {
			$publicize_permanently_disabled = is_publicize_permanently_disabled( $this->blog_id );
		}
		return $publicize_permanently_disabled;
	}

	/**
	 * Returns the post ID of the static front page.
	 *
	 * @return int
	 **/
	public function get_page_on_front() {
		return (int) get_option( 'page_on_front' );
	}

	/**
	 * Returns the post ID of the page designated as the posts page.
	 *
	 * @return int
	 **/
	public function get_page_for_posts() {
		return (int) get_option( 'page_for_posts' );
	}

	/**
	 * Whether or not headstart is enabled for the site
	 *
	 * @return bool
	 **/
	public function is_headstart() {
		return get_option( 'headstart' );
	}

	/**
	 * The WordPress version on the site.
	 *
	 * @return string
	 **/
	public function get_wordpress_version() {
		global $wp_version;
		return $wp_version;
	}

	/**
	 * Whether or not this is a domain-only site (only relevant on WordPress.com simple sites - false otherwise)
	 *
	 * @return bool
	 **/
	public function is_domain_only() {
		$options = get_option( 'options' );
		return ! empty( $options['is_domain_only'] ) ? (bool) $options['is_domain_only'] : false;
	}

	/**
	 * Whether or not the blog is set to public (not hidden from search engines)
	 *
	 * @return int 1 for true, 0 for false.
	 **/
	public function get_blog_public() {
		return (int) get_option( 'blog_public' );
	}

	/**
	 * Whether or not the site is in a 'pending automated transfer' state.
	 *
	 * @return bool
	 **/
	public function has_pending_automated_transfer() {
		/**
		 * Filter if a site is in pending automated transfer state.
		 *
		 * @module json-api
		 *
		 * @since 6.4.0
		 *
		 * @param bool has_site_pending_automated_transfer( $this->blog_id )
		 * @param int  $blog_id Blog identifier.
		 */
		return apply_filters(
			'jetpack_site_pending_automated_transfer',
			false,
			$this->blog_id
		);
	}

	/**
	 * Whether or not the site has a 'designType' option set as 'store'
	 *
	 * @return bool
	 **/
	public function signup_is_store() {
		return $this->get_design_type() === 'store';
	}

	/**
	 * Return a new WP_Roles instance, which implements a user roles API
	 *
	 * @return WP_Roles
	 **/
	public function get_roles() {
		return new WP_Roles();
	}

	/**
	 * Returns the 'designType' option if set (the site design type), null otherwise.
	 *
	 * @return string|null
	 **/
	public function get_design_type() {
		$options = get_option( 'options' );
		return empty( $options['designType'] ) ? null : $options['designType'];
	}

	/**
	 * Returns the 'siteGoals' option if set (eg. share, promote, educate, sell, showcase), null otherwise.
	 *
	 * @return string|null
	 **/
	public function get_site_goals() {
		$options = get_option( 'options' );
		return empty( $options['siteGoals'] ) ? null : $options['siteGoals'];
	}

	/**
	 * Return site's launch status. Expanded in class.json-api-site-jetpack.php.
	 *
	 * @return bool False in this case.
	 */
	public function get_launch_status() {
		return false;
	}

	/**
	 * Whether a site has any migration meta details - only applicable on WordPress.com
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-jetpack-shadow.php
	 *
	 * @return null
	 */
	public function get_migration_meta() {
		return null;
	}

	/**
	 * Whether a site has a site segment - only applicable on WordPress.com
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-wpcom.php
	 *
	 * @return false
	 */
	public function get_site_segment() {
		return false;
	}

	/**
	 * Whether a site has Vertical ID (used for Starter Templates) - default to only applicable on WordPress.com
	 *
	 * @see /wpcom/public.api/rest/sal/class.json-api-site-wpcom.php
	 *
	 * @return false
	 */
	public function get_site_vertical_id() {
		return false;
	}

	/**
	 * Whether a site has a 'site_creation_flow' option set (eg gutenboarding, mobile) - only applicable on WordPress.com
	 *
	 * @see /wpcom-json-endpoints/class.wpcom-json-api-new-site-endpoint.php for more on the option.
	 *
	 * @return bool
	 */
	public function get_site_creation_flow() {
		return get_option( 'site_creation_flow' );
	}

	/**
	 * Whether a site has a 'site_source_slug' option set - only applicable on WordPress.com
	 *
	 * @see /wpcom-json-endpoints/class.wpcom-json-api-new-site-endpoint.php for more on the option.
	 *
	 * @return bool
	 */
	public function get_site_source_slug() {
			return get_option( 'site_source_slug' );
	}

	/**
	 * Return any selected features (used to help recommend plans)
	 *
	 * @return string
	 */
	public function get_selected_features() {
		return get_option( 'selected_features' );
	}

	/**
	 * Return true if the site design was created with a Blank Canvas (empty homepage template), false otherwise.
	 *
	 * @return bool
	 */
	public function was_created_with_blank_canvas_design() {
		return (bool) get_option( 'was_created_with_blank_canvas_design' );
	}

	/**
	 * Get the option storing the Anchor podcast ID that identifies a site as a podcasting site.
	 *
	 * @return string
	 */
	public function get_anchor_podcast() {
		return get_option( 'anchor_podcast' );
	}

	/**
	 * Check if the site is currently being built by the DIFM Lite team.
	 *
	 * @return bool
	 */
	public function is_difm_lite_in_progress() {
		if ( function_exists( 'has_blog_sticker' ) ) {
			return has_blog_sticker( 'difm-lite-in-progress' );
		} elseif ( function_exists( 'wpcomsh_is_site_sticker_active' ) ) {
			// For atomic sites
			return wpcomsh_is_site_sticker_active( 'difm-lite-in-progress' );
		}
		return false;
	}

	/**
	 * The site options for DIFM lite in the design picker step
	 *
	 * @return string
	 */
	public function get_difm_lite_site_options() {
		return get_option( 'difm_lite_site_options' );
	}

	/**
	 * Get the option of site intent which value is coming from the Hero Flow
	 *
	 * @return string
	 */
	public function get_site_intent() {
		return get_option( 'site_intent', '' );
	}

	/**
	 * Get site option to determine if and how to display launchpad onboarding
	 *
	 * @return string
	 */
	public function get_launchpad_screen() {
		return get_option( 'launchpad_screen' );
	}

	/**
	 * Get site option for completed launchpad checklist tasks
	 *
	 * @return string
	 */
	public function get_launchpad_checklist_tasks_statuses() {
		$launchpad_checklist_tasks_statuses_option = get_option( 'launchpad_checklist_tasks_statuses' );

		if ( is_array( $launchpad_checklist_tasks_statuses_option ) ) {
			return $launchpad_checklist_tasks_statuses_option;
		}

		return array();
	}

	/**
	 * Get site option for the production blog id (if is a WP.com Staging Site).
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_wpcom_production_blog_id();

	/**
	 * Get site option for the staging blog ids (if it has them)
	 *
	 * @see class.json-api-site-jetpack.php for implementation.
	 */
	abstract public function get_wpcom_staging_blog_ids();

	/**
	 * Get the site's Blaze eligibility status.
	 *
	 * @return bool
	 */
	public function can_blaze() {
		return (bool) Blaze::site_supports_blaze( $this->blog_id );
	}
}
