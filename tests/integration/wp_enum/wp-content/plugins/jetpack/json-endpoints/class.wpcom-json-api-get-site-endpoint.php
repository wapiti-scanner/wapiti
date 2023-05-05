<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_GET_Site_Endpoint(
	array(
		'description'                          => 'Get information about a site.',
		'group'                                => 'sites',
		'stat'                                 => 'sites:X',
		'allowed_if_flagged'                   => true,
		'method'                               => 'GET',
		'max_version'                          => '1.1',
		'new_version'                          => '1.2',
		'path'                                 => '/sites/%s',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'allow_jetpack_site_auth'              => true,

		'allow_fallback_to_jetpack_blog_token' => true,

		'query_parameters'                     => array(
			'context' => false,
			'options' => '(string) Optional. Returns specified options only. Comma-separated list. Example: options=login_url,timezone',
		),

		'response_format'                      => WPCOM_JSON_API_GET_Site_Endpoint::$site_format,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1/sites/en.blog.wordpress.com/',
	)
);

/**
 * GET Site endpoint class.
 */
class WPCOM_JSON_API_GET_Site_Endpoint extends WPCOM_JSON_API_Endpoint {

	/**
	 * Site meta data.
	 *
	 * @var array $site_format
	 */
	public static $site_format = array(
		'ID'                          => '(int) Site ID',
		'name'                        => '(string) Title of site',
		'description'                 => '(string) Tagline or description of site',
		'URL'                         => '(string) Full URL to the site',
		'user_can_manage'             => '(bool) The current user can manage this site', // deprecated.
		'capabilities'                => '(array) Array of capabilities for the current user on this site.',
		'jetpack'                     => '(bool) Whether the site is a Jetpack site or not',
		'jetpack_connection'          => '(bool) Whether the site is connected to WP.com via `jetpack-connection`',
		'is_multisite'                => '(bool) Whether the site is a Multisite site or not. Always true for WP.com sites.',
		'site_owner'                  => '(int) User ID of the site owner',
		'post_count'                  => '(int) The number of posts the site has',
		'subscribers_count'           => '(int) The number of subscribers the site has',
		'lang'                        => '(string) Primary language code of the site',
		'icon'                        => '(array) An array of icon formats for the site',
		'logo'                        => '(array) The site logo, set in the Customizer',
		'visible'                     => '(bool) If this site is visible in the user\'s site list',
		'is_private'                  => '(bool) If the site is a private site or not',
		'is_coming_soon'              => '(bool) If the site is marked as "coming soon" or not',
		'single_user_site'            => '(bool) Whether the site is single user. Only returned for WP.com sites and for Jetpack sites with version 3.4 or higher.',
		'is_vip'                      => '(bool) If the site is a VIP site or not.',
		'is_following'                => '(bool) If the current user is subscribed to this site in the reader',
		'organization_id'             => '(int) P2 Organization identifier.',
		'options'                     => '(array) An array of options/settings for the blog. Only viewable by users with post editing rights to the site. Note: Post formats is deprecated, please see /sites/$id/post-formats/',
		'p2_thumbnail_elements'       => '(array) Details used to render a thumbnail of the site. P2020 themed sites only.',
		'plan'                        => '(array) Details of the current plan for this site.',
		'products'                    => '(array) Details of the current products for this site.',
		'zendesk_site_meta'           => '(array) Site meta data for Zendesk.',
		'updates'                     => '(array) An array of available updates for plugins, themes, wordpress, and languages.',
		'jetpack_modules'             => '(array) A list of active Jetpack modules.',
		'meta'                        => '(object) Meta data',
		'quota'                       => '(array) An array describing how much space a user has left for uploads',
		'launch_status'               => '(string) A string describing the launch status of a site',
		'site_migration'              => '(array) Data about any migration into the site.',
		'is_fse_active'               => '(bool) If the site has Full Site Editing active or not.',
		'is_fse_eligible'             => '(bool) If the site is capable of Full Site Editing or not',
		'is_core_site_editor_enabled' => '(bool) If the site has the core site editor enabled.',
		'is_wpcom_atomic'             => '(bool) If the site is a WP.com Atomic one.',
		'is_wpcom_staging_site'       => '(bool) If the site is a WP.com staging site.',
		'user_interactions'           => '(array) An array of user interactions with a site.',
		'was_ecommerce_trial'         => '(bool) If the site ever used an eCommerce trial.',
	);

	/**
	 * No member fields.
	 *
	 * @var array $no_member_fields
	 */
	protected static $no_member_fields = array(
		'ID',
		'name',
		'description',
		'URL',
		'jetpack',
		'jetpack_connection',
		'post_count',
		'subscribers_count',
		'lang',
		'locale',
		'icon',
		'logo',
		'visible',
		'is_private',
		'is_coming_soon',
		'is_following',
		'organization_id',
		'meta',
		'launch_status',
		'site_migration',
		'is_fse_active',
		'is_fse_eligible',
		'is_core_site_editor_enabled',
		'is_wpcom_atomic',
		'is_wpcom_staging_site',
	);

	/**
	 * Site options.
	 *
	 * @var array $site_options_format
	 */
	protected static $site_options_format = array(
		'timezone',
		'gmt_offset',
		'blog_public',
		'videopress_enabled',
		'upgraded_filetypes_enabled',
		'login_url',
		'admin_url',
		'is_mapped_domain',
		'is_redirect',
		'unmapped_url',
		'featured_images_enabled',
		'theme_slug',
		'header_image',
		'background_color',
		'image_default_link_type',
		'image_thumbnail_width',
		'image_thumbnail_height',
		'image_thumbnail_crop',
		'image_medium_width',
		'image_medium_height',
		'image_large_width',
		'image_large_height',
		'permalink_structure',
		'post_formats',
		'default_post_format',
		'default_category',
		'allowed_file_types',
		'show_on_front',
		/** This filter is documented in modules/likes.php */
		'default_likes_enabled',
		'default_sharing_status',
		'default_comment_status',
		'default_ping_status',
		'software_version',
		'created_at',
		'updated_at',
		'wordads',
		'publicize_permanently_disabled',
		'frame_nonce',
		'jetpack_frame_nonce',
		'page_on_front',
		'page_for_posts',
		'headstart',
		'headstart_is_fresh',
		'ak_vp_bundle_enabled',
		Jetpack_SEO_Utils::FRONT_PAGE_META_OPTION,
		Jetpack_SEO_Titles::TITLE_FORMATS_OPTION,
		'verification_services_codes',
		'podcasting_archive',
		'is_domain_only',
		'is_automated_transfer',
		'is_wpcom_atomic',
		'is_wpcom_store',
		'signup_is_store',
		'has_pending_automated_transfer',
		'woocommerce_is_active',
		'editing_toolkit_is_active',
		'design_type',
		'site_goals',
		'site_segment',
		'site_source_slug',
		'import_engine',
		'is_pending_plan',
		'is_wpforteams_site',
		'p2_hub_blog_id',
		'site_creation_flow',
		'is_cloud_eligible',
		'selected_features',
		'anchor_podcast',
		'was_created_with_blank_canvas_design',
		'videopress_storage_used',
		'is_difm_lite_in_progress',
		'difm_lite_site_options',
		'site_intent',
		'site_vertical_id',
		'blogging_prompts_settings',
		'launchpad_screen',
		'launchpad_checklist_tasks_statuses',
		'wpcom_production_blog_id',
		'wpcom_staging_blog_ids',
		'can_blaze',
	);

	/**
	 * List of DIFM Lite options to be displayed
	 *
	 * @var array $displayed_difm_lite_site_options
	 */
	protected static $displayed_difm_lite_site_options = array(
		'site_category',
		'is_website_content_submitted',
		'selected_page_titles',
	);

	/**
	 * Jetpack response fields.
	 *
	 * @var array $jetpack_response_field_additions
	 */
	protected static $jetpack_response_field_additions = array(
		'subscribers_count',
		'site_migration',
		'site_owner',
		'is_wpcom_staging_site',
		'was_ecommerce_trial',
	);

	/**
	 * Jetpack response field member additions.
	 *
	 * @var array $jetpack_response_field_member_additions
	 */
	protected static $jetpack_response_field_member_additions = array(
		'capabilities',
		'plan',
		'products',
		'zendesk_site_meta',
	);

	/**
	 * Jetpack response option additions.
	 *
	 * @var array $jetpack_response_field_member_additions
	 */
	protected static $jetpack_response_option_additions = array(
		'publicize_permanently_disabled',
		'ak_vp_bundle_enabled',
		'is_automated_transfer',
		'is_wpcom_atomic',
		'is_wpcom_store',
		'woocommerce_is_active',
		'editing_toolkit_is_active',
		'frame_nonce',
		'jetpack_frame_nonce',
		'design_type',
		'wordads',
		// Use the site registered date from wpcom, since it is only available in a multisite context
		// and defaults to `0000-00-00T00:00:00+00:00` from the Jetpack site.
		// See https://github.com/Automattic/jetpack/blob/58638f46094b36f5df9cbc4570006544f0ad300c/sal/class.json-api-site-base.php#L387.
		'created_at',
		'updated_at',
		'is_pending_plan',
		'is_cloud_eligible',
		'videopress_storage_used',
		'blogging_prompts_settings',
		'wpcom_production_blog_id',
		'wpcom_staging_blog_ids',
	);

	/**
	 * Site
	 *
	 * @var $site.
	 */
	private $site;

	/**
	 * Fields to include.
	 *
	 * @var $fields_to_include
	 */
	protected $fields_to_include = '_all';

	/**
	 * Options to include.
	 *
	 * @var $options_to_include
	 */
	protected $options_to_include = '_all';

	/**
	 *
	 * API callback.
	 *
	 * /sites/mine
	 * /sites/%s -> $blog_id\
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		if ( 'mine' === $blog_id ) {
			$api = WPCOM_JSON_API::init();
			if ( ! $api->token_details || empty( $api->token_details['blog_id'] ) ) {
				return new WP_Error( 'authorization_required', 'An active access token must be used to query information about the current blog.', 403 );
			}
			$blog_id = $api->token_details['blog_id'];
		}

		add_filter( 'wpcom_allow_jetpack_blog_token', '__return_true' );
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		$this->filter_fields_and_options();

		$response = $this->build_current_site_response();

		/** This action is documented in json-endpoints/class.wpcom-json-api-site-settings-endpoint.php */
		do_action( 'wpcom_json_api_objects', 'sites' );

		return $response;
	}

	/**
	 * Filter fields and options.
	 */
	public function filter_fields_and_options() {
		$query_args = $this->query_args();

		$this->fields_to_include  = empty( $query_args['fields'] ) ? '_all' : array_map( 'trim', explode( ',', $query_args['fields'] ) );
		$this->options_to_include = empty( $query_args['options'] ) ? '_all' : array_map( 'trim', explode( ',', $query_args['options'] ) );
	}

	/**
	 * Collects the necessary information to return for a site's response.
	 *
	 * @return array
	 */
	public function build_current_site_response() {

		$blog_id = (int) $this->api->get_blog_id_for_output();

		$this->site = $this->get_platform()->get_site( $blog_id );

		/**
		 * Filter the structure of information about the site to return.
		 *
		 * @module json-api
		 *
		 * @since 3.9.3
		 *
		 * @param array $site_format Data structure.
		 */
		$default_fields = array_keys( apply_filters( 'sites_site_format', self::$site_format ) );

		$response_keys = is_array( $this->fields_to_include ) ?
			array_intersect( $default_fields, $this->fields_to_include ) :
			$default_fields;

		$has_blog_access = $this->has_blog_access( $this->api->token_details );
		$has_user_access = $this->has_user_access();

		if ( ! $has_user_access && ! $has_blog_access ) {
			// Public access without user or blog auth, only return `$no_member_fields`.
			$response_keys = array_intersect( $response_keys, self::$no_member_fields );
		} elseif ( $has_user_access && ! current_user_can( 'edit_posts' ) ) {
			// Subscriber level user, don't return site options.
			$response_keys = array_diff( $response_keys, array( 'options' ) );
		}

		return $this->render_response_keys( $response_keys );
	}

	/**
	 * Checks that the current user has access to the current blog.
	 *
	 * @return bool Whether or not the current user can access the current blog.
	 */
	private function has_user_access() {
		return is_user_member_of_blog( get_current_user_id(), get_current_blog_id() );
	}

	/**
	 * Checks if the request has a valid blog token for the current blog.
	 *
	 * @param array $token_details Access token for the api request.
	 * @return bool
	 */
	private function has_blog_access( $token_details ) {
		$token_details = (array) $token_details;
		if ( ! isset( $token_details['access'], $token_details['auth'], $token_details['blog_id'] ) ) {
			return false;
		}

		return 'jetpack' === $token_details['auth'] &&
			'blog' === $token_details['access'] &&
			get_current_blog_id() === $token_details['blog_id'];
	}

	/**
	 * Render response keys.
	 *
	 * @param array $response_keys - the response keys.
	 */
	private function render_response_keys( &$response_keys ) {
		$response = array();

		$is_user_logged_in = is_user_logged_in();

		$this->site->before_render();

		foreach ( $response_keys as $key ) {
			$this->render_response_key( $key, $response, $is_user_logged_in );
		}

		$this->site->after_render( $response );

		return $response;
	}

	/**
	 * Render response key.
	 *
	 * @param string  $key - the key.
	 * @param array   $response - the response.
	 * @param boolean $is_user_logged_in - if the user is logged in.
	 */
	protected function render_response_key( $key, &$response, $is_user_logged_in ) {
		do_action( 'pre_render_site_response_key', $key );

		switch ( $key ) {
			case 'ID':
				$response[ $key ] = $this->site->blog_id;
				break;
			case 'name':
				$response[ $key ] = $this->site->get_name();
				break;
			case 'description':
				$response[ $key ] = $this->site->get_description();
				break;
			case 'URL':
				$response[ $key ] = $this->site->get_url();
				break;
			case 'user_can_manage':
				$response[ $key ] = $this->site->user_can_manage();
				// fall through is intentional.
			case 'is_private':
				$response[ $key ] = $this->site->is_private();
				break;
			case 'is_coming_soon':
				// This option is stored on wp.com for both simple and atomic sites. @see mu-plugins/private-blog.php.
				$response[ $key ] = $this->site->is_coming_soon();

				break;
			case 'launch_status':
				$response[ $key ] = $this->site->get_launch_status();
				break;
			case 'visible':
				$response[ $key ] = $this->site->is_visible();
				break;
			case 'subscribers_count':
				$response[ $key ] = $this->site->get_subscribers_count();
				break;
			case 'post_count':
				if ( $is_user_logged_in ) {
					$response[ $key ] = $this->site->get_post_count();
				}
				break;
			case 'icon':
				$icon = $this->site->get_icon();

				if ( $icon !== null ) {
					$response[ $key ] = $icon;
				}
				break;
			case 'logo':
				$response[ $key ] = $this->site->get_logo();
				break;
			case 'is_following':
				$response[ $key ] = $this->site->is_following();
				break;
			case 'options':
				// small optimisation - don't recalculate.
				$all_options = apply_filters( 'sites_site_options_format', self::$site_options_format );

				$options_response_keys = is_array( $this->options_to_include ) ?
					array_intersect( $all_options, $this->options_to_include ) :
					$all_options;

				$options = $this->render_option_keys( $options_response_keys );

				$this->site->after_render_options( $options );

				$response[ $key ] = (object) $options;
				break;
			case 'meta':
				$this->build_meta_response( $response );
				break;
			case 'lang':
				$response[ $key ] = $is_user_logged_in ? $this->site->get_locale() : false;
				break;
			case 'locale':
				$response[ $key ] = $is_user_logged_in ? $this->site->get_locale() : false;
				break;
			case 'jetpack':
				$response[ $key ] = $this->site->is_jetpack();
				break;
			case 'jetpack_connection':
				$response[ $key ] = $this->site->is_jetpack_connection();
				break;
			case 'single_user_site':
				$response[ $key ] = $this->site->is_single_user_site();
				break;
			case 'is_vip':
				$response[ $key ] = $this->site->is_vip();
				break;
			case 'is_multisite':
				$response[ $key ] = $this->site->is_multisite();
				break;
			case 'site_owner':
				$response[ $key ] = $this->site->get_site_owner();
				break;
			case 'organization_id':
				$response[ $key ] = $this->site->get_p2_organization_id();
				break;

			case 'capabilities':
				$response[ $key ] = $this->site->get_capabilities();
				break;
			case 'jetpack_modules':
				if ( is_user_member_of_blog() ) {
					$response[ $key ] = $this->site->get_jetpack_modules();
				}
				break;
			case 'plan':
				$response[ $key ] = $this->site->get_plan();
				break;
			case 'products':
				$response[ $key ] = $this->site->get_products();
				break;
			case 'zendesk_site_meta':
				// D59613-code only added this function to the wpcom SAL subclasses. Absent any better idea,
				// we'll just omit the key entirely in Jetpack.
				if ( is_callable( array( $this->site, 'get_zendesk_site_meta' ) ) ) {
					$response[ $key ] = $this->site->get_zendesk_site_meta();
				}
				break;
			case 'quota':
				$response[ $key ] = $this->site->get_quota();
				break;
			case 'site_migration':
				$response[ $key ] = $this->site->get_migration_meta();
				break;
			case 'is_fse_active':
				$response[ $key ] = $this->site->is_fse_active();
				break;
			case 'is_fse_eligible':
				$response[ $key ] = $this->site->is_fse_eligible();
				break;
			case 'is_core_site_editor_enabled':
				$response[ $key ] = $this->site->is_core_site_editor_enabled();
				break;
			case 'is_wpcom_atomic':
				$response[ $key ] = $this->site->is_wpcom_atomic();
				break;
			case 'is_wpcom_staging_site':
				$response[ $key ] = $this->site->is_wpcom_staging_site();
				break;
			case 'user_interactions':
				$response[ $key ] = $this->site->get_user_interactions();
				break;
			case 'p2_thumbnail_elements':
				$response[ $key ] = $this->site->get_p2_thumbnail_elements();
				break;
			case 'was_ecommerce_trial':
				$response[ $key ] = $this->site->was_ecommerce_trial();
				break;
		}

		do_action( 'post_render_site_response_key', $key );
	}

	/**
	 * Render option keys.
	 *
	 * @param array $options_response_keys - the response keys.
	 */
	protected function render_option_keys( &$options_response_keys ) {
		$options = array();
		$site    = $this->site;

		$custom_front_page = $site->is_custom_front_page();

		foreach ( $options_response_keys as $key ) {
			switch ( $key ) {
				case 'timezone':
					$options[ $key ] = $site->get_timezone();
					break;
				case 'gmt_offset':
					$options[ $key ] = $site->get_gmt_offset();
					break;
				case 'videopress_enabled':
					$options[ $key ] = $site->has_videopress();
					break;
				case 'upgraded_filetypes_enabled':
					$options[ $key ] = $site->upgraded_filetypes_enabled();
					break;
				case 'login_url':
					$options[ $key ] = $site->get_login_url();
					break;
				case 'admin_url':
					$options[ $key ] = $site->get_admin_url();
					break;
				case 'is_mapped_domain':
					$options[ $key ] = $site->is_mapped_domain();
					break;
				case 'is_redirect':
					$options[ $key ] = $site->is_redirect();
					break;
				case 'unmapped_url':
					$options[ $key ] = $site->get_unmapped_url();
					break;
				case 'featured_images_enabled':
					$options[ $key ] = $site->featured_images_enabled();
					break;
				case 'theme_slug':
					$options[ $key ] = $site->get_theme_slug();
					break;
				case 'header_image':
					$options[ $key ] = $site->get_header_image();
					break;
				case 'background_color':
					$options[ $key ] = $site->get_background_color();
					break;
				case 'image_default_link_type':
					$options[ $key ] = $site->get_image_default_link_type();
					break;
				case 'image_thumbnail_width':
					$options[ $key ] = $site->get_image_thumbnail_width();
					break;
				case 'image_thumbnail_height':
					$options[ $key ] = $site->get_image_thumbnail_height();
					break;
				case 'image_thumbnail_crop':
					$options[ $key ] = $site->get_image_thumbnail_crop();
					break;
				case 'image_medium_width':
					$options[ $key ] = $site->get_image_medium_width();
					break;
				case 'image_medium_height':
					$options[ $key ] = $site->get_image_medium_height();
					break;
				case 'image_large_width':
					$options[ $key ] = $site->get_image_large_width();
					break;
				case 'image_large_height':
					$options[ $key ] = $site->get_image_large_height();
					break;
				case 'permalink_structure':
					$options[ $key ] = $site->get_permalink_structure();
					break;
				case 'post_formats':
					$options[ $key ] = $site->get_post_formats();
					break;
				case 'default_post_format':
					$options[ $key ] = $site->get_default_post_format();
					break;
				case 'default_category':
					$options[ $key ] = $site->get_default_category();
					break;
				case 'allowed_file_types':
					$options[ $key ] = $site->allowed_file_types();
					break;
				case 'show_on_front':
					$options[ $key ] = $site->get_show_on_front();
					break;
				/** This filter is documented in modules/likes.php */
				case 'default_likes_enabled':
					$options[ $key ] = $site->get_default_likes_enabled();
					break;
				case 'default_sharing_status':
					$options[ $key ] = $site->get_default_sharing_status();
					break;
				case 'default_comment_status':
					$options[ $key ] = $site->get_default_comment_status();
					break;
				case 'default_ping_status':
					$options[ $key ] = $site->default_ping_status();
					break;
				case 'software_version':
					$options[ $key ] = $site->get_wordpress_version();
					break;
				case 'created_at':
					$options[ $key ] = $site->get_registered_date();
					break;
				case 'updated_at':
					$options[ $key ] = $site->get_last_update_date();
					break;
				case 'wordads':
					$options[ $key ] = $site->has_wordads();
					break;
				case 'publicize_permanently_disabled':
					$options[ $key ] = $site->is_publicize_permanently_disabled();
					break;
				case 'frame_nonce':
					$options[ $key ] = $site->get_frame_nonce();
					break;
				case 'jetpack_frame_nonce':
					$options[ $key ] = $site->get_jetpack_frame_nonce();
					break;
				case 'page_on_front':
					if ( $custom_front_page ) {
						$options[ $key ] = $site->get_page_on_front();
					}
					break;
				case 'page_for_posts':
					if ( $custom_front_page ) {
						$options[ $key ] = $site->get_page_for_posts();
					}
					break;
				case 'headstart':
					$options[ $key ] = $site->is_headstart();
					break;
				case 'headstart_is_fresh':
					$options[ $key ] = $site->is_headstart_fresh();
					break;
				case 'ak_vp_bundle_enabled':
					$options[ $key ] = $site->get_ak_vp_bundle_enabled();
					break;
				case Jetpack_SEO_Utils::FRONT_PAGE_META_OPTION:
					$options[ $key ] = $site->get_jetpack_seo_front_page_description();
					break;
				case Jetpack_SEO_Titles::TITLE_FORMATS_OPTION:
					$options[ $key ] = $site->get_jetpack_seo_title_formats();
					break;
				case 'verification_services_codes':
					$options[ $key ] = $site->get_verification_services_codes();
					break;
				case 'podcasting_archive':
					$options[ $key ] = $site->get_podcasting_archive();
					break;
				case 'is_domain_only':
					$options[ $key ] = $site->is_domain_only();
					break;
				case 'is_automated_transfer':
					$options[ $key ] = $site->is_automated_transfer();
					break;
				case 'blog_public':
					$options[ $key ] = $site->get_blog_public();
					break;
				case 'is_wpcom_atomic':
					$options[ $key ] = $site->is_wpcom_atomic();
					break;
				case 'is_wpcom_store':
					$options[ $key ] = $site->is_wpcom_store();
					break;
				case 'signup_is_store':
					$signup_is_store = $site->signup_is_store();

					if ( $signup_is_store ) {
						$options[ $key ] = $site->signup_is_store();
					}

					break;
				case 'has_pending_automated_transfer':
					$has_pending_automated_transfer = $site->has_pending_automated_transfer();

					if ( $has_pending_automated_transfer ) {
						$options[ $key ] = true;
					}

					break;
				case 'woocommerce_is_active':
					$options[ $key ] = $site->woocommerce_is_active();
					break;
				case 'editing_toolkit_is_active':
					$options[ $key ] = $site->editing_toolkit_is_active();
					break;
				case 'design_type':
					$options[ $key ] = $site->get_design_type();
					break;
				case 'site_segment':
					$options[ $key ] = $site->get_site_segment();
					break;
				case 'import_engine':
					$options[ $key ] = $site->get_import_engine();
					break;
				case 'is_pending_plan':
					// D40032-code only added this function to the wpcom SAL subclasses. Absent any better idea,
					// we'll just omit the key entirely in Jetpack.
					if ( is_callable( array( $site, 'is_pending_plan' ) ) ) {
						$options[ $key ] = $site->is_pending_plan();
					}
					break;

				case 'is_wpforteams_site':
					$options[ $key ] = $site->is_wpforteams_site();
					break;
				case 'p2_hub_blog_id':
					$options[ $key ] = $site->get_p2_hub_blog_id();
					break;

				case 'site_creation_flow':
					$site_creation_flow = $site->get_site_creation_flow();
					if ( $site_creation_flow ) {
						$options[ $key ] = $site_creation_flow;
					}
					break;
				case 'site_source_slug':
					$site_source_slug = $site->get_site_source_slug();
					if ( $site_source_slug ) {
						$options[ $key ] = $site_source_slug;
					}
					break;
				case 'is_cloud_eligible':
					$options[ $key ] = $site->is_cloud_eligible();
					break;
				case 'selected_features':
					$selected_features = $site->get_selected_features();
					if ( $selected_features ) {
						$options[ $key ] = $selected_features;
					}
					break;
				case 'anchor_podcast':
					$options[ $key ] = $site->get_anchor_podcast();
					break;
				case 'was_created_with_blank_canvas_design':
					$options[ $key ] = $site->was_created_with_blank_canvas_design();
					break;
				case 'videopress_storage_used':
					$options[ $key ] = $this->site->get_videopress_storage_used();
					break;
				case 'is_difm_lite_in_progress':
					$options[ $key ] = $site->is_difm_lite_in_progress();
					break;
				case 'difm_lite_site_options':
					$difm_lite_options          = $site->get_difm_lite_site_options();
					$visible_options            = self::$displayed_difm_lite_site_options;
					$filtered_difm_lite_options = new stdClass();
					if ( $difm_lite_options ) {
						$filtered_difm_lite_options = array_filter(
							$difm_lite_options,
							function ( $key ) use ( $visible_options ) {
								return in_array( $key, $visible_options, true );
							},
							ARRAY_FILTER_USE_KEY
						);
					}
					$options[ $key ] = $filtered_difm_lite_options;
					break;
				case 'site_intent':
					$options[ $key ] = $site->get_site_intent();
					break;
				case 'site_vertical_id':
					$options[ $key ] = $site->get_site_vertical_id();
					break;
				case 'blogging_prompts_settings':
					if ( current_user_can( 'edit_posts' ) ) {
						$options[ $key ] = $site->get_blogging_prompts_settings( get_current_user_id(), $site->blog_id );
					}
					break;
				case 'launchpad_screen':
					$options[ $key ] = $site->get_launchpad_screen();
					break;
				case 'launchpad_checklist_tasks_statuses':
					$options[ $key ] = $site->get_launchpad_checklist_tasks_statuses();
					break;
				case 'wpcom_production_blog_id':
					$options[ $key ] = $site->get_wpcom_production_blog_id();
					break;
				case 'wpcom_staging_blog_ids':
					$options[ $key ] = $site->get_wpcom_staging_blog_ids();
					break;
				case 'can_blaze':
					$options[ $key ] = $site->can_blaze();
					break;
			}
		}

		return $options;
	}

	/**
	 * Build meta response.
	 *
	 * @param array $response - the response.
	 */
	protected function build_meta_response( &$response ) {
		$links = array(
			'self'     => (string) $this->links->get_site_link( $this->site->blog_id ),
			'help'     => (string) $this->links->get_site_link( $this->site->blog_id, 'help' ),
			'posts'    => (string) $this->links->get_site_link( $this->site->blog_id, 'posts/' ),
			'comments' => (string) $this->links->get_site_link( $this->site->blog_id, 'comments/' ),
			'xmlrpc'   => (string) $this->site->get_xmlrpc_url(),
		);

		$icon = $this->site->get_icon();
		if ( ! empty( $icon ) && ! empty( $icon['media_id'] ) ) {
			$links['site_icon'] = (string) $this->links->get_site_link( $this->site->blog_id, 'media/' . $icon['media_id'] );
		}

		$response['meta'] = (object) array(
			'links' => (object) $links,
		);
	}

	/**
	 * Apply any WPCOM-only response components to a Jetpack site response.
	 *
	 * @param array $response - the response.
	 */
	public function decorate_jetpack_response( &$response ) {
		$this->site = $this->get_platform()->get_site( $response->ID );
		switch_to_blog( $this->site->get_id() );

		$wpcom_response = $this->render_response_keys( self::$jetpack_response_field_additions );

		foreach ( $wpcom_response as $key => $value ) {
			$response->{ $key } = $value;
		}

		if ( $this->has_user_access() || $this->has_blog_access( $this->api->token_details ) ) {
			$wpcom_member_response = $this->render_response_keys( self::$jetpack_response_field_member_additions );

			foreach ( $wpcom_member_response as $key => $value ) {
				$response->{ $key } = $value;
			}
		} else {
			// ensure private data is not rendered for non members of the site.
			unset( $response->options );
			unset( $response->is_vip );
			unset( $response->single_user_site );
			unset( $response->is_private );
			unset( $response->is_coming_soon );
			unset( $response->capabilities );
			unset( $response->lang );
			unset( $response->user_can_manage );
			unset( $response->is_multisite );
			unset( $response->site_owner );
			unset( $response->plan );
			unset( $response->products );
			unset( $response->zendesk_site_meta );
		}

		// render additional options.
		if ( $response->options ) {
			$wpcom_options_response = $this->render_option_keys( self::$jetpack_response_option_additions );

			// Remove heic from jetpack (and atomic) sites so that the iOS app know to convert the file format into a JPEG.
			// heic fromat is currently not supported by for uploading.
			// See https://jetpackp2.wordpress.com/2020/08/19/image-uploads-in-the-wp-ios-app-broken
			if ( $this->site->is_jetpack() && isset( $response->options['allowed_file_types'] ) ) {
				$remove_file_types                       = array(
					'heic',
				);
				$response->options['allowed_file_types'] = array_values( array_diff( $response->options['allowed_file_types'], $remove_file_types ) );
			}

			foreach ( $wpcom_options_response as $key => $value ) {
				$response->options[ $key ] = $value;
			}
		}

		restore_current_blog();
		return $response; // possibly no need since it's modified in place.
	}
}

new WPCOM_JSON_API_List_Post_Formats_Endpoint(
	array(
		'description'                          => 'Get a list of post formats supported by a site.',
		'group'                                => '__do_not_document',
		'stat'                                 => 'sites:X:post-formats',

		'method'                               => 'GET',
		'path'                                 => '/sites/%s/post-formats',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'query_parameters'                     => array(
			'context' => false,
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'response_format'                      => array(
			'formats' => '(object) An object of supported post formats, each key a supported format slug mapped to its display string.',
		),
	)
);

/**
 * List Post Formates endpoint class.
 */
class WPCOM_JSON_API_List_Post_Formats_Endpoint extends WPCOM_JSON_API_Endpoint { // phpcs:ignore
	/**
	 *
	 * API callback.
	 *
	 * /sites/%s/post-formats -> $blog_id
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$this->load_theme_functions();
		}

		// Get a list of supported post formats.
		$all_formats = get_post_format_strings();
		$supported   = get_theme_support( 'post-formats' );

		$response          = array(
			'formats' => array(),
		);
		$supported_formats = $response['formats'];

		if ( isset( $supported[0] ) ) {
			foreach ( $supported[0] as $format ) {
				$supported_formats[ $format ] = $all_formats[ $format ];
			}
		}

		$response['formats'] = (object) $supported_formats;

		return $response;
	}
}

new WPCOM_JSON_API_List_Page_Templates_Endpoint(
	array(
		'description'      => 'Get a list of page templates supported by a site.',
		'group'            => 'sites',
		'stat'             => 'sites:X:post-templates',

		'method'           => 'GET',
		'path'             => '/sites/%s/page-templates',
		'path_labels'      => array(
			'$site' => '(int|string) Site ID or domain',
		),
		'query_parameters' => array(
			'context' => false,
		),
		'response_format'  => array(
			'templates' => '(array) A list of supported page templates. Contains label and file.',
		),
		'example_request'  => 'https://public-api.wordpress.com/rest/v1.1/sites/33534099/page-templates',
	)
);

/**
 * List page templates endpoint class.
 */
class WPCOM_JSON_API_List_Page_Templates_Endpoint extends WPCOM_JSON_API_Endpoint { // phpcs:ignore
	/**
	 *
	 * API callback.
	 * /sites/%s/page-templates -> $blog_id
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		$blog_id = $this->api->switch_to_blog_and_validate_user( $this->api->get_blog_id( $blog_id ) );
		if ( is_wp_error( $blog_id ) ) {
			return $blog_id;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$this->load_theme_functions();
		}

		$response       = array();
		$page_templates = array();

		$templates = get_page_templates();
		ksort( $templates );

		foreach ( array_keys( $templates ) as $label ) {
			$page_templates[] = array(
				'label' => $label,
				'file'  => $templates[ $label ],
			);
		}

		$response['templates'] = $page_templates;

		return $response;
	}
}
