<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

new WPCOM_JSON_API_GET_Site_V1_2_Endpoint(
	array(
		'description'                          => 'Get information about a site.',
		'group'                                => 'sites',
		'stat'                                 => 'sites:X',
		'allowed_if_flagged'                   => true,
		'method'                               => 'GET',
		'min_version'                          => '1.2',
		'path'                                 => '/sites/%s',
		'path_labels'                          => array(
			'$site' => '(int|string) Site ID or domain',
		),

		'allow_fallback_to_jetpack_blog_token' => true,

		'query_parameters'                     => array(
			'context' => false,
			'filters' => '(string) Optional. Returns sites that satisfy the given filters only. Example: filters=jetpack,atomic,wpcom',
		),

		'response_format'                      => WPCOM_JSON_API_GET_Site_V1_2_Endpoint::$site_format,

		'example_request'                      => 'https://public-api.wordpress.com/rest/v1.2/sites/en.blog.wordpress.com/',
	)
);

/**
 * GET Site v1_2 endpoint.
 */
class WPCOM_JSON_API_GET_Site_V1_2_Endpoint extends WPCOM_JSON_API_GET_Site_Endpoint {

	/**
	 * Site format array.
	 *
	 * @var array $site_format
	 */
	public static $site_format = array(
		'ID'                          => '(int) Site ID',
		'name'                        => '(string) Title of site',
		'description'                 => '(string) Tagline or description of site',
		'URL'                         => '(string) Full URL to the site',
		'capabilities'                => '(array) Array of capabilities for the current user on this site.',
		'jetpack'                     => '(bool) Whether the site is a Jetpack site or not',
		'jetpack_connection'          => '(bool) Whether the site is connected to WP.com via `jetpack-connection`',
		'is_multisite'                => '(bool) Whether the site is a Multisite site or not. Always true for WP.com sites.',
		'site_owner'                  => '(int) User ID of the site owner',
		'post_count'                  => '(int) The number of posts the site has',
		'subscribers_count'           => '(int) The number of subscribers the site has',
		'locale'                      => '(string) Primary locale code of the site',
		'icon'                        => '(array) An array of icon formats for the site',
		'logo'                        => '(array) The site logo, set in the Customizer',
		'visible'                     => '(bool) If this site is visible in the user\'s site list',
		'is_private'                  => '(bool) If the site is a private site or not',
		'is_coming_soon'              => '(bool) If the site is a "coming soon" site or not',
		'single_user_site'            => '(bool) Whether the site is single user. Only returned for WP.com sites and for Jetpack sites with version 3.4 or higher.',
		'is_vip'                      => '(bool) If the site is a VIP site or not.',
		'is_following'                => '(bool) If the current user is subscribed to this site in the reader',
		'organization_id'             => '(int) P2 Organization identifier.',
		'options'                     => '(array) An array of options/settings for the blog. Only viewable by users with post editing rights to the site. Note: Post formats is deprecated, please see /sites/$id/post-formats/',
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
		'was_ecommerce_trial'         => '(bool) If the site ever used an eCommerce trial.',
	);

	/**
	 *
	 * API callback.
	 *
	 * @param string $path - the path.
	 * @param int    $blog_id - the blog ID.
	 */
	public function callback( $path = '', $blog_id = 0 ) {
		add_filter( 'sites_site_format', array( $this, 'site_format' ) );

		// Site filtering is a WPCOM concept, once a request gets anywhere else it should just be returned
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// Apply filter here, return same error as switch_to_blog_and_validate_user if blog is not found.
			require_lib( 'site-filter' );
			$filters = Site_Filter::process_query_arg( $this->query_args() );
			if ( is_wp_error( $filters ) ) {
				return $filters;
			}
			if ( ! empty( $filters ) && ! Site_Filter::filter_blog( $this->api->get_blog_id( $blog_id ), $filters ) ) {
				return new WP_Error( 'unknown_blog', 'Unknown blog', 404 );
			}
		}

		return parent::callback( $path, $blog_id );
	}

	/**
	 * Site format.
	 *
	 * @param string $format - the format.
	 */
	public function site_format( $format ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return self::$site_format;
	}
}
