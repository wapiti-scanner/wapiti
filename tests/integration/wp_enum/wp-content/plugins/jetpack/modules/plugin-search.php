<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Adds the PSH functionality to Jetpack.
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Tracking;

/**
 * Disable direct access and execution.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if (
	is_admin() &&
	Jetpack::is_connection_ready() &&
	/** This filter is documented in _inc/lib/admin-pages/class.jetpack-react-page.php */
	apply_filters( 'jetpack_show_promotions', true ) &&
	// Disable feature hints when plugins cannot be installed.
	! Constants::is_true( 'DISALLOW_FILE_MODS' ) &&
	jetpack_is_psh_active()
) {
	Jetpack_Plugin_Search::init();
}

// Register endpoints when WP REST API is initialized.
add_action( 'rest_api_init', array( 'Jetpack_Plugin_Search', 'register_endpoints' ) );

/**
 * Class that includes cards in the plugin search results when users enter terms that match some Jetpack feature.
 * Card can be dismissed and includes a title, description, button to enable the feature and a link for more information.
 *
 * @since 7.1.0
 */
class Jetpack_Plugin_Search {

	/**
	 * PSH slug name.
	 *
	 * @var string
	 */
	public static $slug = 'jetpack-plugin-search';

	/**
	 * Singleton constructor.
	 *
	 * @return Jetpack_Plugin_Search
	 */
	public static function init() {
		static $instance = null;

		if ( ! $instance ) {
			$instance = new Jetpack_Plugin_Search();
		}

		return $instance;
	}

	/**
	 * Jetpack_Plugin_Search constructor.
	 */
	public function __construct() {
		add_action( 'current_screen', array( $this, 'start' ) );
	}

	/**
	 * Add actions and filters only if this is the plugin installation screen and it's the first page.
	 *
	 * @param object $screen WP SCreen object.
	 *
	 * @since 7.1.0
	 */
	public function start( $screen ) {
		if ( 'plugin-install' === $screen->base && ( ! isset( $_GET['paged'] ) || 1 === intval( $_GET['paged'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			add_action( 'admin_enqueue_scripts', array( $this, 'load_plugins_search_script' ) );
			add_filter( 'plugins_api_result', array( $this, 'inject_jetpack_module_suggestion' ), 10, 3 );
			add_filter( 'self_admin_url', array( $this, 'plugin_details' ) );
			add_filter( 'plugin_install_action_links', array( $this, 'insert_module_related_links' ), 10, 2 );
		}
	}

	/**
	 * Modify URL used to fetch to plugin information so it pulls Jetpack plugin page.
	 *
	 * @param string $url URL to load in dialog pulling the plugin page from wporg.
	 *
	 * @since 7.1.0
	 *
	 * @return string The URL with 'jetpack' instead of 'jetpack-plugin-search'.
	 */
	public function plugin_details( $url ) {
		return false !== stripos( $url, 'tab=plugin-information&amp;plugin=' . self::$slug )
			? 'plugin-install.php?tab=plugin-information&amp;plugin=jetpack&amp;TB_iframe=true&amp;width=600&amp;height=550'
			: $url;
	}

	/**
	 * Register REST API endpoints.
	 *
	 * @since 7.1.0
	 */
	public static function register_endpoints() {
		register_rest_route(
			'jetpack/v4',
			'/hints',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => __CLASS__ . '::dismiss',
				'permission_callback' => __CLASS__ . '::can_request',
				'args'                => array(
					'hint' => array(
						'default'           => '',
						'type'              => 'string',
						'required'          => true,
						'validate_callback' => __CLASS__ . '::is_hint_id',
					),
				),
			)
		);
	}

	/**
	 * A WordPress REST API permission callback method that accepts a request object and
	 * decides if the current user has enough privileges to act.
	 *
	 * @since 7.1.0
	 *
	 * @return bool does a current user have enough privileges.
	 */
	public static function can_request() {
		return current_user_can( 'jetpack_admin_page' );
	}

	/**
	 * Validates that the ID of the hint to dismiss is a string.
	 *
	 * @since 7.1.0
	 *
	 * @param string|bool     $value Value to check.
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @param string          $param Name of the parameter passed to endpoint holding $value.
	 *
	 * @return bool|WP_Error
	 */
	public static function is_hint_id( $value, $request, $param ) {
		return in_array( $value, Jetpack::get_available_modules(), true )
			? true
			/* translators: %s is the name of a parameter passed to an endpoint. */
			: new WP_Error( 'invalid_param', sprintf( esc_html__( '%s must be an alphanumeric string.', 'jetpack' ), $param ) );
	}

	/**
	 * A WordPress REST API callback method that accepts a request object and decides what to do with it.
	 *
	 * @param WP_REST_Request $request {
	 *     Array of parameters received by request.
	 *
	 *     @type string $hint Slug of card to dismiss.
	 * }
	 *
	 * @since 7.1.0
	 *
	 * @return bool|array|WP_Error a resulting value or object, or an error.
	 */
	public static function dismiss( WP_REST_Request $request ) {
		return self::add_to_dismissed_hints( $request['hint'] )
			? rest_ensure_response( array( 'code' => 'success' ) )
			: new WP_Error( 'not_dismissed', esc_html__( 'The card could not be dismissed', 'jetpack' ), array( 'status' => 400 ) );
	}

	/**
	 * Returns a list of previously dismissed hints.
	 *
	 * @since 7.1.0
	 *
	 * @return array List of dismissed hints.
	 */
	protected static function get_dismissed_hints() {
		$dismissed_hints = Jetpack_Options::get_option( 'dismissed_hints' );
		return isset( $dismissed_hints ) && is_array( $dismissed_hints )
			? $dismissed_hints
			: array();
	}

	/**
	 * Save the hint in the list of dismissed hints.
	 *
	 * @since 7.1.0
	 *
	 * @param string $hint The hint id, which is a Jetpack module slug.
	 *
	 * @return bool Whether the card was added to the list and hence dismissed.
	 */
	protected static function add_to_dismissed_hints( $hint ) {
		return Jetpack_Options::update_option( 'dismissed_hints', array_merge( self::get_dismissed_hints(), array( $hint ) ) );
	}

	/**
	 * Checks that the module slug passed should be displayed.
	 *
	 * A feature hint will be displayed if it has not been dismissed before or if 2 or fewer other hints have been dismissed.
	 *
	 * @since 7.2.1
	 *
	 * @param string $hint The hint id, which is a Jetpack module slug.
	 *
	 * @return bool True if $hint should be displayed.
	 */
	protected function should_display_hint( $hint ) {
		$dismissed_hints = $this->get_dismissed_hints();
		// If more than 2 hints have been dismissed, then show no more.
		if ( 2 < count( $dismissed_hints ) ) {
			return false;
		}

		$plan = Jetpack_Plan::get();
		if ( isset( $plan['class'] ) && ( 'free' === $plan['class'] || 'personal' === $plan['class'] ) && 'vaultpress' === $hint ) {
			return false;
		}

		return ! in_array( $hint, $dismissed_hints, true );
	}

	/**
	 * Load the search scripts and CSS for PSH.
	 */
	public function load_plugins_search_script() {
		wp_enqueue_script( self::$slug, plugins_url( 'modules/plugin-search/plugin-search.js', JETPACK__PLUGIN_FILE ), array( 'jquery' ), JETPACK__VERSION, true );
		wp_localize_script(
			self::$slug,
			'jetpackPluginSearch',
			array(
				'nonce'          => wp_create_nonce( 'wp_rest' ),
				'base_rest_url'  => rest_url( '/jetpack/v4' ),
				'poweredBy'      => esc_html__( 'by Jetpack (installed)', 'jetpack' ),
				'manageSettings' => esc_html__( 'Configure', 'jetpack' ),
				'activateModule' => esc_html__( 'Activate Module', 'jetpack' ),
				'getStarted'     => esc_html__( 'Get started', 'jetpack' ),
				'activated'      => esc_html__( 'Activated', 'jetpack' ),
				'activating'     => esc_html__( 'Activating', 'jetpack' ),
				'logo'           => 'https://ps.w.org/jetpack/assets/icon.svg?rev=1791404',
				'legend'         => esc_html__(
					'This suggestion was made by Jetpack, the security and performance plugin already installed on your site.',
					'jetpack'
				),
				'supportText'    => esc_html__(
					'Learn more about these suggestions.',
					'jetpack'
				),
				'supportLink'    => Redirect::get_url( 'plugin-hint-learn-support' ),
				'hideText'       => esc_html__( 'Hide this suggestion', 'jetpack' ),
			)
		);

		wp_enqueue_style( self::$slug, plugins_url( 'modules/plugin-search/plugin-search.css', JETPACK__PLUGIN_FILE ), array(), JETPACK__VERSION );
	}

	/**
	 * Get the plugin repo's data for Jetpack to populate the fields with.
	 *
	 * @return array|mixed|object|WP_Error
	 */
	public static function get_jetpack_plugin_data() {
		$data = get_transient( 'jetpack_plugin_data' );

		if ( false === $data || is_wp_error( $data ) ) {
			include_once ABSPATH . 'wp-admin/includes/plugin-install.php';
			$data = plugins_api(
				'plugin_information',
				array(
					'slug'   => 'jetpack',
					'is_ssl' => is_ssl(),
					'fields' => array(
						'banners'         => true,
						'reviews'         => true,
						'active_installs' => true,
						'versions'        => false,
						'sections'        => false,
					),
				)
			);
			set_transient( 'jetpack_plugin_data', $data, DAY_IN_SECONDS );
		}

		return $data;
	}

	/**
	 * Create a list with additional features for those we don't have a module, like Akismet.
	 *
	 * @since 7.1.0
	 *
	 * @return array List of features.
	 */
	public function get_extra_features() {
		return array(
			'akismet' => array(
				'name'                => 'Akismet',
				'search_terms'        => 'akismet, anti-spam, antispam, comments, spam, spam protection, form spam, captcha, no captcha, nocaptcha, recaptcha, phising, google',
				'short_description'   => esc_html__( 'Keep your visitors and search engines happy by stopping comment and contact form spam with Akismet.', 'jetpack' ),
				'requires_connection' => true,
				'module'              => 'akismet',
				'sort'                => '16',
				'learn_more_button'   => Redirect::get_url( 'plugin-hint-upgrade-akismet' ),
				'configure_url'       => admin_url( 'admin.php?page=akismet-key-config' ),
			),
		);
	}

	/**
	 * Intercept the plugins API response and add in an appropriate card for Jetpack
	 *
	 * @param object $result Plugin search results.
	 * @param string $action unused.
	 * @param object $args Search args.
	 */
	public function inject_jetpack_module_suggestion( $result, $action, $args ) {
		// Looks like a search query; it's matching time.
		if ( ! empty( $args->search ) ) {
			require_once JETPACK__PLUGIN_DIR . 'class.jetpack-admin.php';
			$tracking             = new Tracking();
			$jetpack_modules_list = array_intersect_key(
				array_merge( $this->get_extra_features(), Jetpack_Admin::init()->get_modules() ),
				array_flip(
					array(
						'contact-form',
						'lazy-images',
						'monitor',
						'photon',
						'photon-cdn',
						'protect',
						'publicize',
						'related-posts',
						'sharedaddy',
						'akismet',
						'vaultpress',
						'videopress',
						'search',
					)
				)
			);
			uasort( $jetpack_modules_list, array( $this, 'by_sorting_option' ) );

			// Record event when user searches for a term over 3 chars (less than 3 is not very useful).
			if ( strlen( $args->search ) >= 3 ) {
				$tracking->record_user_event( 'wpa_plugin_search_term', array( 'search_term' => $args->search ) );
			}

			// Lowercase, trim, remove punctuation/special chars, decode url, remove 'jetpack'.
			$normalized_term = $this->sanitize_search_term( $args->search );

			$matching_module = null;

			// Try to match a passed search term with module's search terms.
			foreach ( $jetpack_modules_list as $module_slug => $module_opts ) {
				/*
				* Does the site's current plan support the feature?
				* We don't use Jetpack_Plan::supports() here because
				* that check always returns Akismet as supported,
				* since Akismet has a free version.
				*/
				$current_plan         = Jetpack_Plan::get();
				$is_supported_by_plan = in_array( $module_slug, $current_plan['supports'], true );

				if (
					false !== stripos( $module_opts['search_terms'] . ', ' . $module_opts['name'], $normalized_term )
					&& $is_supported_by_plan
				) {
					$matching_module = $module_slug;
					break;
				}
			}

			if ( isset( $matching_module ) && $this->should_display_hint( $matching_module ) ) {
				// Record event when a matching feature is found.
				$tracking->record_user_event( 'wpa_plugin_search_match_found', array( 'feature' => $matching_module ) );

				$inject    = (array) self::get_jetpack_plugin_data();
				$image_url = plugins_url( 'modules/plugin-search/psh', JETPACK__PLUGIN_FILE );
				$overrides = array(
					'plugin-search'       => true, // Helps to determine if that an injected card.
					'name'                => sprintf(       // Supplement name/description so that they clearly indicate this was added.
						/* translators: Jetpack module name */
						esc_html_x( 'Jetpack: %s', 'Jetpack: Module Name', 'jetpack' ),
						$jetpack_modules_list[ $matching_module ]['name']
					),
					'short_description'   => $jetpack_modules_list[ $matching_module ]['short_description'],
					'requires_connection' => (bool) $jetpack_modules_list[ $matching_module ]['requires_connection'],
					'slug'                => self::$slug,
					'version'             => JETPACK__VERSION,
					'icons'               => array(
						'1x'  => "$image_url-128.png",
						'2x'  => "$image_url-256.png",
						'svg' => "$image_url.svg",
					),
				);

				// Splice in the base module data.
				$inject = array_merge( $inject, $jetpack_modules_list[ $matching_module ], $overrides );

				// Add it to the top of the list.
				$result->plugins = array_filter( $result->plugins, array( $this, 'filter_cards' ) );
				array_unshift( $result->plugins, $inject );
			}
		}
		return $result;
	}

	/**
	 * Remove cards for Jetpack plugins since we don't want duplicates.
	 *
	 * @since 7.1.0
	 * @since 7.2.0 Only remove Jetpack.
	 * @since 7.4.0 Simplify for WordPress 5.1+.
	 *
	 * @param array|object $plugin WordPress search result card.
	 *
	 * @return bool
	 */
	public function filter_cards( $plugin ) {
		/*
		 * $plugin is normally an array.
		 * However, since the response data can be filtered,
		 * we cannot fully trust its format.
		 * Let's handle both arrays and objects, and bail if it's neither.
		 */
		if ( is_array( $plugin ) && ! empty( $plugin['slug'] ) ) {
			$slug = $plugin['slug'];
		} elseif ( is_object( $plugin ) && ! empty( $plugin->slug ) ) {
			$slug = $plugin->slug;
		} else {
			return false;
		}

		return ! in_array( $slug, array( 'jetpack' ), true );
	}

	/**
	 * Take a raw search query and return something a bit more standardized and
	 * easy to work with.
	 *
	 * @param  string $term The raw search term.
	 * @return string A simplified/sanitized version.
	 */
	private function sanitize_search_term( $term ) {
		$term = strtolower( urldecode( $term ) );

		// remove non-alpha/space chars.
		$term = preg_replace( '/[^a-z ]/', '', $term );

		// remove strings that don't help matches.
		$term = trim( str_replace( array( 'jetpack', 'jp', 'free', 'wordpress' ), '', $term ) );

		return $term;
	}

	/**
	 * Callback function to sort the array of modules by the sort option.
	 *
	 * @param array $m1 Array 1 to sort.
	 * @param array $m2 Array 2 to sort.
	 */
	private function by_sorting_option( $m1, $m2 ) {
		return $m1['sort'] - $m2['sort'];
	}

	/**
	 * Modify the URL to the feature settings, for example Publicize.
	 * Sharing is included here because while we still have a page in WP Admin,
	 * we prefer to send users to Calypso.
	 *
	 * @param string $feature Feature.
	 * @param string $configure_url URL to configure feature.
	 *
	 * @return string
	 * @since 7.1.0
	 */
	private function get_configure_url( $feature, $configure_url ) {
		switch ( $feature ) {
			case 'sharing':
			case 'publicize':
				$configure_url = Redirect::get_url( 'calypso-marketing-connections' );
				break;
			case 'seo-tools':
				$configure_url = Redirect::get_url(
					'calypso-marketing-traffic',
					array(
						'anchor' => 'seo',
					)
				);
				break;
			case 'google-analytics':
				$configure_url = Redirect::get_url(
					'calypso-marketing-traffic',
					array(
						'anchor' => 'analytics',
					)
				);
				break;
			case 'wordads':
				$configure_url = Redirect::get_url( 'wpcom-ads-settings' );
				break;
		}
		return $configure_url;
	}

	/**
	 * Put some more appropriate links on our custom result cards.
	 *
	 * @param array $links Related links.
	 * @param array $plugin Plugin result information.
	 */
	public function insert_module_related_links( $links, $plugin ) {
		if ( self::$slug !== $plugin['slug'] ) {
			return $links;
		}

		// By the time this filter is applied, self_admin_url was already applied and we don't need it anymore.
		remove_filter( 'self_admin_url', array( $this, 'plugin_details' ) );

		$links = array();

		if ( 'akismet' === $plugin['module'] || 'vaultpress' === $plugin['module'] ) {
			$links['jp_get_started'] = '<a
				id="plugin-select-settings"
				class="jetpack-plugin-search__primary jetpack-plugin-search__get-started button"
				href="' . esc_url( Redirect::get_url( 'plugin-hint-learn-' . $plugin['module'] ) ) . '"
				data-module="' . esc_attr( $plugin['module'] ) . '"
				data-track="get_started"
				>' . esc_html__( 'Get started', 'jetpack' ) . '</a>';
			// Jetpack installed, active, feature not enabled; prompt to enable.
		} elseif (
			current_user_can( 'jetpack_activate_modules' ) &&
			! Jetpack::is_module_active( $plugin['module'] ) &&
			Jetpack_Plan::supports( $plugin['module'] )
		) {
			$links[] = '<button
					id="plugin-select-activate"
					class="jetpack-plugin-search__primary button"
					data-module="' . esc_attr( $plugin['module'] ) . '"
					data-configure-url="' . esc_url( $this->get_configure_url( $plugin['module'], $plugin['configure_url'] ) ) . '"
					> ' . esc_html__( 'Enable', 'jetpack' ) . '</button>';

			// Jetpack installed, active, feature enabled; link to settings.
		} elseif (
			! empty( $plugin['configure_url'] ) &&
			current_user_can( 'jetpack_configure_modules' ) &&
			Jetpack::is_module_active( $plugin['module'] ) &&
			/** This filter is documented in class.jetpack-admin.php */
			apply_filters( 'jetpack_module_configurable_' . $plugin['module'], false )
		) {
			$links[] = '<a
				id="plugin-select-settings"
				class="jetpack-plugin-search__primary button jetpack-plugin-search__configure"
				href="' . esc_url( $this->get_configure_url( $plugin['module'], $plugin['configure_url'] ) ) . '"
				data-module="' . esc_attr( $plugin['module'] ) . '"
				data-track="configure"
				>' . esc_html__( 'Configure', 'jetpack' ) . '</a>';
			// Module is active, doesn't have options to configure.
		} elseif ( Jetpack::is_module_active( $plugin['module'] ) ) {
			$links['jp_get_started'] = '<a
				id="plugin-select-settings"
				class="jetpack-plugin-search__primary jetpack-plugin-search__get-started button"
				href="' . esc_url( Redirect::get_url( 'plugin-hint-learn-' . $plugin['module'] ) ) . '"
				data-module="' . esc_attr( $plugin['module'] ) . '"
				data-track="get_started"
				>' . esc_html__( 'Get started', 'jetpack' ) . '</a>';
		}

		// Add link pointing to a relevant doc page in jetpack.com only if the Get started button isn't displayed.
		if ( ! empty( $plugin['learn_more_button'] ) && ! isset( $links['jp_get_started'] ) ) {
			$links[] = '<a
				class="jetpack-plugin-search__learn-more"
				href="' . esc_url( $plugin['learn_more_button'] ) . '"
				target="_blank"
				data-module="' . esc_attr( $plugin['module'] ) . '"
				data-track="learn_more"
				>' . esc_html__( 'Learn more', 'jetpack' ) . '</a>';
		}

		// Dismiss link.
		$links[] = '<a
			class="jetpack-plugin-search__dismiss"
			data-module="' . esc_attr( $plugin['module'] ) . '"
			>' . esc_html__( 'Hide this suggestion', 'jetpack' ) . '</a>';

		return $links;
	}

}

/**
 * Master control that checks if Plugin search hints is active.
 *
 * @since 7.1.1
 *
 * @return bool True if PSH is active.
 */
function jetpack_is_psh_active() {
	/**
	 * Disables the Plugin Search Hints feature found when searching the plugins page.
	 *
	 * @since 8.7.0
	 *
	 * @param bool Set false to disable the feature.
	 */
	return apply_filters( 'jetpack_psh_active', true );
}
