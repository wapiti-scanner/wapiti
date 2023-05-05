<?php
/**
 * File: CacheGroups_Plugin_Admin.php
 *
 * @since 2.1.0
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: CacheGroups_Plugin_Admin
 *
 * @since 2.1.0
 */
class CacheGroups_Plugin_Admin extends Base_Page_Settings {
	/**
	 * Current page.
	 *
	 * @var string
	 */
	protected $_page = 'w3tc_cachegroups'; // phpcs:ignore PSR2.Classes.PropertyDeclaration.Underscore

	/**
	 * Cache groups settings view.
	 *
	 * @since 2.1.0
	 */
	public function view() {
		$c = Dispatcher::config();

		// Header.
		require W3TC_INC_DIR . '/options/common/header.php';

		// User agent groups.
		$useragent_groups = array(
			'value'       => $c->get_array( 'mobile.rgroups' ),
			'disabled'    => $c->is_sealed( 'mobile.rgroups' ),
			'description' =>
				'<li>' .
				__(
					'Enabling even a single user agent group will set a cookie called "w3tc_referrer." It is used to ensure a consistent user experience across page views. Make sure any reverse proxy servers etc respect this cookie for proper operation.',
					'w3-total-cache'
				) .
				'</li>' .
				'<li>' .
				__(
					'Per the above, make sure that visitors are notified about the cookie as per any regulations in your market.',
					'w3-total-cache'
				) .
				'</li>',
		);

		$useragent_groups = apply_filters( 'w3tc_ui_config_item_mobile.rgroups', $useragent_groups ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores
		$w3_mobile        = Dispatcher::component( 'Mobile_UserAgent' );
		$useragent_themes = $w3_mobile->get_themes();

		// Referrer groups.
		$referrer_groups = $this->_config->get_array( 'referrer.rgroups' );
		$w3_referrer     = Dispatcher::component( 'Mobile_Referrer' );
		$referrer_themes = $w3_referrer->get_themes();

		// Cookie groups.
		$cookie_groups = array(
			'value'    => $c->get_array( 'pgcache.cookiegroups.groups' ),
			'disabled' => $c->is_sealed( 'pgcache.cookiegroups.groups' ),
		);
		$cookie_groups = apply_filters( 'w3tc_ui_config_item_pgcache.cookiegroups.groups', $cookie_groups ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores

		// Load view.
		require W3TC_DIR . '/CacheGroups_Plugin_Admin_View.php';

		// Footer.
		require W3TC_INC_DIR . '/options/common/footer.php';
	}

	/**
	 * Save settings.
	 *
	 * @since 2.1.0
	 *
	 * @static
	 *
	 * @param array $config Config.
	 */
	public static function w3tc_config_ui_save_w3tc_cachegroups( $config ) {
		// * User agent groups.
		$useragent_groups     = Util_Request::get_array( 'mobile_groups' );
		$mobile_groups        = array();
		$cached_mobile_groups = array();

		foreach ( $useragent_groups as $group => $group_config ) {
			$group = strtolower( $group );
			$group = preg_replace( '~[^0-9a-z_]+~', '_', $group );
			$group = trim( $group, '_' );

			if ( $group ) {
				$theme    = isset( $group_config['theme'] ) ? trim( $group_config['theme'] ) : 'default';
				$enabled  = isset( $group_config['enabled'] ) ? (bool) $group_config['enabled'] : true;
				$redirect = isset( $group_config['redirect'] ) ? trim( $group_config['redirect'] ) : '';
				$agents   = isset( $group_config['agents'] ) ? explode( "\r\n", trim( $group_config['agents'] ) ) : array();

				$mobile_groups[ $group ] = array(
					'theme'    => $theme,
					'enabled'  => $enabled,
					'redirect' => $redirect,
					'agents'   => $agents,
				);

				$cached_mobile_groups[ $group ] = $agents;
			}
		}

		// Allow plugins modify WPSC mobile groups.
		$cached_mobile_groups = apply_filters( 'cached_mobile_groups', $cached_mobile_groups );

		// Merge existent and delete removed groups.
		foreach ( $mobile_groups as $group => $group_config ) {
			if ( isset( $cached_mobile_groups[ $group ] ) ) {
				$mobile_groups[ $group ]['agents'] = (array) $cached_mobile_groups[ $group ];
			} else {
				unset( $mobile_groups[ $group ] );
			}
		}

		// Add new groups.
		foreach ( $cached_mobile_groups as $group => $agents ) {
			if ( ! isset( $mobile_groups[ $group ] ) ) {
				$mobile_groups[ $group ] = array(
					'theme'    => '',
					'enabled'  => true,
					'redirect' => '',
					'agents'   => $agents,
				);
			}
		}

		// Allow plugins modify W3TC mobile groups.
		$mobile_groups = apply_filters( 'w3tc_mobile_groups', $mobile_groups );

		// Sanitize mobile groups.
		foreach ( $mobile_groups as $group => $group_config ) {
			$mobile_groups[ $group ] = array_merge(
				array(
					'theme'    => '',
					'enabled'  => true,
					'redirect' => '',
					'agents'   => array(),
				),
				$group_config
			);

			$mobile_groups[ $group ]['agents'] = array_unique( $mobile_groups[ $group ]['agents'] );
			$mobile_groups[ $group ]['agents'] = array_map( 'strtolower', $mobile_groups[ $group ]['agents'] );

			sort( $mobile_groups[ $group ]['agents'] );
		}

		$enable_mobile = false;

		foreach ( $mobile_groups as $group_config ) {
			if ( $group_config['enabled'] ) {
				$enable_mobile = true;
				break;
			}
		}

		$config->set( 'mobile.enabled', $enable_mobile );
		$config->set( 'mobile.rgroups', $mobile_groups );

		// * Referrer groups.
		$ref_groups = Util_Request::get_array( 'referrer_groups' );

		$referrer_groups = array();

		foreach ( $ref_groups as $group => $group_config ) {
			$group = strtolower( $group );
			$group = preg_replace( '~[^0-9a-z_]+~', '_', $group );
			$group = trim( $group, '_' );

			if ( $group ) {
				$theme     = isset( $group_config['theme'] ) ? trim( $group_config['theme'] ) : 'default';
				$enabled   = isset( $group_config['enabled'] ) ? (bool) $group_config['enabled'] : true;
				$redirect  = isset( $group_config['redirect'] ) ? trim( $group_config['redirect'] ) : '';
				$referrers = isset( $group_config['referrers'] ) ? explode( "\r\n", trim( $group_config['referrers'] ) ) : array();

				$referrer_groups[ $group ] = array(
					'theme'     => $theme,
					'enabled'   => $enabled,
					'redirect'  => $redirect,
					'referrers' => $referrers,
				);
			}
		}

		// Allow plugins modify W3TC referrer groups.
		$referrer_groups = apply_filters( 'w3tc_referrer_groups', $referrer_groups );

		// Sanitize mobile groups.
		foreach ( $referrer_groups as $group => $group_config ) {
			$referrer_groups[ $group ] = array_merge(
				array(
					'theme'     => '',
					'enabled'   => true,
					'redirect'  => '',
					'referrers' => array(),
				),
				$group_config
			);

			$referrer_groups[ $group ]['referrers'] = array_unique( $referrer_groups[ $group ]['referrers'] );
			$referrer_groups[ $group ]['referrers'] = array_map( 'strtolower', $referrer_groups[ $group ]['referrers'] );

			sort( $referrer_groups[ $group ]['referrers'] );
		}

		$enable_referrer = false;

		foreach ( $referrer_groups as $group_config ) {
			if ( $group_config['enabled'] ) {
				$enable_referrer = true;
				break;
			}
		}

		$config->set( 'referrer.enabled', $enable_referrer );
		$config->set( 'referrer.rgroups', $referrer_groups );

		// * Cookie groups.
		$mobile_groups        = array();
		$cached_mobile_groups = array();
		$cookie_groups        = Util_Request::get_array( 'cookiegroups' );

		foreach ( $cookie_groups as $group => $group_config ) {
			$group = strtolower( $group );
			$group = preg_replace( '~[^0-9a-z_]+~', '_', $group );
			$group = trim( $group, '_' );

			if ( $group ) {
				$enabled = isset( $group_config['enabled'] ) ?
					(bool) $group_config['enabled'] : false;
				$cache   = isset( $group_config['cache'] ) ?
					(bool) $group_config['cache'] : false;
				$cookies = isset( $group_config['cookies'] ) ?
					explode( "\r\n", trim( $group_config['cookies'] ) ) : array();
				$cookies = array_unique( $cookies );

				sort( $cookies );

				$cookiegroups[ $group ] = array(
					'enabled' => $enabled,
					'cache'   => $cache,
					'cookies' => $cookies,
				);
			}
		}

		// Allow plugins modify W3TC cookie groups.
		$cookiegroups = apply_filters( 'w3tc_pgcache_cookiegroups', $cookiegroups );

		$enabled = false;

		foreach ( $cookiegroups as $group_config ) {
			if ( $group_config['enabled'] ) {
				$enabled = true;
				break;
			}
		}

		$config->set( 'pgcache.cookiegroups.enabled', $enabled );
		$config->set( 'pgcache.cookiegroups.groups', $cookiegroups );
	}
}
