<?php
/**
 * A hosting provide class for Jetpack.
 *
 * @package automattic/jetpack-status
 */

namespace Automattic\Jetpack\Status;

use Automattic\Jetpack\Constants;

/**
 * Hosting provider class.
 */
class Host {
	/**
	 * Determine if this site is an WordPress.com on Atomic site or not by looking for presence of the wpcomsh plugin.
	 *
	 * @since 1.9.0
	 *
	 * @return bool
	 */
	public function is_woa_site() {
		$ret = Cache::get( 'is_woa_site' );
		if ( null === $ret ) {
			$ret = $this->is_atomic_platform() && Constants::is_true( 'WPCOMSH__PLUGIN_FILE' );
			Cache::set( 'is_woa_site', $ret );
		}
		return $ret;
	}

	/**
	 * Determine if the site is hosted on the Atomic hosting platform.
	 *
	 * @since 1.9.0
	 *
	 * @return bool;
	 */
	public function is_atomic_platform() {
		return Constants::is_true( 'ATOMIC_SITE_ID' ) && Constants::is_true( 'ATOMIC_CLIENT_ID' );
	}

	/**
	 * Determine if this is a Newspack site.
	 *
	 * @return bool
	 */
	public function is_newspack_site() {
		return Constants::is_defined( 'NEWSPACK_PLUGIN_FILE' );
	}

	/**
	 * Determine if this is a VIP-hosted site.
	 *
	 * @return bool
	 */
	public function is_vip_site() {
		return Constants::is_defined( 'WPCOM_IS_VIP_ENV' ) && true === Constants::get_constant( 'WPCOM_IS_VIP_ENV' );
	}

	/**
	 * Determine if this is a Simple platform site.
	 *
	 * @return bool
	 */
	public function is_wpcom_simple() {
		return Constants::is_defined( 'IS_WPCOM' ) && true === Constants::get_constant( 'IS_WPCOM' );
	}

	/**
	 * Determine if this is a WordPress.com site.
	 *
	 * Includes both Simple and WoA platforms.
	 *
	 * @return bool
	 */
	public function is_wpcom_platform() {
		return $this->is_wpcom_simple() || $this->is_woa_site();
	}

	/**
	 * Add all wordpress.com environments to the safe redirect allowed list.
	 *
	 * To be used with a filter of allowed domains for a redirect.
	 *
	 * @param array $domains Allowed WP.com Environments.
	 */
	public static function allow_wpcom_environments( $domains ) {
		$domains[] = 'wordpress.com';
		$domains[] = 'jetpack.wordpress.com';
		$domains[] = 'wpcalypso.wordpress.com';
		$domains[] = 'horizon.wordpress.com';
		$domains[] = 'calypso.localhost';
		return $domains;
	}
}
