<?php
/**
 * Jetpack Partner package.
 *
 * @package  automattic/jetpack-partner
 */

namespace Automattic\Jetpack;

/**
 * This class introduces functionality used by Jetpack hosting partners.
 *
 * @since 1.0.0
 */
class Partner {

	/**
	 * Affiliate code.
	 */
	const AFFILIATE_CODE = 'affiliate';

	/**
	 * Subsidiary id code.
	 */
	const SUBSIDIARY_CODE = 'subsidiary';

	/**
	 * Singleton instance.
	 *
	 * @since 1.0.0
	 *
	 * @var Partner This class instance.
	 */
	private static $instance = null;

	/**
	 * Partner constructor.
	 */
	private function __construct() {
	}

	/**
	 * Initializes the class or returns the singleton.
	 *
	 * @return Partner | false
	 * @since 1.0.0
	 */
	public static function init() {
		if ( self::$instance === null ) {
			self::$instance = new Partner();
			add_filter( 'jetpack_build_authorize_url', array( self::$instance, 'add_subsidiary_id_as_query_arg' ) );
			add_filter( 'jetpack_build_authorize_url', array( self::$instance, 'add_affiliate_code_as_query_arg' ) );
			add_filter( 'jetpack_build_connection_url', array( self::$instance, 'add_subsidiary_id_as_query_arg' ) );
			add_filter( 'jetpack_build_connection_url', array( self::$instance, 'add_affiliate_code_as_query_arg' ) );

			add_filter( 'jetpack_register_request_body', array( self::$instance, 'add_subsidiary_id_to_params_array' ) );
			add_filter( 'jetpack_register_request_body', array( self::$instance, 'add_affiliate_code_to_params_array' ) );
		}

		return self::$instance;
	}

	/**
	 * Adds the partner subsidiary code to the passed URL.
	 *
	 * @param string $url The URL.
	 *
	 * @return string
	 */
	public function add_subsidiary_id_as_query_arg( $url ) {
		return $this->add_code_as_query_arg( self::SUBSIDIARY_CODE, $url );
	}

	/**
	 * Adds the affiliate code to the passed URL.
	 *
	 * @param string $url The URL.
	 *
	 * @return string
	 */
	public function add_affiliate_code_as_query_arg( $url ) {
		return $this->add_code_as_query_arg( self::AFFILIATE_CODE, $url );
	}

	/**
	 * Adds the partner subsidiary code to the passed array.
	 *
	 * @param array $params The parameters array.
	 *
	 * @return array
	 * @since 1.5.0
	 */
	public function add_subsidiary_id_to_params_array( $params ) {
		if ( ! is_array( $params ) ) {
			return $params;
		}
		return array_merge( $params, $this->get_code_as_array( self::SUBSIDIARY_CODE ) );
	}

	/**
	 * Adds the affiliate code to the passed array.
	 *
	 * @param array $params The parameters array.
	 *
	 * @return array
	 * @since 1.5.0
	 */
	public function add_affiliate_code_to_params_array( $params ) {
		if ( ! is_array( $params ) ) {
			return $params;
		}
		return array_merge( $params, $this->get_code_as_array( self::AFFILIATE_CODE ) );
	}

	/**
	 * Returns the passed URL with the partner code added as a URL query arg.
	 *
	 * @param string $type The partner code.
	 * @param string $url The URL where the partner subsidiary id will be added.
	 *
	 * @return string The passed URL with the partner code added.
	 * @since 1.0.0
	 */
	public function add_code_as_query_arg( $type, $url ) {
		return add_query_arg( $this->get_code_as_array( $type ), $url );
	}

	/**
	 * Gets the partner code in an associative array format
	 *
	 * @param string $type The partner code.
	 * @return array
	 * @since 1.5.0
	 */
	private function get_code_as_array( $type ) {
		switch ( $type ) {
			case self::AFFILIATE_CODE:
				$query_arg_name = 'aff';
				break;
			case self::SUBSIDIARY_CODE:
				$query_arg_name = 'subsidiaryId';
				break;
			default:
				return array();
		}

		$code = $this->get_partner_code( $type );

		if ( '' === $code ) {
			return array();
		}

		return array( $query_arg_name => $code );
	}

	/**
	 * Returns a partner code.
	 *
	 * @param string $type This can be either 'affiliate' or 'subsidiary'. Returns empty string when code is unknown.
	 *
	 * @return string The partner code.
	 * @since 1.0.0
	 */
	public function get_partner_code( $type ) {
		switch ( $type ) {
			case self::AFFILIATE_CODE:
				/**
				 * Allow to filter the affiliate code.
				 *
				 * @param string $affiliate_code The affiliate code, blank by default.
				 *
				 * @since 1.0.0
				 * @since-jetpack 6.9.0
				 */
				return apply_filters( 'jetpack_affiliate_code', get_option( 'jetpack_affiliate_code', '' ) );
			case self::SUBSIDIARY_CODE:
				/**
				 * Allow to filter the partner subsidiary id.
				 *
				 * @param string $subsidiary_id The partner subsidiary id, blank by default.
				 *
				 * @since 1.0.0
				 */
				return apply_filters(
					'jetpack_partner_subsidiary_id',
					get_option( 'jetpack_partner_subsidiary_id', '' )
				);
			default:
				return '';
		}
	}

	/**
	 * Resets the singleton for testing purposes.
	 */
	public static function reset() {
		self::$instance = null;
	}
}
