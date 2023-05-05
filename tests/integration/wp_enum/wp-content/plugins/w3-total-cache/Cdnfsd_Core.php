<?php
namespace W3TC;

/**
 * Core for FSD CDN
 */
class Cdnfsd_Core {
	/**
	 * Returns CDN object
	 */
	function get_engine() {
		static $engine_object = null;

		if ( is_null( $engine_object ) ) {
			$c = Dispatcher::config();
			$engine = $c->get_string( 'cdnfsd.engine' );

			switch ( $engine ) {
			case 'cloudflare':
				$engine_object = null;   // extension handles everything
				break;

				case 'transparentcdn':
					$engine_object = new Cdnfsd_TransparentCDN_Engine( array(
						'company_id'    => $c->get_string( 'cdnfsd.transparentcdn.company_id' ),
						'client_id'     => $c->get_string( 'cdnfsd.transparentcdn.client_id' ),
						'client_secret' => $c->get_string( 'cdnfsd.transparentcdn.client_secret' )
					) );
				break;

			case 'cloudfront':
				$engine_object = new Cdnfsd_CloudFront_Engine( array(
						'access_key' => $c->get_string( 'cdnfsd.cloudfront.access_key' ),
						'secret_key' => $c->get_string( 'cdnfsd.cloudfront.secret_key' ),
						'distribution_id' => $c->get_string( 'cdnfsd.cloudfront.distribution_id' )
					) );
				break;

			case 'limelight':
				$engine_object = new Cdnfsd_LimeLight_Engine( array(
						'short_name' => $c->get_string( 'cdnfsd.limelight.short_name' ),
						'username' => $c->get_string( 'cdnfsd.limelight.username' ),
						'api_key' => $c->get_string( 'cdnfsd.limelight.api_key' ),
						'debug' => $c->get_string( 'cdnfsd.debug' )
					) );
				break;

			case 'stackpath':
				$engine_object = new Cdnfsd_StackPath_Engine( array(
						'api_key' => $c->get_string( 'cdnfsd.stackpath.api_key' ),
						'zone_id' => $c->get_integer( 'cdnfsd.stackpath.zone_id' )
					) );
				break;

			case 'stackpath2':
				$state = Dispatcher::config_state();

				$engine_object = new Cdnfsd_StackPath2_Engine( array(
					'client_id' => $c->get_string( 'cdnfsd.stackpath2.client_id' ),
					'client_secret' => $c->get_string( 'cdnfsd.stackpath2.client_secret' ),
					'stack_id' => $c->get_string( 'cdnfsd.stackpath2.stack_id' ),
					'site_root_domain' => $c->get_string( 'cdnfsd.stackpath2.site_root_domain' ),
					'domain' => $c->get_array( 'cdnfsd.stackpath2.domain' ),
					'ssl' => $c->get_string( 'cdnfsd.stackpath2.ssl' ),
					'access_token' => $state->get_string( 'cdnfsd.stackpath2.access_token' ),
					'on_new_access_token' => array(
						$this,
						'on_stackpath2_new_access_token'
					)
				) );
				break;

			default:
				throw new \Exception( 'unknown engine ' . $engine );
			}
		}

		return $engine_object;
	}


	public function on_stackpath2_new_access_token( $access_token ) {
		$state = Dispatcher::config_state();
		$state->set( 'cdnfsd.stackpath2.access_token', $access_token );
		$state->save();
	}
}
