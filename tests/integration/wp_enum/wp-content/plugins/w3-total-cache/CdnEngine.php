<?php
namespace W3TC;

/**
 * class CdnEngine
 */
class CdnEngine {
	/**
	 * Returns CdnEngine_Base instance
	 *
	 * @param string  $engine
	 * @param array   $config
	 * @return CdnEngine_Base
	 */
	static function instance( $engine, $config = array() ) {
		static $instances = array();

		$instance_key = sprintf( '%s_%s', $engine, md5( serialize( $config ) ) );

		if ( !isset( $instances[$instance_key] ) ) {
			switch ( $engine ) {
			case 'akamai':
				$instances[$instance_key] = new CdnEngine_Mirror_Akamai( $config );
				break;

			case 'att':
				$instances[$instance_key] = new CdnEngine_Mirror_Att( $config );
				break;

			case 'azure':
				$instances[$instance_key] = new CdnEngine_Azure( $config );
				break;

			case 'cf':
				$instances[$instance_key] = new CdnEngine_CloudFront( $config );
				break;

			case 'cf2':
				$instances[$instance_key] = new CdnEngine_Mirror_CloudFront( $config );
				break;

			case 'cotendo':
				$instances[$instance_key] = new CdnEngine_Mirror_Cotendo( $config );
				break;

			case 'edgecast':
				$instances[$instance_key] = new CdnEngine_Mirror_Edgecast( $config );
				break;

			case 'ftp':
				$instances[$instance_key] = new CdnEngine_Ftp( $config );
				break;

			case 'google_drive':
				$instances[$instance_key] = new CdnEngine_GoogleDrive( $config );
				break;

			case 'highwinds':
				$instances[$instance_key] = new CdnEngine_Mirror_Highwinds( $config );
				break;

			case 'limelight':
				$instances[$instance_key] = new CdnEngine_Mirror_LimeLight( $config );
				break;

			case 'mirror':
				$instances[$instance_key] = new CdnEngine_Mirror( $config );
				break;

			case 'rackspace_cdn':
				$instances[$instance_key] = new CdnEngine_Mirror_RackSpaceCdn( $config );
				break;

			case 'rscf':
				$instances[$instance_key] =
					new CdnEngine_RackSpaceCloudFiles( $config );
				break;

			case 's3':
				$instances[$instance_key] = new CdnEngine_S3( $config );
				break;

			case 's3_compatible':
				$instances[$instance_key] = new CdnEngine_S3_Compatible( $config );
				break;

			case 'stackpath':
				$instances[$instance_key] = new CdnEngine_Mirror_StackPath( $config );
				break;

			case 'stackpath2':
				$instances[$instance_key] = new CdnEngine_Mirror_StackPath2( $config );
				break;

			default :
				trigger_error( 'Incorrect CDN engine', E_USER_WARNING );
				$instances[$instance_key] = new CdnEngine_Base();
				break;
			}
		}

		return $instances[$instance_key];
	}
}
