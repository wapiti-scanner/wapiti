<?php
/**
 * File: Extension_ImageService_Environment.php
 *
 * @since 2.2.0
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Extension_ImageService_Environment
 */
class Extension_ImageService_Environment {
	/**
	 * Fixes environment in each wp-admin request.
	 *
	 * @since 2.2.0
	 *
	 * @param Config $config           Configuration.
	 * @param bool   $force_all_checks Force all checks.
	 * @throws Util_Environment_Exceptions Exceptions.
	 */
	public function fix_on_wpadmin_request( $config, $force_all_checks ) {
		$exs = new Util_Environment_Exceptions();

		if ( $config->get_boolean( 'config.check' ) || $force_all_checks ) {
			$extensions_active = $config->get_array( 'extensions.active' );

			if ( array_key_exists( 'imageservice', $extensions_active ) ) {
				$this->rules_add( $config, $exs );
			} else {
				$this->rules_remove( $exs );
			}
		}

		if ( count( $exs->exceptions() ) > 0 ) {
			throw $exs;
		}
	}

	/**
	 * Fixes environment once event occurs.
	 *
	 * @since 2.2.0
	 *
	 * @param Config $config     Config object.
	 * @param mixed  $event      Event.
	 * @param Config $old_config Old config object.
	 */
	public function fix_on_event( $config, $event, $old_config = null ) {
	}

	/**
	 * Fixes environment after plugin deactivation
	 *
	 * @since 2.2.0
	 *
	 * @throws Util_Environment_Exceptions Exceptions.
	 */
	public function fix_after_deactivation() {
		$exs = new Util_Environment_Exceptions();

		$this->rules_remove( $exs );

		if ( count( $exs->exceptions() ) > 0 ) {
			throw $exs;
		}
	}

	/**
	 * Returns required rules for module.
	 *
	 * @since 2.2.0
	 *
	 * @param Config $config Configuration object.
	 * @return array
	 */
	public function get_required_rules( $config ) {
		return array(
			array(
				'filename' => Util_Rule::get_browsercache_rules_cache_path(),
				'content'  => $this->rules_generate(),
			),
		);
	}

	/**
	 * Write rewrite rules.
	 *
	 * @since 2.2.0
	 *
	 * @param Config                      $config Configuration.
	 * @param Util_Environment_Exceptions $exs    Exceptions.
	 *
	 * @throws Util_WpFile_FilesystemOperationException S/FTP form if it can't get the required filesystem credentials.
	 */
	private function rules_add( $config, $exs ) {
		Util_Rule::add_rules(
			$exs,
			Util_Rule::get_browsercache_rules_cache_path(),
			$this->rules_generate(),
			W3TC_MARKER_BEGIN_WEBP,
			W3TC_MARKER_END_WEBP,
			array(
				W3TC_MARKER_BEGIN_BROWSERCACHE_CACHE => 0,
				W3TC_MARKER_BEGIN_WORDPRESS          => 0,
			)
		);
	}

	/**
	 * Generate rewrite rules.
	 *
	 * @since 2.2.0
	 *
	 * @see Dispatcher::nginx_rules_for_browsercache_section()
	 *
	 * @return string
	 */
	private function rules_generate() {
		switch ( true ) {
			case Util_Environment::is_apache():
			case Util_Environment::is_litespeed():
				return '
# BEGIN W3TC WEBP
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTP_ACCEPT} image/webp
    RewriteCond %{REQUEST_FILENAME} (.+)\.(jpe?g|png|gif)$
    RewriteCond %1\.webp -f
    RewriteCond %{QUERY_STRING} !type=original
    RewriteRule (.+)\.(jpe?g|png|gif)$ $1.webp [NC,T=image/webp,E=webp,L]
</IfModule>
<IfModule mod_headers.c>
    <FilesMatch "\.(jpe?g|png|gif)$">
        Header append Vary Accept
    </FilesMatch>
</IfModule>
AddType image/webp .webp
# END W3TC WEBP

';

			case Util_Environment::is_nginx():
				$config = Dispatcher::config();

				/*
				 * Add Nginx rules only if Browser Cache is disabled.
				 * Otherwise, the rules are added in "BrowserCache_Environment_Nginx.php".
				 * @see BrowserCache_Environment_Nginx::generate_section()
				 */
				if ( ! $config->get_boolean( 'browsercache.enabled' ) ) {
					if ( $config->get_boolean( 'browsercache.no404wp' ) ) {
						$fallback = '=404';
					} else {
						$fallback = '/index.php?$args';
					}

					return '
# BEGIN W3TC WEBP
location ~* ^(?<path>.+)\.(jpe?g|png|gif)$ {
    if ( $http_accept !~* "webp|\*/\*" ) {
        break;
    }

    ' . implode( "\n    ", Dispatcher::nginx_rules_for_browsercache_section( $config, 'other' ) ) . '

    add_header Vary Accept;
    try_files ${path}.webp $uri ' . $fallback . ';
}
# END W3TC WEBP

';
				} else {
					return '';
				}

			default:
				return '';
		}
	}

	/**
	 * Removes cache directives
	 *
	 * @since 2.2.0
	 *
	 * @param Util_Environment_Exceptions $exs Exceptions.
	 *
	 * @throws Util_WpFile_FilesystemOperationException S/FTP form if it can't get the required filesystem credentials.
	 */
	private function rules_remove( $exs ) {
		Util_Rule::remove_rules(
			$exs,
			Util_Rule::get_pgcache_rules_core_path(),
			W3TC_MARKER_BEGIN_WEBP,
			W3TC_MARKER_END_WEBP
		);
	}
}
