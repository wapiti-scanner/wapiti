<?php
namespace W3TC;

/**
 * Rules generation for Nginx
 */
class BrowserCache_Environment_Nginx {
	private $c;



	public function __construct( $config ) {
		$this->c = $config;
	}



	public function get_required_rules( $mime_types ) {
		return array(
			array(
				'filename' => Util_Rule::get_nginx_rules_path(),
				'content'  => $this->generate( $mime_types ),
			),
		);
	}



	/**
	 * Returns cache rules
	 */
	public function generate( $mime_types, $cdnftp = false ) {
		$cssjs_types = $mime_types['cssjs'];
		$cssjs_types = array_unique( $cssjs_types );
		$html_types = $mime_types['html'];
		$other_types = $mime_types['other'];
		$other_compression_types = $mime_types['other_compression'];

		$rules = '';
		$rules .= W3TC_MARKER_BEGIN_BROWSERCACHE_CACHE . "\n";

		if ( $this->c->get_boolean( 'browsercache.rewrite' ) ) {
			$core = Dispatcher::component( 'BrowserCache_Core' );
			$extensions = $core->get_replace_extensions( $this->c );

			$exts = implode( '|', $extensions );

			$rules .= "set \$w3tcbc_rewrite_filename '';\n";
			$rules .= "set \$w3tcbc_rewrite_uri '';\n";
			$rules .= "if (\$uri ~ '^(?<w3tcbc_base>.+)\.(x[0-9]{5})" .
				"(?<w3tcbc_ext>\.($exts))$') {\n";
			$rules .= "    set \$w3tcbc_rewrite_filename \$document_root\$w3tcbc_base\$w3tcbc_ext;\n";
			$rules .= "    set \$w3tcbc_rewrite_uri \$w3tcbc_base\$w3tcbc_ext;\n";
			$rules .= "}\n";

			if ( Util_Environment::is_wpmu() &&
				!Util_Environment::is_wpmu_subdomain() ) {
				// WPMU subdir extra rewrite

				if ( defined( 'W3TC_HOME_URI' ) ) {
					$home_uri = W3TC_HOME_URI;
				} else {
					$primary_blog_id = get_network()->site_id;
					$home_uri = parse_url( get_home_url( $primary_blog_id ),
						PHP_URL_PATH );
					$home_uri = rtrim( $home_uri, '/' );
				}

				$rules .= "if (\$uri ~ '^$home_uri/[_0-9a-zA-Z-]+(?<w3tcbc_base>/wp-.+)\.(x[0-9]{5})(?<w3tcbc_ext>\.($exts))$') {\n";
				$rules .= "    set \$w3tcbc_rewrite_filename \$document_root$home_uri\$w3tcbc_base\$w3tcbc_ext;\n";
				$rules .= "    set \$w3tcbc_rewrite_uri $home_uri\$w3tcbc_base\$w3tcbc_ext;\n";
				$rules .= "}\n";
			}

			$rules .= "if (-f \$w3tcbc_rewrite_filename) {\n";
			$rules .= "    rewrite .* \$w3tcbc_rewrite_uri;\n";
			$rules .= "}\n";
		}

		$cssjs_brotli = $this->c->get_boolean( 'browsercache.cssjs.brotli' );
		$html_brotli = $this->c->get_boolean( 'browsercache.html.brotli' );
		$other_brotli = $this->c->get_boolean( 'browsercache.other.brotli' );

		if ( $cssjs_brotli || $html_brotli || $other_brotli ) {
			$brotli_types = array();

			if ( $cssjs_brotli ) {
				$brotli_types = array_merge( $brotli_types, $cssjs_types );
			}

			if ( $html_brotli ) {
				$brotli_types = array_merge( $brotli_types, $html_types );
			}

			if ( $other_brotli ) {
				$brotli_types = array_merge( $brotli_types,
					$other_compression_types );
			}

			unset( $brotli_types['html|htm'] );

			// some nginx cant handle values longer than 47 chars
			unset( $brotli_types['odp'] );

			$rules .= "brotli on;\n";
			$rules .= 'brotli_types ' .
				implode( ' ', array_unique( $brotli_types ) ) . ";\n";
		}

		$cssjs_compression = $this->c->get_boolean( 'browsercache.cssjs.compression' );
		$html_compression = $this->c->get_boolean( 'browsercache.html.compression' );
		$other_compression = $this->c->get_boolean( 'browsercache.other.compression' );

		if ( $cssjs_compression || $html_compression || $other_compression ) {
			$compression_types = array();

			if ( $cssjs_compression ) {
				$compression_types = array_merge( $compression_types, $cssjs_types );
			}

			if ( $html_compression ) {
				$compression_types = array_merge( $compression_types, $html_types );
			}

			if ( $other_compression ) {
				$compression_types = array_merge( $compression_types,
					$other_compression_types );
			}

			unset( $compression_types['html|htm'] );

			// some nginx cant handle values longer than 47 chars
			unset( $compression_types['odp'] );

			$rules .= "gzip on;\n";
			$rules .= "gzip_types " .
				implode( ' ', array_unique( $compression_types ) ) . ";\n";
		}

		if ( $this->c->get_boolean( 'browsercache.no404wp' ) ) {
			$exceptions = $this->c->get_array( 'browsercache.no404wp.exceptions' );

			$impoloded = implode( '|', $exceptions );
			if ( !empty( $impoloded ) ) {
				$wp_uri = network_home_url( '', 'relative' );
				$wp_uri = rtrim( $wp_uri, '/' );

				$rules .= "location ~ (" . $impoloded . ") {\n";
				$rules .= '    try_files $uri $uri/ ' . $wp_uri .
					'/index.php?$args;' . "\n";
				$rules .= "}\n";
			}
		}

		$this->generate_section( $rules, $mime_types['cssjs'], 'cssjs' );
		$this->generate_section( $rules, $mime_types['html'], 'html' );
		$this->generate_section( $rules, $mime_types['other'], 'other' );

		$rules .= implode( "\n", $this->security_rules() ) . "\n";
		$rules .= W3TC_MARKER_END_BROWSERCACHE_CACHE . "\n";

		return $rules;
	}



	/**
	 * Returns security header directives
	 */
	private function security_rules() {
		$rules = [];

		if ( $this->c->get_boolean( 'browsercache.hsts' ) ||
			$this->c->get_boolean( 'browsercache.security.xfo' ) ||
			$this->c->get_boolean( 'browsercache.security.xss' ) ||
			$this->c->get_boolean( 'browsercache.security.xcto' ) ||
			$this->c->get_boolean( 'browsercache.security.pkp' ) ||
			$this->c->get_boolean( 'browsercache.security.referrer.policy' ) ||
			$this->c->get_boolean( 'browsercache.security.csp' ) ||
			$this->c->get_boolean( 'browsercache.security.cspro' ) ||
			$this->c->get_boolean( 'browsercache.security.fp' )
			) {
			$lifetime = $this->c->get_integer( 'browsercache.other.lifetime' );

			if ( $this->c->get_boolean( 'browsercache.hsts' ) ) {
				$dir = $this->c->get_string( 'browsercache.security.hsts.directive' );
				$rules[] = "add_header Strict-Transport-Security \"max-age=$lifetime" . ( strpos( $dir,"inc" ) ? "; includeSubDomains" : "" ) . ( strpos( $dir, "pre" ) ? "; preload" : "" ) . "\";";
			}

			if ( $this->c->get_boolean( 'browsercache.security.xfo' ) ) {
				$dir = $this->c->get_string( 'browsercache.security.xfo.directive' );
				$url = trim( $this->c->get_string( 'browsercache.security.xfo.allow' ) );
				if ( empty( $url ) ) {
					$url = Util_Environment::home_url_maybe_https();
				}
				$rules[] = "add_header X-Frame-Options \"" . ( $dir == "same" ? "SAMEORIGIN" : ( $dir == "deny" ? "DENY" : "ALLOW-FROM $url" ) ) . "\";";
			}

			if ( $this->c->get_boolean( 'browsercache.security.xss' ) ) {
				$dir = $this->c->get_string( 'browsercache.security.xss.directive' );
				$rules[] = "add_header X-XSS-Protection \"" . ( $dir == "block" ? "1; mode=block" : $dir ) . "\";";
			}

			if ( $this->c->get_boolean( 'browsercache.security.xcto' ) ) {
				$rules[] = "add_header X-Content-Type-Options \"nosniff\";";
			}

			if ( $this->c->get_boolean( 'browsercache.security.pkp' ) ) {
				$pin = trim( $this->c->get_string( 'browsercache.security.pkp.pin' ) );
				$pinbak = trim( $this->c->get_string( 'browsercache.security.pkp.pin.backup' ) );
				$extra = $this->c->get_string( 'browsercache.security.pkp.extra' );
				$url = trim( $this->c->get_string( 'browsercache.security.pkp.report.url' ) );
				$rep_only = $this->c->get_string( 'browsercache.security.pkp.report.only' ) == '1' ? true : false;
				$rules[] = "add_header " . ( $rep_only ? "Public-Key-Pins-Report-Only" : "Public-Key-Pins" ) . " 'pin-sha256=\"$pin\"; pin-sha256=\"$pinbak\"; max-age=$lifetime" . ( strpos( $extra,"inc" ) ? "; includeSubDomains" : "" ) . ( !empty( $url ) ? "; report-uri=\"$url\"" : "" ) . "';";
			}

			if ( $this->c->get_boolean( 'browsercache.security.referrer.policy' ) ) {
				$dir = $this->c->get_string( 'browsercache.security.referrer.policy.directive' );
				$rules[] = "add_header Referrer-Policy \"" . ( $dir == "0" ? "" : $dir ) . "\";";
			}

			if ( $this->c->get_boolean( 'browsercache.security.csp' ) ) {
				$base            = trim( $this->c->get_string( 'browsercache.security.csp.base' ) );
				$frame           = trim( $this->c->get_string( 'browsercache.security.csp.frame' ) );
				$connect         = trim( $this->c->get_string( 'browsercache.security.csp.connect' ) );
				$font            = trim( $this->c->get_string( 'browsercache.security.csp.font' ) );
				$script          = trim( $this->c->get_string( 'browsercache.security.csp.script' ) );
				$style           = trim( $this->c->get_string( 'browsercache.security.csp.style' ) );
				$img             = trim( $this->c->get_string( 'browsercache.security.csp.img' ) );
				$media           = trim( $this->c->get_string( 'browsercache.security.csp.media' ) );
				$object          = trim( $this->c->get_string( 'browsercache.security.csp.object' ) );
				$plugin          = trim( $this->c->get_string( 'browsercache.security.csp.plugin' ) );
				$form            = trim( $this->c->get_string( 'browsercache.security.csp.form' ) );
				$frame_ancestors = trim( $this->c->get_string( 'browsercache.security.csp.frame.ancestors' ) );
				$sandbox         = trim( $this->c->get_string( 'browsercache.security.csp.sandbox' ) );
				$child           = trim( $this->c->get_string( 'browsercache.security.csp.child' ) );
				$manifest        = trim( $this->c->get_string( 'browsercache.security.csp.manifest' ) );
				$scriptelem      = trim( $this->c->get_string( 'browsercache.security.csp.scriptelem' ) );
				$scriptattr      = trim( $this->c->get_string( 'browsercache.security.csp.scriptattr' ) );
				$styleelem       = trim( $this->c->get_string( 'browsercache.security.csp.styleelem' ) );
				$scriptelem      = trim( $this->c->get_string( 'browsercache.security.csp.styleattr' ) );
				$worker          = trim( $this->c->get_string( 'browsercache.security.csp.worker' ) );
				$default         = trim( $this->c->get_string( 'browsercache.security.csp.default' ) );

				$dir = rtrim(
					( ! empty( $base ) ? "base-uri $base; " : '' ) .
						( ! empty( $frame ) ? "frame-src $frame; " : '' ) .
						( ! empty( $connect ) ? "connect-src $connect; " : '' ) .
						( ! empty( $font ) ? "font-src $font; " : '' ) .
						( ! empty( $script ) ? "script-src $script; " : '' ) .
						( ! empty( $style ) ? "style-src $style; " : '' ) .
						( ! empty( $img ) ? "img-src $img; " : '' ) .
						( ! empty( $media ) ? "media-src $media; " : '' ) .
						( ! empty( $object ) ? "object-src $object; " : '' ) .
						( ! empty( $plugin ) ? "plugin-types $plugin; " : '' ) .
						( ! empty( $form ) ? "form-action $form; " : '' ) .
						( ! empty( $frame_ancestors ) ? "frame-ancestors $frame_ancestors; " : '' ) .
						( ! empty( $sandbox ) ? "sandbox $sandbox; " : '' ) .
						( ! empty( $child ) ? "child-src $child; " : '' ) .
						( ! empty( $manifest ) ? "manifest-src $manifest; " : '' ) .
						( ! empty( $scriptelem ) ? "script-src-elem $scriptelem; " : '' ) .
						( ! empty( $scriptattr ) ? "script-src-attr $scriptattr; " : '' ) .
						( ! empty( $styleelem ) ? "style-src-elem $styleelem; " : '' ) .
						( ! empty( $styleattr ) ? "style-src-attr $styleattr; " : '' ) .
						( ! empty( $worker ) ? "worker-src $worker; " : '' ) .
						( ! empty( $default ) ? "default-src $default;" : '' ),
					'; '
				);

				if ( ! empty( $dir ) ) {
					$rules[] = "add_header Content-Security-Policy \"$dir\";";
				}
			}

			if ( $this->c->get_boolean( 'browsercache.security.cspro' ) && ( ! empty( $this->c->get_string( 'browsercache.security.cspro.reporturi' ) ) || ! empty( $this->c->get_string( 'browsercache.security.cspro.reportto' ) ) ) ) {
				$base            = trim( $this->c->get_string( 'browsercache.security.cspro.base' ) );
				$reporturi       = trim( $this->c->get_string( 'browsercache.security.cspro.reporturi' ) );
				$reportto        = trim( $this->c->get_string( 'browsercache.security.cspro.reportto' ) );
				$frame           = trim( $this->c->get_string( 'browsercache.security.cspro.frame' ) );
				$connect         = trim( $this->c->get_string( 'browsercache.security.cspro.connect' ) );
				$font            = trim( $this->c->get_string( 'browsercache.security.cspro.font' ) );
				$script          = trim( $this->c->get_string( 'browsercache.security.cspro.script' ) );
				$style           = trim( $this->c->get_string( 'browsercache.security.cspro.style' ) );
				$img             = trim( $this->c->get_string( 'browsercache.security.cspro.img' ) );
				$media           = trim( $this->c->get_string( 'browsercache.security.cspro.media' ) );
				$object          = trim( $this->c->get_string( 'browsercache.security.cspro.object' ) );
				$plugin          = trim( $this->c->get_string( 'browsercache.security.cspro.plugin' ) );
				$form            = trim( $this->c->get_string( 'browsercache.security.cspro.form' ) );
				$frame_ancestors = trim( $this->c->get_string( 'browsercache.security.cspro.frame.ancestors' ) );
				$sandbox         = trim( $this->c->get_string( 'browsercache.security.cspro.sandbox' ) );
				$child           = trim( $this->c->get_string( 'browsercache.security.csp.child' ) );
				$manifest        = trim( $this->c->get_string( 'browsercache.security.csp.manifest' ) );
				$scriptelem      = trim( $this->c->get_string( 'browsercache.security.csp.scriptelem' ) );
				$scriptattr      = trim( $this->c->get_string( 'browsercache.security.csp.scriptattr' ) );
				$styleelem       = trim( $this->c->get_string( 'browsercache.security.csp.styleelem' ) );
				$scriptelem      = trim( $this->c->get_string( 'browsercache.security.csp.styleattr' ) );
				$worker          = trim( $this->c->get_string( 'browsercache.security.csp.worker' ) );
				$default         = trim( $this->c->get_string( 'browsercache.security.cspro.default' ) );

				$dir = rtrim(
					( ! empty( $base ) ? "base-uri $base; " : '' ) .
						( ! empty( $reporturi ) ? "report-uri $reporturi; " : '' ) .
						( ! empty( $reportto ) ? "report-to $reportto; " : '' ) .
						( ! empty( $frame ) ? "frame-src $frame; " : '' ) .
						( ! empty( $connect ) ? "connect-src $connect; " : '' ) .
						( ! empty( $font ) ? "font-src $font; " : '' ) .
						( ! empty( $script ) ? "script-src $script; " : '' ) .
						( ! empty( $style ) ? "style-src $style; " : '' ) .
						( ! empty( $img ) ? "img-src $img; " : '' ) .
						( ! empty( $media ) ? "media-src $media; " : '' ) .
						( ! empty( $object ) ? "object-src $object; " : '' ) .
						( ! empty( $plugin ) ? "plugin-types $plugin; " : '' ) .
						( ! empty( $form ) ? "form-action $form; " : '' ) .
						( ! empty( $frame_ancestors ) ? "frame-ancestors $frame_ancestors; " : '' ) .
						( ! empty( $sandbox ) ? "sandbox $sandbox; " : '' ) .
						( ! empty( $child ) ? "child-src $child; " : '' ) .
						( ! empty( $manifest ) ? "manifest-src $manifest; " : '' ) .
						( ! empty( $scriptelem ) ? "script-src-elem $scriptelem; " : '' ) .
						( ! empty( $scriptattr ) ? "script-src-attr $scriptattr; " : '' ) .
						( ! empty( $styleelem ) ? "style-src-elem $styleelem; " : '' ) .
						( ! empty( $styleattr ) ? "style-src-attr $styleattr; " : '' ) .
						( ! empty( $worker ) ? "worker-src $worker; " : '' ) .
						( ! empty( $default ) ? "default-src $default;" : '' ),
					'; '
				);

				if ( ! empty( $dir ) ) {
					$rules[] = "add_header Content-Security-Policy-Report-Only \"$dir\";";
				}
			}

			if ( $this->c->get_boolean( 'browsercache.security.fp' ) ) {
				$fp_values = $this->c->get_array( 'browsercache.security.fp.values' );

				$feature_v    = array();
				$permission_v = array();
				foreach ( $fp_values as $key => $value ) {
					if ( ! empty( $value ) ) {
						$value = str_replace( array( '"', "'" ), '', $value );

						$feature_v[]    = "$key '$value'";
						$permission_v[] = "$key=($value)";
					}
				}

				if ( ! empty( $feature_v ) ) {
					$rules .= '    Header set Feature-Policy "' . implode( ';', $feature_v ) . "\"\n";
				}

				if ( ! empty( $permission_v ) ) {
					$rules .= '    Header set Permissions-Policy "' . implode( ',', $permission_v ) . "\"\n";
				}
			}
		}

		return $rules;
	}

	/**
	 * Adds cache rules for type to &$rules.
	 *
	 * @param string $rules      Rules.
	 * @param array  $mime_types MIME types.
	 * @param string $section    Section.
	 * @return void
	 */
	private function generate_section( &$rules, $mime_types, $section ) {
		$expires       = $this->c->get_boolean( 'browsercache.' . $section . '.expires' );
		$etag          = $this->c->get_boolean( 'browsercache.' . $section . '.etag' );
		$cache_control = $this->c->get_boolean( 'browsercache.' . $section . '.cache.control' );
		$w3tc          = $this->c->get_boolean( 'browsercache.' . $section . '.w3tc' );
		$last_modified = $this->c->get_boolean( 'browsercache.' . $section . '.last_modified' );

		if ( $etag || $expires || $cache_control || $w3tc || ! $last_modified ) {
			$mime_types2 = apply_filters(
				'w3tc_browsercache_rules_section_extensions',
				$mime_types,
				$this->c,
				$section
			);
			$extensions  = array_keys( $mime_types2 );

			// Remove ext from filesmatch if its the same as permalink extension.
			$pext = strtolower( pathinfo( get_option( 'permalink_structure' ), PATHINFO_EXTENSION ) );

			if ( $pext ) {
				$extensions = Util_Rule::remove_extension_from_list( $extensions, $pext );
			}

			$rules .= 'location ~ \\.(' . implode( '|', $extensions ) . ')$ {' . "\n";

			$subrules = Dispatcher::nginx_rules_for_browsercache_section( $this->c, $section );
			$rules   .= '    ' . implode( "\n    ", $subrules ) . "\n";

			// Add rules for the Image Service extension, if active.
			if ( 'other' === $section && array_key_exists( 'imageservice', $this->c->get_array( 'extensions.active' ) ) ) {
				$rules .= "\n" . '    location ~* ^(?<path>.+)\.(jpe?g|png|gif)$ {' . "\n" .
					'        if ( $http_accept !~* "webp|\*/\*" ) {' . "\n" .
					'            break;' . "\n" .
					'        }' . "\n\n" .
					'        ' . implode( "\n        ", Dispatcher::nginx_rules_for_browsercache_section( $this->c, $section, true ) ) . "\n" .
					'        add_header Vary Accept;' . "\n";

				if ( $this->c->get_boolean( 'browsercache.no404wp' ) ) {
					$rules .= '        try_files ${path}.webp $uri =404;';
				} else {
					$rules .= '        try_files ${path}.webp $uri /index.php?$args;';
				}

				$rules .= "\n" . '    }' . "\n\n";
			}

			if ( ! $this->c->get_boolean( 'browsercache.no404wp' ) ) {
				$wp_uri = network_home_url( '', 'relative' );
				$wp_uri = rtrim( $wp_uri, '/' );
				$rules .= '    try_files $uri $uri/ ' . $wp_uri . '/index.php?$args;' . "\n";
			}

			$rules .= '}' . "\n";
		}
	}

	/**
	 * Returns directives plugin applies to files of specific section
	 * Without location
	 *
	 * $extra_add_headers_set specifies if other add_header directives will
	 *   be added to location block generated
	 */
	public function section_rules( $section, $extra_add_headers_set = false ) {
		$rules = array();

		$expires = $this->c->get_boolean( "browsercache.$section.expires" );
		$lifetime = $this->c->get_integer( "browsercache.$section.lifetime" );

		if ( $expires ) {
			$rules[] = 'expires ' . $lifetime . 's;';
		}
		if ( version_compare( Util_Environment::get_server_version(), '1.3.3', '>=' ) ) {
			if ( $this->c->get_boolean( "browsercache.$section.etag" ) ) {
				$rules[] = 'etag on;';
			} else {
				$rules[] = 'etag off;';
			}
		}
		if ( $this->c->get_boolean( "browsercache.$section.last_modified" ) ) {
			$rules[] = 'if_modified_since exact;';
		} else {
			$rules[] = 'if_modified_since off;';
		}

		$add_header_rules = array();
		if ( $this->c->get_boolean( "browsercache.$section.cache.control" ) ) {
			$cache_policy = $this->c->get_string( "browsercache.$section.cache.policy" );

			switch ( $cache_policy ) {
			case 'cache':
				$add_header_rules[] = 'add_header Pragma "public";';
				$add_header_rules[] = 'add_header Cache-Control "public";';
				break;

			case 'cache_public_maxage':
				$add_header_rules[] = 'add_header Pragma "public";';

				if ( $expires ) {
					$add_header_rules[] = 'add_header Cache-Control "public";';
				} else {
					$add_header_rules[] = "add_header Cache-Control \"max-age=$lifetime, public\";";
				}
				break;

			case 'cache_validation':
				$add_header_rules[] = 'add_header Pragma "public";';
				$add_header_rules[] = 'add_header Cache-Control "public, must-revalidate, proxy-revalidate";';
				break;

			case 'cache_noproxy':
				$add_header_rules[] = 'add_header Pragma "public";';
				$add_header_rules[] = 'add_header Cache-Control "private, must-revalidate";';
				break;

			case 'cache_maxage':
				$add_header_rules[] = 'add_header Pragma "public";';

				if ( $expires ) {
					$add_header_rules[] = 'add_header Cache-Control "public, must-revalidate, proxy-revalidate";';
				} else {
					$add_header_rules[] = "add_header Cache-Control \"max-age=$lifetime, public, must-revalidate, proxy-revalidate\";";
				}
				break;

			case 'no_cache':
				$add_header_rules[] = 'add_header Pragma "no-cache";';
				$add_header_rules[] = 'add_header Cache-Control "max-age=0, private, no-store, no-cache, must-revalidate";';
				break;
			}
		}

		if ( $this->c->get_boolean( "browsercache.$section.w3tc" ) ) {
			$add_header_rules[] = 'add_header X-Powered-By "' .
				Util_Environment::w3tc_header() . '";';
		}

		if ( !empty( $add_header_rules ) || $extra_add_headers_set ) {
			$add_header_rules = array_merge( $add_header_rules,
				$this->security_rules() );
		}

		return array( 'add_header' => $add_header_rules, 'other' => $rules );
	}
}
