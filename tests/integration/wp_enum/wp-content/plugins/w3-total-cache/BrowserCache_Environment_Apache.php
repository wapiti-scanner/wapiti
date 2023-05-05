<?php
namespace W3TC;

/**
 * Environment (rules) generation for apache
 * TODO: move all apache-specific code here from BrowserCache_Environment
 */
class BrowserCache_Environment_Apache {
	private $c;



	public function __construct( $config ) {
		$this->c = $config;
	}



	public function rules_rewrite() {
		if ( ! $this->c->get_boolean( 'browsercache.rewrite' ) ) {
			return '';
		}

		$core = Dispatcher::component( 'BrowserCache_Core' );
		$extensions = $core->get_replace_extensions( $this->c );

		$rules = array();
		$rules[] = '<IfModule mod_rewrite.c>';
		$rules[] = '    RewriteCond %{REQUEST_FILENAME} !-f';
		$rules[] = '    RewriteRule ^(.+)\.(x[0-9]{5})\.(' .
			implode( '|', $extensions ) . ')$ $1.$3 [L]';
		$rules[] = '</IfModule>';
		$rules[] = '';

		return implode( "\n", $rules );
	}

	/**
	 * Generate rules related to prevent for media 404 error by WP
	 *
	 * @param Config  $config
	 * @return string
	 */
	public function rules_no404wp( $mime_types ) {
		if ( ! $this->c->get_boolean( 'browsercache.no404wp' ) ) {
			return '';
		}

		$cssjs_types = $mime_types['cssjs'];
		$html_types = $mime_types['html'];
		$other_types = $mime_types['other'];

		$extensions = array_merge( array_keys( $cssjs_types ),
			array_keys( $html_types ), array_keys( $other_types ) );

		$permalink_structure = get_option( 'permalink_structure' );
		$permalink_structure_ext = ltrim( strrchr( $permalink_structure, '.' ),
			'.' );

		if ( $permalink_structure_ext != '' ) {
			foreach ( $extensions as $index => $extension ) {
				if ( strstr( $extension, $permalink_structure_ext ) !== false ) {
					$extensions[$index] = preg_replace( '~\|?' .
						Util_Environment::preg_quote( $permalink_structure_ext ) .
						'\|?~', '', $extension );
				}
			}
		}

		$exceptions = $this->c->get_array( 'browsercache.no404wp.exceptions' );
		$wp_uri = network_home_url( '', 'relative' );
		$wp_uri = rtrim( $wp_uri, '/' );

		$rules = '';
		$rules .= "<IfModule mod_rewrite.c>\n";
		$rules .= "    RewriteEngine On\n";

		// in subdir - rewrite theme files and similar to upper folder if file exists
		if ( Util_Environment::is_wpmu() &&
			!Util_Environment::is_wpmu_subdomain() ) {
			$rules .= "    RewriteCond %{REQUEST_FILENAME} !-f\n";
			$rules .= "    RewriteCond %{REQUEST_FILENAME} !-d\n";
			$rules .= "    RewriteCond %{REQUEST_URI} ^$wp_uri/([_0-9a-zA-Z-]+/)(.*\.)(" .
				implode( '|', $extensions ) . ")$ [NC]\n";
			$document_root = Util_Rule::apache_docroot_variable();
			$rules .= '    RewriteCond "' . $document_root . $wp_uri .
				'/%2%3" -f' . "\n";
			$rules .= "    RewriteRule .* $wp_uri/%2%3 [L]\n\n";
		}


		$rules .= "    RewriteCond %{REQUEST_FILENAME} !-f\n";
		$rules .= "    RewriteCond %{REQUEST_FILENAME} !-d\n";

		$imploded = implode( '|', $exceptions );
		if ( !empty( $imploded ) )
			$rules .= "    RewriteCond %{REQUEST_URI} !(" . $imploded. ")\n";

		$rules .= "    RewriteCond %{REQUEST_URI} \\.(" .
			implode( '|', $extensions ) . ")$ [NC]\n";
		$rules .= "    RewriteRule .* - [L]\n";
		$rules .= "</IfModule>\n";

		return $rules;
	}
}
