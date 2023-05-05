<?php
namespace W3TC;



class Generic_Page_PurgeLog {
	private $plugins_regexp = null;



	public function __construct() {
		$p = dirname( dirname( __FILE__ ) );
		if ( $this->starts_with( $p, ABSPATH ) ) {
			$p = substr( $p, strlen( ABSPATH ) );
		}

		$this->plugins_regexp = '~^(' . Util_Environment::preg_quote( $p ) .
			'/)([^/]+)(.*)~';
	}



	public function render_content() {
		$module = Util_Request::get_label( 'module' );
		$log_filename = Util_Debug::log_filename( $module . '-purge' );
		if ( file_exists( $log_filename ) ) {
			$log_filefize = $this->to_human( filesize( $log_filename ) );
		} else {
			$log_filefize = 'n/a';
		}

		$lines = Util_DebugPurgeLog_Reader::read( $module );

		$purgelog_modules = array();
		$c = Dispatcher::config();
		if ( $c->get_boolean( 'pgcache.debug_purge' ) ) {
			$purgelog_modules[] = array(
				'label' => 'pagecache',
				'name' => 'Page Cache',
				'postfix' => ''
			);
		}
		if ( $c->get_boolean( 'dbcache.debug_purge' ) ) {
			$purgelog_modules[] = array(
				'label' => 'dbcache',
				'name' => 'Database Cache',
				'postfix' => ''
			);
		}
		if ( $c->get_boolean( 'objectcache.debug_purge' ) ) {
			$purgelog_modules[] = array(
				'label' => 'objectcache',
				'name' => 'Object Cache',
				'postfix' => ''
			);
		}

		for ( $n = 0; $n < count( $purgelog_modules ) - 1; $n++ ) {
			$purgelog_modules[$n]['postfix'] = '|';
		}

		require( __DIR__ . '/Generic_Page_PurgeLog_View.php' );
	}



	private function to_human($bytes, $decimals = 2) {
		$size = array('B','kB','MB','GB','TB','PB','EB','ZB','YB');
		$factor = floor((strlen($bytes) - 1) / 3);
		return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$size[$factor];
	}



	private function starts_with( $s, $prefix ) {
		return substr( $s, 0, strlen( $prefix ) ) == $prefix;
	}



	private function esc_filename( $filename ) {
		$m = null;
		if ( preg_match( $this->plugins_regexp, $filename, $m ) ) {
			return esc_html( $m[1] ) .
				'<strong>' . esc_html( $m[2] ) . '</strong>' .
				esc_html( $m[3] );
		}

		return esc_html( $filename );
	}
}
