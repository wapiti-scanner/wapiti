<?php
namespace W3TC;



class Cdnfsd_Util {
	static public function engine_name( $engine ) {
		return $engine;
	}



	static public function get_suggested_home_ip() {
		$ip = gethostbyname( Util_Environment::home_url_host() );

		// check if it resolves to local IP, means host cant know its real IP
		if ( substr( $ip, 0, 4 ) == '127.' ||
			substr( $ip, 0, 3 ) == '10.' ||
			substr( $ip, 0, 8 ) == '192.168.' )
			return '';

		return $ip;
	}
}
