<?php
namespace W3TC;

class DbCache_ConfigLabels {
	public function config_labels( $config_labels ) {
		return array_merge( $config_labels, array(
				'dbcache.engine' =>  __( 'Database Cache Method:', 'w3-total-cache' ),
				'dbcache.enabled' => __( 'Database Cache:', 'w3-total-cache' ),
				'dbcache.debug' =>  __( 'Database Cache', 'w3-total-cache' ),
				'dbcache.reject.logged' => __( 'Don\'t cache queries for logged in users', 'w3-total-cache' ),
				'dbcache.lifetime' => __( 'Maximum lifetime of cache objects:', 'w3-total-cache' ),
				'dbcache.file.gc' => __( 'Garbage collection interval:', 'w3-total-cache' ),
				'dbcache.reject.uri' => __( 'Never cache the following pages:', 'w3-total-cache' ),
				'dbcache.reject.sql' => __( 'Ignored query stems:', 'w3-total-cache' ),
				'dbcache.reject.words' => __( 'Reject query words:', 'w3-total-cache' )
			) );
	}
}
