<?php
namespace W3TCExample;



class Extension_Example {
	/**
	 * W3 Total cache config
	 */
	private $config;



	/**
	 * Runs extension
	 */
	function run() {
		// obtain w3tc config
		$this->config = w3tc_config();

		// get value of config option and use it
		if ( $this->config->get_boolean( array( 'example' , 'is_title_postfix' ) ) )
			add_filter( 'the_title', array( $this, 'the_title' ), 10, 2 );
	}



	/**
	 * the_title filter handler.
	 * This extension adds specified postfix to each post title if extensions
	 * is configured so on its settings page
	 */
	public function the_title( $title, $id ) {
		return $title .
			$this->config->get_string( array( 'example' , 'title_postfix' ) );
	}
}



/*
This file is simply loaded by W3 Total Cache in a case if extension is active.
Its up to extension what will it do or which way will it do.
*/
$p = new Extension_Example();
$p->run();

if ( is_admin() ) {
	$p = new Extension_Example_Admin();
	$p->run();
}
