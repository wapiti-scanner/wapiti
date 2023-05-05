<?php
namespace W3TC;



class Extension_FragmentCache_Page {
	function render_content() {
		$config = Dispatcher::config();
		$core = Dispatcher::component( 'Extension_FragmentCache_Core' );

		$registered_groups = $core->get_registered_fragment_groups();
		include W3TC_DIR . '/Extension_FragmentCache_Page_View.php';
	}
}
