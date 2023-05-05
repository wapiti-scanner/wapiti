<?php
namespace W3TC;

class UserExperience_Page {
	public function render_content() {
		$c = Dispatcher::config();
		include  W3TC_DIR . '/UserExperience_Page_View.php';
	}
}
