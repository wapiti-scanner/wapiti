<?php
namespace W3TC;

class UserExperience_Plugin_Admin {
	function run() {
		add_filter( 'w3tc_admin_menu', array( $this, 'w3tc_admin_menu' ) );
		add_action( 'w3tc_settings_page-w3tc_userexperience',
			array( $this, 'w3tc_settings_page_w3tc_userexperience' ) );
		add_action( 'admin_init_w3tc_general',
			array( '\W3TC\UserExperience_GeneralPage', 'admin_init_w3tc_general' ) );
		add_filter( 'w3tc_extensions', array(
				'\W3TC\UserExperience_Plugin_Admin',
				'w3tc_extensions' ),
			10, 2 );

	}



	public function w3tc_admin_menu( $menu ) {
		$c = Dispatcher::config();

		$menu['w3tc_userexperience'] = array(
			'page_title' => __( 'User Experience', 'w3-total-cache' ),
			'menu_text' => __( 'User Experience', 'w3-total-cache' ),
			'visible_always' => false,
			'order' => 1200
		);

		return $menu;
	}



	static public function w3tc_extensions( $extensions, $config ) {
		$extensions['user-experience-emoji'] = array(
			'public' => false,
			'extension_id' => 'user-experience-emoji',
			'path' => 'w3-total-cache/UserExperience_Emoji_Extension.php'
		);
		$extensions['user-experience-oembed'] = array(
			'public' => false,
			'extension_id' => 'user-experience-oembed',
			'path' => 'w3-total-cache/UserExperience_OEmbed_Extension.php'
		);

		return $extensions;
	}



	public function w3tc_settings_page_w3tc_userexperience() {
		$v = new UserExperience_Page();
		$v->render_content();
	}
}
