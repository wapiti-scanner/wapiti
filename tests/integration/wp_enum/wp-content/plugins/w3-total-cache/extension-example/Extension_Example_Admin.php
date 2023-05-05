<?php
namespace W3TCExample;



/**
 * Backend functionality of an extension.
 * This class is loaded only for wp-admin/ requests
 */
class Extension_Example_Admin {
	/**
	 * w3tc_extensions filter handler
	 *
	 * @param array   $extensions array of extension descriptors to fill
	 * @param Config  $config     w3-total-cache configuration
	 * @return array
	 */
	static public function w3tc_extensions( $extensions, $config ) {
		$extensions['example'] = array (
			'name' => 'Example Extension',
			'author' => 'W3 EDGE',
			'description' => __( 'Example extension' ),
			'author_uri' => 'https://www.w3-edge.com/',
			'extension_uri' => 'https://www.w3-edge.com/',
			'extension_id' => 'example',
			'settings_exists' => true,
			'version' => '1.0',
			'enabled' => true,
			'requirements' => '',
			'path' => 'w3-total-cache-example/Extension_Example.php'
		);

		return $extensions;
	}



	/**
	 * Entry point of extension for wp-admin/ requests
	 * Called from Extension_Example.php
	 */
	public function run() {
		// handle settings page of this extension
		add_action( 'w3tc_extension_page_example', array(
				$this,
				'w3tc_extension_page'
			) );

		// get control when configuration is changed by user
		add_action( 'w3tc_config_ui_save', array(
				$this,
				'w3tc_config_ui_save'
			), 10, 2 );

		// Register widget on W3 Total Cache Dashboard page
		add_action( 'w3tc_widget_setup', array(
				$this,
				'w3tc_widget_setup'
			) );

		// get control when extension is deactivated
		add_action( 'w3tc_deactivate_extension_example', array(
				$this, 'w3tc_deactivate_extension' ) );

	}



	/**
	 * Show settings page
	 */
	public function w3tc_extension_page() {
		include dirname( __FILE__ ) . '/Extension_Example_Page_View.php';
	}



	/**
	 * Get control when configuration is changed by user
	 */
	public function w3tc_config_ui_save( $config, $old_config ) {
		if ( $config->get( array( 'example', 'is_title_postfix' ) ) !=
			$old_config->get( array( 'example', 'is_title_postfix' ) ) ||
			$config->get( array( 'example', 'title_postfix' ) ) !=
			$old_config->get( array( 'example', 'title_postfix' ) ) ) {
			// flush all content caches, since our extension will now alter
			// content
			w3tc_flush_posts();
		}
	}



	/**
	 * Registers widget on W3 Total Cache Dashboard page
	 */
	public function w3tc_widget_setup() {
		$screen = get_current_screen();
		add_meta_box( 'example', 'example', array( $this, 'widget_content' ),
			$screen, 'normal', 'core' );
	}



	/**
	 * Renders content of widget
	 */
	public function widget_content() {
		echo "Example extension's widget";
	}



	/**
	 * Called when extension is deactivated.
	 * Perform a cleanup here
	 */
	public function w3tc_deactivate_extension() {
	}
}
