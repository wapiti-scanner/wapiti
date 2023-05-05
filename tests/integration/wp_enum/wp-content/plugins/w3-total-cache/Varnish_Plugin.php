<?php
namespace W3TC;

/**
 * class Varnish_Plugin
 */
class Varnish_Plugin {
	/**
	 * Runs plugin
	 */
	public function run() {
		Util_AttachToActions::flush_posts_on_actions();

		add_action( 'w3tc_flush_all',
			array( $this, 'varnish_flush' ),
			2000, 1 );
		add_action( 'w3tc_flush_post',
			array( $this, 'varnish_flush_post' ),
			2000, 2 );
		add_action( 'w3tc_flushable_posts', '__return_true', 2000 );
		add_action( 'w3tc_flush_posts',
			array( $this, 'varnish_flush' ),
			2000 );
		add_action( 'w3tc_flush_url',
			array( $this, 'varnish_flush_url' ),
			2000, 1 );

		add_filter( 'w3tc_admin_bar_menu',
			array( $this, 'w3tc_admin_bar_menu' ) );
	}



	/**
	 * Purges varnish cache
	 *
	 * @return mixed
	 */
	public function varnish_flush( $extras = array() ) {
		if ( isset( $extras['only'] ) && $extras['only'] != 'varnish' )
			return;

		$varnishflush = Dispatcher::component( 'Varnish_Flush' );
		$v = $varnishflush->flush();

		return $v;
	}

	/**
	 * Purges post from varnish
	 *
	 * @param integer $post_id Post ID.
	 * @param boolean $force   Force flag (optional).
	 *
	 * @return mixed
	 */
	public function varnish_flush_post( $post_id, $force = false ) {
		$varnishflush = Dispatcher::component( 'Varnish_Flush' );
		$v = $varnishflush->flush_post( $post_id, $force );

		return $v;
	}

	/**
	 * Purges post from varnish
	 *
	 * @param string  $url
	 * @return mixed
	 */
	public function varnish_flush_url( $url ) {
		$varnishflush = Dispatcher::component( 'Varnish_Flush' );
		$v = $varnishflush->flush_url( $url );

		return $v;
	}

	public function w3tc_admin_bar_menu( $menu_items ) {
		$menu_items['20610.varnish'] = array(
			'id' => 'w3tc_flush_varnish',
			'parent' => 'w3tc_flush',
			'title' => __( 'Reverse Proxy', 'w3-total-cache' ),
			'href' => wp_nonce_url( admin_url(
					'admin.php?page=w3tc_dashboard&amp;w3tc_flush_varnish' ),
				'w3tc' )
		);

		return $menu_items;
	}
}
