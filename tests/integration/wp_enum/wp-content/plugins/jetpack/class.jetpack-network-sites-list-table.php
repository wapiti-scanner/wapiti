<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Jetpack network sites list table.
 *
 * @package automattic/jetpack
 */

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Jetpack network sites list table.
 */
class Jetpack_Network_Sites_List_Table extends WP_List_Table {

	/**
	 * Get columns.
	 *
	 * @return array name => header HTML.
	 */
	public function get_columns() {
		// site name, status, username connected under.
		$columns = array(
			'cb'        => '<input type="checkbox" />',
			'blogname'  => __( 'Site Name', 'jetpack' ),
			'blog_path' => __( 'Path', 'jetpack' ),
			'connected' => __( 'Connected', 'jetpack' ),
		);

		return $columns;
	}

	/**
	 * Prepare items.
	 */
	public function prepare_items() {
		// Make sure Jetpack_Network is initialized.
		Jetpack_Network::init();

		// Deal with bulk actions if any were requested by the user.
		$this->process_bulk_action();

		$sites = get_sites(
			array(
				'site__not_in' => array( get_current_blog_id() ),
				'archived'     => false,
				'number'       => 0,
				'network_id'   => get_current_network_id(),
			)
		);

		// Setup pagination.
		$per_page     = 25;
		$current_page = $this->get_pagenum();
		$total_items  = count( $sites );
		$sites        = array_slice( $sites, ( ( $current_page - 1 ) * $per_page ), $per_page );
		$this->set_pagination_args(
			array(
				'total_items' => $total_items,
				'per_page'    => $per_page,
			)
		);

		$columns               = $this->get_columns();
		$hidden                = array();
		$sortable              = array();
		$this->_column_headers = array( $columns, $hidden, $sortable );
		$this->items           = $sites;
	}

	/**
	 * Column blogname.
	 *
	 * @param object|array $item Item.
	 * @return string HTML.
	 */
	public function column_blogname( $item ) {
		// <http://jpms/wp-admin/network/site-info.php?id=1>.
		switch_to_blog( $item->blog_id );
		$jp_url = admin_url( 'admin.php?page=jetpack' );
		restore_current_blog();

		$actions = array(
			'edit'                      => '<a href="' . esc_url( network_admin_url( 'site-info.php?id=' . $item->blog_id ) ) . '">' . esc_html__( 'Edit', 'jetpack' ) . '</a>',
			'dashboard'                 => '<a href="' . esc_url( get_admin_url( $item->blog_id, '', 'admin' ) ) . '">' . esc_html__( 'Dashboard', 'jetpack' ) . '</a>',
			'view'                      => '<a href="' . esc_url( get_site_url( $item->blog_id, '', 'admin' ) ) . '">' . esc_html__( 'View', 'jetpack' ) . '</a>',
			'jetpack-' . $item->blog_id => '<a href="' . esc_url( $jp_url ) . '">Jetpack</a>',
		);

		return sprintf( '%1$s %2$s', '<strong>' . get_blog_option( $item->blog_id, 'blogname' ) . '</strong>', $this->row_actions( $actions ) );
	}

	/**
	 * Column blog path.
	 *
	 * @param object|array $item Item.
	 * @return string HTML.
	 */
	public function column_blog_path( $item ) {
		return '<a href="' .
			get_site_url( $item->blog_id, '', 'admin' ) .
			'">' .
			str_replace( array( 'http://', 'https://' ), '', get_site_url( $item->blog_id, '', 'admin' ) ) .
			'</a>';
	}

	/**
	 * Column connected.
	 *
	 * @param object|array $item Item.
	 * @return string HTML.
	 */
	public function column_connected( $item ) {
		$jpms = Jetpack_Network::init();
		$jp   = Jetpack::init();

		switch_to_blog( $item->blog_id );

		// Checks for both the stock version of Jetpack and the one managed by the Jetpack Beta Plugin.
		if ( ! is_plugin_active( 'jetpack/jetpack.php' ) && ! is_plugin_active( 'jetpack-dev/jetpack.php' ) ) {
			$title  = __( 'Jetpack is not active on this site.', 'jetpack' );
			$action = array(
				'manage-plugins' => '<a href="' . get_admin_url( $item->blog_id, 'plugins.php', 'admin' ) . '">' . __( 'Manage Plugins', 'jetpack' ) . '</a>',
			);
			restore_current_blog();
			return sprintf( '%1$s %2$s', $title, $this->row_actions( $action ) );
		}

		if ( $jp->is_connection_ready() ) {
			// Build url for disconnecting.
			$url = $jpms->get_url(
				array(
					'name'    => 'subsitedisconnect',
					'site_id' => $item->blog_id,

				)
			);
			restore_current_blog();
			return '<a href="' . wp_nonce_url( $url, 'jetpack-subsite-disconnect' ) . '">' . esc_html__( 'Disconnect', 'jetpack' ) . '</a>';
		}
		restore_current_blog();

		// Build URL for connecting.
		$url = $jpms->get_url(
			array(
				'name'    => 'subsiteregister',
				'site_id' => $item->blog_id,
			)
		);
		return '<a href="' . wp_nonce_url( $url, 'jetpack-subsite-register' ) . '">' . esc_html__( 'Connect', 'jetpack' ) . '</a>';
	}

	/**
	 * Get bulk actions.
	 *
	 * @return array Code => HTML.
	 */
	public function get_bulk_actions() {
		$actions = array(
			'connect'    => esc_html__( 'Connect', 'jetpack' ),
			'disconnect' => esc_html__( 'Disconnect', 'jetpack' ),
		);

		return $actions;
	}

	/**
	 * Column checkbox.
	 *
	 * @param object|array $item Item.
	 * @return string HTML.
	 */
	public function column_cb( $item ) {
			return sprintf(
				'<input type="checkbox" name="bulk[]" value="%s" />',
				$item->blog_id
			);
	}

	/**
	 * Process bulk actions.
	 */
	public function process_bulk_action() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Check if we have anything to do before checking the nonce.
		if ( empty( $_POST['bulk'] ) ) {
			return; // Thou shall not pass! There is nothing to do.
		}

		check_admin_referer( 'bulk-toplevel_page_jetpack-network' );

		$jpms = Jetpack_Network::init();

		$action = $this->current_action();
		switch ( $action ) {

			case 'connect':
				$bulk = wp_unslash( $_POST['bulk'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				foreach ( $bulk as $site ) {
					$jpms->do_subsiteregister( $site );
				}
				break;
			case 'disconnect':
				$bulk = wp_unslash( $_POST['bulk'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				foreach ( $bulk as $site ) {
					$jpms->do_subsitedisconnect( $site );
				}
				break;
		}
	}
} // end h
