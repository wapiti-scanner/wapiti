<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Jetpack modules list table.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Jetpack modules list table.
 */
class Jetpack_Modules_List_Table extends WP_List_Table {

	/** Constructor. */
	public function __construct() {
		parent::__construct();

		Jetpack::init();

		if ( $this->compat_fields && is_array( $this->compat_fields ) ) {
			array_push( $this->compat_fields, 'all_items' );
		}

		/**
		 * Filters the list of modules available to be displayed in the Jetpack Settings screen.
		 *
		 * @since 3.0.0
		 *
		 * @param array $modules Array of Jetpack modules.
		 */
		$this->all_items       = apply_filters( 'jetpack_modules_list_table_items', Jetpack_Admin::init()->get_modules() );
		$this->items           = $this->all_items;
		$this->items           = $this->filter_displayed_table_items( $this->items );
		$this->_column_headers = array( $this->get_columns(), array(), array(), 'name' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce: This is a view, not a model or controller. InputNotSanitized: Sanitized below via `$this->module_info_check()`.
		$modal_info = isset( $_GET['info'] ) ? wp_unslash( $_GET['info'] ) : false;

		// Adding in a hidden h1 heading for screen-readers.
		?>
		<h1 class="screen-reader-text"><?php esc_html_e( 'Jetpack Modules List', 'jetpack' ); ?></h1>
		<?php

		wp_register_script(
			'models.jetpack-modules',
			Assets::get_file_url_for_environment(
				'_inc/build/jetpack-modules.models.min.js',
				'_inc/jetpack-modules.models.js'
			),
			array( 'jquery', 'backbone', 'underscore' ),
			JETPACK__VERSION,
			false // @todo Can this be put in the footer?
		);
		wp_register_script(
			'views.jetpack-modules',
			Assets::get_file_url_for_environment(
				'_inc/build/jetpack-modules.views.min.js',
				'_inc/jetpack-modules.views.js'
			),
			array( 'jquery', 'backbone', 'underscore', 'wp-util' ),
			JETPACK__VERSION,
			false // @todo Can this be put in the footer?
		);
		wp_register_script(
			'jetpack-modules-list-table',
			Assets::get_file_url_for_environment(
				'_inc/build/jetpack-modules.min.js',
				'_inc/jetpack-modules.js'
			),
			array(
				'views.jetpack-modules',
				'models.jetpack-modules',
				'jquery',
			),
			JETPACK__VERSION,
			true
		);

		wp_localize_script(
			'jetpack-modules-list-table',
			'jetpackModulesData',
			array(
				'modules'   => Jetpack::get_translated_modules( $this->all_items ),
				'i18n'      => array(
					'search_placeholder' => __( 'Search Modules…', 'jetpack' ),
				),
				'modalinfo' => $this->module_info_check( $modal_info, $this->all_items ),
				'nonces'    => array(
					'bulk' => wp_create_nonce( 'bulk-jetpack_page_jetpack_modules' ),
				),
			)
		);

		wp_enqueue_script( 'jetpack-modules-list-table' );

		/**
		 * Filters the js_templates callback value.
		 *
		 * @since 3.6.0
		 *
		 * @param array array( $this, 'js_templates' ) js_templates callback.
		 */
		add_action( 'admin_footer', apply_filters( 'jetpack_modules_list_table_js_template_callback', array( $this, 'js_templates' ) ), 9 );
	}

	/**
	 * Output row template.
	 */
	public function js_templates() {
		?>
		<script type="text/html" id="tmpl-Jetpack_Modules_List_Table_Template">
			<# var i = 0;
			if ( data.items.length ) {
			_.each( data.items, function( item, key, list ) {
				if ( item === undefined ) return; #>
				<tr class="jetpack-module <# if ( ++i % 2 ) { #> alternate<# } #><# if ( item.activated ) { #> active<# } #><# if ( ! item.available ) { #> unavailable<# } #>" id="{{{ item.module }}}">
					<th scope="row" class="check-column">
						<input type="checkbox" name="modules[]" value="{{{ item.module }}}" />
					</th>
					<td class='name column-name'>
						<span class='info'><a href="{{{item.learn_more_button}}}" target="blank">{{{ item.name }}}</a></span>
						<div class="row-actions">
						<# if ( item.configurable ) { #>
							<span class='configure'>{{{ item.configurable }}}</span>
						<# } #>
						<# if ( item.activated && 'vaultpress' !== item.module && item.available ) { #>
							<span class='delete'><a href="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>?page=jetpack&#038;action=deactivate&#038;module={{{ item.module }}}&#038;_wpnonce={{{ item.deactivate_nonce }}}"><?php esc_html_e( 'Deactivate', 'jetpack' ); ?></a></span>
						<# } else if ( item.available ) { #>
							<span class='activate'><a href="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>?page=jetpack&#038;action=activate&#038;module={{{ item.module }}}&#038;_wpnonce={{{ item.activate_nonce }}}"><?php esc_html_e( 'Activate', 'jetpack' ); ?></a></span>
						<# } #>
						<# if ( ! item.available ) { #>
							<span class='unavailable_reason'>{{{ item.unavailable_reason }}}</span>
						<# } #>
						</div>
					</td>
				</tr>
				<#
			});
			} else {
				#>
				<tr class="no-modules-found">
					<td colspan="2"><?php esc_html_e( 'No Modules Found', 'jetpack' ); ?></td>
				</tr>
				<#
			}
			#>
		</script>
		<?php
	}

	/**
	 * Get views data.
	 *
	 * @return array Maps identifier to display HTML.
	 */
	public function get_views() {
		/** This filter is already documented in class.jetpack-modules-list-table.php */
		$modules              = apply_filters( 'jetpack_modules_list_table_items', Jetpack_Admin::init()->get_modules() );
		$array_of_module_tags = wp_list_pluck( $modules, 'module_tags' );
		$module_tags          = array_merge( ...array_values( $array_of_module_tags ) );
		$module_tags          = array_map( 'jetpack_get_module_i18n_tag', $module_tags );
		$module_tags_unique   = array_count_values( $module_tags );
		ksort( $module_tags_unique );

		$format = '<a href="%3$s"%4$s data-title="%1$s">%1$s <span class="count">(%2$s)</span></a>';
		$title  = __( 'All', 'jetpack' );
		$count  = count( $modules );
		$url    = esc_url( remove_query_arg( 'module_tag' ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a view, not a model or controller.
		$current = empty( $_GET['module_tag'] ) ? ' class="current all"' : ' class="all"';
		$views   = array(
			'all' => sprintf( $format, $title, $count, $url, $current ),
		);
		foreach ( $module_tags_unique as $title => $count ) {
			$key           = sanitize_title( $title );
			$display_title = esc_html( wptexturize( $title ) );
			$url           = esc_url( add_query_arg( 'module_tag', rawurlencode( $title ) ) );
			$current       = '';
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a view, not a model or controller.
			if ( ! empty( $_GET['module_tag'] ) && $title === $_GET['module_tag'] ) {
				$current = ' class="current"';
			}
			$views[ $key ] = sprintf( $format, $display_title, $count, $url, $current );
		}
		return $views;
	}

	/**
	 * Output views HTML.
	 */
	public function views() {
		$views = $this->get_views();

		echo "<ul class='subsubsub'>\n";
		foreach ( $views as $class => $view ) {
			$views[ $class ] = "\t<li class='$class'>$view</li>";
		}
		echo implode( "\n", $views ) . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Is HTML. Escaping happens in get_views().
		echo '</ul>';
	}

	/**
	 * Filter a modules array for displayed items.
	 *
	 * @param array $modules Modules.
	 * @return array Displayed modules.
	 */
	public function filter_displayed_table_items( $modules ) {
		return array_filter( $modules, array( $this, 'is_module_displayed' ) );
	}

	/**
	 * Determine if a module is displayed.
	 *
	 * @param array $module Module data.
	 * @return bool
	 */
	public static function is_module_displayed( $module ) {
		// Handle module tag based filtering.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a view, not a model or controller.
		if ( ! empty( $_REQUEST['module_tag'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a view, not a model or controller.
			$module_tag = sanitize_text_field( wp_unslash( $_REQUEST['module_tag'] ) );
			if ( ! in_array( $module_tag, array_map( 'jetpack_get_module_i18n_tag', $module['module_tags'] ), true ) ) {
				return false;
			}
		}

		// If nothing rejected it, include it!
		return true;
	}

	/**
	 * Sort callback to put modules with `requires_connection` last.
	 *
	 * @param array $module1 Module data.
	 * @param array $module2 Module data.
	 * @return int Indicating the relative ordering of module1 and module2.
	 */
	public static function sort_requires_connection_last( $module1, $module2 ) {
		if ( (bool) $module1['requires_connection'] === (bool) $module2['requires_connection'] ) {
			return 0;
		}
		if ( $module1['requires_connection'] ) {
			return 1;
		}
		if ( $module2['requires_connection'] ) {
			return -1;
		}

		return 0;
	}

	/**
	 * Get table columns.
	 *
	 * @return string[] Column name to header HTML.
	 */
	public function get_columns() {
		$columns = array(
			'cb'   => '<input type="checkbox" />',
			'name' => __( 'Name', 'jetpack' ),
		);
		return $columns;
	}

	/**
	 * Get bulk actions for the table.
	 *
	 * @return string[] Actions, code => text.
	 */
	public function get_bulk_actions() {
		$actions = array(
			'bulk-activate'   => __( 'Activate', 'jetpack' ),
			'bulk-deactivate' => __( 'Deactivate', 'jetpack' ),
		);
		return $actions;
	}

	/**
	 * Print a single row of the table.
	 *
	 * @param object|array $item Item.
	 */
	public function single_row( $item ) {
		static $i  = 0;
		$row_class = ( ( ++$i ) % 2 ) ? ' alternate' : '';

		if ( ! empty( $item['activated'] ) ) {
			$row_class .= ' active';
		}

		if ( ! Jetpack_Admin::is_module_available( $item ) ) {
			$row_class .= ' unavailable';
		}

		echo '<tr class="jetpack-module' . esc_attr( $row_class ) . '" id="' . esc_attr( $item['module'] ) . '">';
		$this->single_row_columns( $item );
		echo '</tr>';
	}

	/**
	 * Table classes.
	 *
	 * @return string[] HTML.
	 */
	public function get_table_classes() {
		return array( 'table', 'table-bordered', 'wp-list-table', 'widefat', 'fixed', 'jetpack-modules' );
	}

	/**
	 * Column checkbox.
	 *
	 * @param object|array $item Item.
	 * @return string HTML.
	 */
	public function column_cb( $item ) {
		if ( ! Jetpack_Admin::is_module_available( $item ) ) {
			return '';
		}

		return sprintf( '<input type="checkbox" name="modules[]" value="%s" />', $item['module'] );
	}

	/**
	 * Column icon.
	 *
	 * @return string HTML.
	 */
	public function column_icon() {
		$badge_text = '';
		$free_text  = '';
		ob_start();
		?>
		<a href="#TB_inline?width=600&height=550&inlineId=more-info-module-settings-modal" class="thickbox">
			<div class="module-image">
				<p><span class="module-image-badge"><?php echo esc_html( $badge_text ); ?></span><span class="module-image-free" style="display: none"><?php echo esc_html( $free_text ); ?></span></p>
			</div>
		</a>
		<?php
		return ob_get_clean();
	}

	/**
	 * Column name.
	 *
	 * @param object|array $item Item.
	 * @return string HTML.
	 */
	public function column_name( $item ) {
		$actions = array(
			'info' => sprintf( '<a href="%s" target="blank">%s</a>', esc_url( $item['learn_more_button'] ), esc_html__( 'Feature Info', 'jetpack' ) ),
		);

		if ( ! empty( $item['configurable'] ) ) {
			$actions['configure'] = $item['configurable'];
		}

		if ( empty( $item['activated'] ) && Jetpack_Admin::is_module_available( $item ) ) {
			$url                 = wp_nonce_url(
				Jetpack::admin_url(
					array(
						'page'   => 'jetpack',
						'action' => 'activate',
						'module' => $item['module'],
					)
				),
				'jetpack_activate-' . $item['module']
			);
			$actions['activate'] = sprintf( '<a href="%s">%s</a>', esc_url( $url ), esc_html__( 'Activate', 'jetpack' ) );
		} elseif ( ! empty( $item['activated'] ) ) {
			$url               = wp_nonce_url(
				Jetpack::admin_url(
					array(
						'page'   => 'jetpack',
						'action' => 'deactivate',
						'module' => $item['module'],
					)
				),
				'jetpack_deactivate-' . $item['module']
			);
			$actions['delete'] = sprintf( '<a href="%s">%s</a>', esc_url( $url ), esc_html__( 'Deactivate', 'jetpack' ) );
		}

		return $this->row_actions( $actions ) . wptexturize( $item['name'] );
	}

	/**
	 * Column description.
	 *
	 * @param object|array $item Item.
	 * @return string HTML.
	 */
	public function column_description( $item ) {
		ob_start();
		// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped
		/** This action is documented in class.jetpack-admin.php */
		echo apply_filters( 'jetpack_short_module_description', $item['description'], $item['module'] );
		/** This action is documented in class.jetpack-admin.php */
		do_action( 'jetpack_learn_more_button_' . $item['module'] );
		echo '<div id="more-info-' . $item['module'] . '" class="more-info">';
		/** This action is documented in class.jetpack-admin.php */
		do_action( 'jetpack_module_more_info_' . $item['module'] );
		echo '</div>';
		// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
		return ob_get_clean();
	}

	/**
	 * Return module tags HTML.
	 *
	 * @param object|array $item Item.
	 * @return string HTML.
	 */
	public function column_module_tags( $item ) {
		$module_tags = array();
		foreach ( array_map( 'jetpack_get_module_i18n_tag', $item['module_tags'] ) as $module_tag ) {
			$module_tags[] = sprintf( '<a href="%3$s" data-title="%2$s">%1$s</a>', esc_html( $module_tag ), esc_attr( $module_tag ), esc_url( add_query_arg( 'module_tag', rawurlencode( $module_tag ) ) ) );
		}
		return implode( ', ', $module_tags );
	}

	/**
	 * Column default value.
	 *
	 * @param object|array $item Item.
	 * @param string       $column_name Column name.
	 * @return string
	 */
	public function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'icon':
			case 'name':
			case 'description':
				return '';
			default:
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r
				return print_r( $item, true );
		}
	}

	/**
	 * Check if the info parameter provided in the URL corresponds to an actual module.
	 *
	 * @param string|false $info Info parameter.
	 * @param array        $modules Modules array.
	 * @return string|false
	 */
	public function module_info_check( $info, $modules ) {
		if ( ! $info ) {
			return false;
		} elseif ( array_key_exists( $info, $modules ) ) {
			return $info;
		}
	}

	/**
	 * Core switched their `display_tablenav()` method to protected, so we can't access it directly.
	 * Instead, let's include an access function to make it doable without errors!
	 *
	 * @see https://github.com/WordPress/WordPress/commit/d28f6344de97616de8ece543ed290c4ba2383622
	 *
	 * @param string $which Which nav table to display.
	 * @return mixed
	 */
	public function unprotected_display_tablenav( $which = 'top' ) {
		return $this->display_tablenav( $which );
	}

}
