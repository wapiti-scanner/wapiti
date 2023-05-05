<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<p id="w3tc-options-menu">
	<?php esc_html_e( 'Jump to:', 'w3-total-cache' ); ?>
	<a href="admin.php?page=w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
	<a href="admin.php?page=w3tc_extensions"><?php esc_html_e( 'Extensions', 'w3-total-cache' ); ?></a> |
	<a href="#header"><?php esc_html_e( 'Header', 'w3-total-cache' ); ?></a> |
	<a href="#content"><?php esc_html_e( 'Content', 'w3-total-cache' ); ?></a> |
	<a href="#sidebar"><?php esc_html_e( 'Sidebar', 'w3-total-cache' ); ?></a> |
	<a href="#exclusions"><?php esc_html_e( 'Exclusions', 'w3-total-cache' ); ?></a>
</p>
<p>
	<?php esc_html_e( 'Genesis extension is currently ', 'w3-total-cache' ); ?>
	<?php
	if ( $config->is_extension_active_frontend( 'genesis.theme' ) ) {
		echo '<span class="w3tc-enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) . '</span>';
	} else {
		echo '<span class="w3tc-disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) . '</span>';
	}
	?>
	.
<p>

<div class="metabox-holder">
	<?php Util_Ui::postbox_header( esc_html__( 'Header', 'w3-total-cache' ), '', 'header' ); ?>
	<table class="form-table">
		<?php
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'wp_head' ),
				'control'        => 'checkbox',
				'label'          => esc_html__( 'Cache wp_head loop:', 'w3-total-cache' ),
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'description'    => esc_html__( 'Cache wp_head. This includes the embedded CSS, JS etc.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'genesis_header' ),
				'control'        => 'checkbox',
				'label'          => esc_html__( 'Cache header:', 'w3-total-cache' ),
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'description'    => esc_html__( 'Cache header loop. This is the area where the logo is located.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'genesis_do_nav' ),
				'control'        => 'checkbox',
				'label'          => esc_html__( 'Cache primary navigation:', 'w3-total-cache' ),
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches the navigation filter; per page.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'genesis_do_subnav' ),
				'control'        => 'checkbox',
				'label'          => esc_html__( 'Cache secondary navigation:', 'w3-total-cache' ),
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches secondary navigation filter; per page.', 'w3-total-cache' ),
			)
		);
		?>
	</table>
	<?php Util_Ui::button_config_save( 'extension_genesis_header' ); ?>
	<?php Util_Ui::postbox_footer(); ?>

	<?php Util_Ui::postbox_header( esc_html__( 'Content', 'w3-total-cache' ), '', 'content' ); ?>
	<table class="form-table">
		<?php
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'loop_front_page' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Cache front page post loop:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches the front page post loop, pagination is supported.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'loop_terms' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Cache author/tag/categories/term post loop:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches the posts listed on tag, categories, author and other term pages, pagination is supported.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'         => array( 'genesis.theme', 'loop_terms_excluded' ),
				'control'     => 'textarea',
				'label'       => esc_html__( 'Excluded terms pages / posts:', 'w3-total-cache' ),
				'description' => esc_html__( 'List of pages / posts that should not have the terms loop cached. Specify one page / post per line. This area supports regular expressions.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'flush_terms' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Flush posts loop:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Flushes the posts loop cache on post updates. See setting above for affected loops.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'loop_single' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Cache single post / page:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches the single post / page loop, pagination is supported.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'         => array( 'genesis.theme', 'loop_single_excluded' ),
				'control'     => 'textarea',
				'label'       => esc_html__( 'Excluded single pages / posts:', 'w3-total-cache' ),
				'description' => esc_html__( 'List of pages / posts that should not have the single post / post loop cached. Specify one page / post per line. This area supports regular expressions.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'loop_single_genesis_comments' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Cache comments:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches the comments loop, pagination is supported.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'loop_single_genesis_pings' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Cache pings:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches the ping loop, pagination is supported. One per line.', 'w3-total-cache' ),
			)
		);
		?>
	</table>
	<?php Util_Ui::button_config_save( 'extension_genesis_content' ); ?>
	<?php Util_Ui::postbox_footer(); ?>

	<?php Util_Ui::postbox_header( esc_html__( 'Sidebar', 'w3-total-cache' ), '', 'sidebar' ); ?>
	<table class="form-table">
		<?php
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'sidebar' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Cache sidebar:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches sidebar loop, the widget area.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'         => array( 'genesis.theme', 'sidebar_excluded' ),
				'control'     => 'textarea',
				'label'       => esc_html__( 'Exclude pages:', 'w3-total-cache' ),
				'description' => esc_html__( 'List of pages that should not have sidebar cached. Specify one page / post per line. This area supports regular expressions.', 'w3-total-cache' ),
			)
		);
		?>
	</table>
	<?php Util_Ui::button_config_save( 'extension_genesis_sidebar' ); ?>
	<?php Util_Ui::postbox_footer(); ?>

	<?php Util_Ui::postbox_header( esc_html__( 'Footer', 'w3-total-cache' ) ); ?>
	<table class="form-table">
		<?php
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'genesis_footer' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Cache genesis footer:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches footer loop.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'wp_footer' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Cache footer:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Caches wp_footer loop.', 'w3-total-cache' ),
			)
		);
		Util_Ui::config_item(
			array(
				'key'            => array( 'genesis.theme', 'reject_logged_roles' ),
				'control'        => 'checkbox',
				'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
				'label'          => esc_html__( 'Disable fragment cache:', 'w3-total-cache' ),
				'description'    => esc_html__( 'Don\'t use fragment cache with the following hooks and for the specified user roles.' ),
			)
		);
		?>
	</table>
	<?php Util_Ui::button_config_save( 'extension_genesis_footer' ); ?>
	<?php Util_Ui::postbox_footer(); ?>

	<?php Util_Ui::postbox_header( esc_html__( 'Exclusions', 'w3-total-cache' ), '', 'exclusions' ); ?>
	<table class="form-table">
		<tr>
			<td><?php esc_html_e( 'Select hooks', 'w3-total-cache' ); ?></td>
			<td>
				<?php
				$saved_hooks = $config->get_array( array( 'genesis.theme', 'reject_logged_roles_on_actions' ) );
				$name        = Util_Ui::config_key_to_http_name( array( 'genesis.theme', 'reject_logged_roles_on_actions' ) );
				$hooks       = array(
					'genesis_header'    => esc_html__( 'Header', 'w3-total-cache' ),
					'genesis_footer'    => esc_html__( 'Footer', 'w3-total-cache' ),
					'genesis_sidebar'   => esc_html__( 'Sidebar', 'w3-total-cache' ),
					'genesis_loop'      => esc_html__( 'The Loop', 'w3-total-cache' ),
					'wp_head'           => 'wp_head',
					'wp_footer'         => 'wp_footer',
					'genesis_comments'  => esc_html__( 'Comments', 'w3-total-cache' ),
					'genesis_pings'     => esc_html__( 'Pings', 'w3-total-cache' ),
					'genesis_do_nav'    => esc_html__( 'Primary navigation', 'w3-total-cache' ),
					'genesis_do_subnav' => esc_html__( 'Secondary navigation', 'w3-total-cache' ),
				);
				?>

				<input <?php disabled( $config->is_sealed( 'genesis.theme' ) ); ?> type="hidden" name="<?php echo esc_attr( $name ); ?>" value="" />
				<?php foreach ( $hooks as $hook => $hook_label ) : ?>
					<input <?php disabled( $config->is_sealed( 'genesis.theme' ) ); ?> 
						type="checkbox" name="<?php echo esc_attr( $name ); ?>[]"
						value="<?php echo esc_attr( $hook ); ?>"
						<?php checked( in_array( $hook, $saved_hooks, true ) ); ?>
						id="role_<?php echo esc_attr( $hook ); ?>" />
					<label for="role_<?php echo esc_attr( $hook ); ?>">
						<?php echo esc_html( $hook_label ); ?>
					</label><br />
				<?php endforeach; ?>

				<p class="description">
					<?php esc_html_e( 'Select hooks from the list that should not be cached if user belongs to any of the roles selected below.', 'w3-total-cache' ); ?>
				</p>
			</td>
		</tr>
		<tr>
			<td><?php esc_html_e( 'Select roles:', 'w3-total-cache' ); ?></td>
			<td>
				<?php
				$saved_roles = $config->get_array( array( 'genesis.theme', 'reject_roles' ) );
				$name        = Util_Ui::config_key_to_http_name( array( 'genesis.theme', 'reject_roles' ) );
				?>
				<input type="hidden" name="<?php echo esc_attr( $name ); ?>" value="" />
				<?php foreach ( get_editable_roles() as $role_name => $role_data ) : ?>
					<input <?php disabled( $config->is_sealed( 'genesis.theme' ) ); ?>
						type="checkbox" name="<?php echo esc_attr( $name ); ?>[]"
						value="<?php echo esc_attr( $role_name ); ?>"
						<?php checked( in_array( $role_name, $saved_roles, true ) ); ?>
						id="role_<?php echo esc_attr( $role_name ); ?>" />
					<label for="role_<?php echo esc_attr( $role_name ); ?>">
						<?php echo esc_html( $role_data['name'] ); ?>
					</label>
				<?php endforeach; ?>
				<p class="description">
					<?php esc_html_e( 'Select user roles that should not use the fragment cache.', 'w3-total-cache' ); ?>
				</p>
			</td>
		</tr>
	</table>
	<?php Util_Ui::button_config_save( 'extension_genesis_exclusions' ); ?>
	<?php Util_Ui::postbox_footer(); ?>

</div>
