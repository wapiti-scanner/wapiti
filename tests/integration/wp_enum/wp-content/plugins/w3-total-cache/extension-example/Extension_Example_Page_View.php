<?php
namespace W3TCExample;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<p>
	<?php esc_html_e( 'Jump to:', 'w3-total-cache' ); ?>
	<a href="admin.php?page=w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
	<a href="admin.php?page=w3tc_extensions"><?php esc_html_e( 'Extensions', 'w3-total-cache' ); ?></a>
</p>
<p><?php esc_html_e( 'Example extension is currently ', 'w3-total-cache' ); ?><span class="w3tc-enabled"><?php esc_html_e( 'enabled', 'w3-total-cache' ); ?></span></p>

<div class="metabox-holder">
<?php
// render settings box header.
\W3TC\Util_Ui::postbox_header( 'Example extension' );
?>
<table class="form-table">
	<?php
	// render controls showing content of w3tc configuration options.
	\W3TC\Util_Ui::config_item(
		array(
			'key'            => array( 'example', 'is_title_postfix' ),
			'control'        => 'checkbox',
			'label'          => __( 'Add postfix to page titles', 'w3-total-cache' ),
			'checkbox_label' => __( 'Enable', 'w3-total-cache' ),
			'description'    => __( 'Check if you want to add postfix to each post title.', 'w3-total-cache' ),
		)
	);
	\W3TC\Util_Ui::config_item(
		array(
			'key'     => array( 'example', 'title_postfix' ),
			'control' => 'textbox',
			'label'   => __( 'Postfix to page titles', 'w3-total-cache' ),
		)
	);
	?>
</table>
<?php
// render save button for ::config_item controls.
\W3TC\Util_Ui::button_config_save( 'extension_example' );
// render settings box footer.
\W3TC\Util_Ui::postbox_footer();
?>
</div>
