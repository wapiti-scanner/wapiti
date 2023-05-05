<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Database Cluster Configuration File', 'w3-total-cache' ) ); ?>
		<table class="form-table">
			<tr>
				<th>
					<textarea cols="70" rows="25" style="width: 100%"
						name="newcontent" id="newcontent"
						tabindex="1"><?php echo esc_textarea( $content ); ?></textarea><br />
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML strong tag, 2 closing HTML strong tag.
								__(
									'Note: Changes will have immediate effect on your database configuration. If the application stops working creating the settings file, edit or remove this configuration file manually at %1$s/wp-content/db-cluster-config.php%2$s.',
									'w3-total-cache'
								),
								'<strong>',
								'</strong>'
							),
							array(
								'strong' => array(),
							)
						);
						?>
					</p>
				</th>
			</tr>
		</table>

		<p class="submit">
			<?php
			echo wp_kses(
				Util_Ui::nonce_field( 'w3tc' ),
				array(
					'input' => array(
						'type'  => array(),
						'name'  => array(),
						'value' => array(),
					),
				)
			);
			?>
			<input type="submit" name="w3tc_config_dbcluster_config_save" class="w3tc-button-save button-primary" value="<?php esc_attr_e( 'Save configuration file', 'w3-total-cache' ); ?>" />
		</p>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>

<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
