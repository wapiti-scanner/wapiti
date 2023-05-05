<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/popup/common/header.php'; ?>

<p>
	<?php
	echo wp_kses(
		sprintf(
			// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
			__(
				'Remove objects from the %1$sCDN%2$s by specifying the relative path on individual lines below and clicking the "Purge" button when done. For example:',
				'w3-total-cache'
			),
			'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
			'</acronym>'
		),
		array(
			'acronym' => array(
				'title' => array(),
			),
		)
	);
	?>
</p>
<p>
	<?php
	switch ( $this->_config->get_string( 'cdn.engine' ) ) :
		case 'cotendo':
			?>
			<ul>
				<li><em><?php echo esc_url( $path ); ?>/images/headers/</em> &mdash; <?php esc_html_e( 'the directory itself (only when accessed directly without any file).', 'w3-total-cache' ); ?></li>
				<li><em><?php echo esc_url( $path ); ?>/images/headers/*.</em> &mdash; <?php esc_html_e( 'all files in the directory with no extension, with all parameter variations.', 'w3-total-cache' ); ?></li>
				<li><em><?php echo esc_url( $path ); ?>/images/headers/*.jpg</em> &mdash; <?php esc_html_e( 'all files in the directory whose extension is "jpg".', 'w3-total-cache' ); ?></li>
				<li><em><?php echo esc_url( $path ); ?>/images/headers/path</em> &mdash; <?php esc_html_e( 'the specific file (when the file does not have an extension), and without parameters.', 'w3-total-cache' ); ?></li>
				<li><em><?php echo esc_url( $path ); ?>/images/headers/path.jpg</em> &mdash; <?php esc_html_e( 'the specific file with its extension, and without parameters.', 'w3-total-cache' ); ?></li>
				<li><em><?php echo esc_url( $path ); ?>/images/headers/path.jpg?*</em> &mdash; <?php esc_html_e( 'the specific file with its extension, with all variation of parameters.', 'w3-total-cache' ); ?></li>
				<li><em><?php echo esc_url( $path ); ?>/images/headers/path.jpg?key=value</em> &mdash; <?php esc_html_e( 'the specific file with its extension, with the specific parameters.', 'w3-total-cache' ); ?></li>
			</ul>
			<?php
			break;

		default:
			?>
			<em><?php echo esc_url( $path ); ?>/images/headers/path.jpg</em>
			<?php
			break;
	endswitch;
	?>
</p>


<form action="admin.php?page=w3tc_cdn" method="post">
	<p><?php esc_html_e( 'Files to purge:', 'w3-total-cache' ); ?></p>
	<p>
		<textarea name="files" rows="10" cols="90"></textarea>
	</p>
	<p>
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
		<input class="button-primary" type="submit" name="w3tc_cdn_purge_files" value="<?php esc_attr_e( 'Purge', 'w3-total-cache' ); ?>" />
	</p>
</form>

<div class="log">
	<?php foreach ( $results as $result ) : ?>
		<div class="log-<?php echo W3TC_CDN_RESULT_OK === $result['result'] ? 'success' : 'error'; ?>">
			<?php echo esc_html( $result['remote_path'] ); ?>
			<strong><?php echo esc_html( $result['error'] ); ?></strong>
		</div>
	<?php endforeach; ?>
</div>

<?php require W3TC_INC_DIR . '/popup/common/footer.php'; ?>
