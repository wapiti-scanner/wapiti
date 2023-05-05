<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$api_key = $config->get_string( 'cdn.limelight.api_key' );
?>
<tr>
	<th style="width: 300px;"><label><?php esc_html_e( 'Authorize:', 'w3-total-cache' ); ?></label></th>
	<td>
		<?php if ( empty( $api_key ) ) : ?>
			<input class="w3tc_cdn_limelight_authorize button" type="button"
				value="<?php esc_attr_e( 'Authorize', 'w3-total-cache' ); ?>" />
		<?php else : ?>
			<input class="w3tc_cdn_limelight_authorize button" type="button"
				value="<?php esc_attr_e( 'Reauthorize', 'w3-total-cache' ); ?>" />
		<?php endif; ?>
	</td>
</tr>

<?php if ( ! empty( $api_key ) ) : ?>
<tr>
	<th>
		<label for="cdn_limelight_ssl">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'%1$sSSL%2$s support:',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
		</label>
	</th>
	<td>
		<select id="cdn_limelight_ssl" name="cdn__limelight__ssl">
			<option value="auto"<?php selected( $config->get_string( 'cdn.limelight.ssl' ), 'auto' ); ?>><?php esc_html_e( 'Auto (determine connection type automatically)', 'w3-total-cache' ); ?></option>
			<option value="enabled"<?php selected( $config->get_string( 'cdn.limelight.ssl' ), 'enabled' ); ?>><?php esc_html_e( 'Enabled (always use SSL)', 'w3-total-cache' ); ?></option>
			<option value="disabled"<?php selected( $config->get_string( 'cdn.limelight.ssl' ), 'disabled' ); ?>><?php esc_html_e( 'Disabled (always use HTTP)', 'w3-total-cache' ); ?></option>
		</select>
		<p class="description">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'Some %1$sCDN%2$s providers may or may not support %3$sSSL%4$s, contact your vendor for more information.',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
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
	</td>
</tr>
<tr>
	<th><?php esc_html_e( 'Replace site\'s hostname with:', 'w3-total-cache' ); ?></th>
	<td>
		<?php
		$cnames = $config->get_array( 'cdn.limelight.host.domains' );
		require W3TC_INC_DIR . '/options/cdn/common/cnames-readonly.php';
		?>
		<p class="description">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'Hostname provided by your %1$sCDN%2$s provider, this value will replace your site\'s hostname in the %3$sHTML%4$s.',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
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
	</td>
</tr>
<tr>
	<th colspan="2">
		<input id="cdn_test"
			class="button {type: 'limelight', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
			type="button" value="<?php esc_attr_e( 'Test', 'w3-total-cache' ); ?>" />
		<span id="cdn_test_status" class="w3tc-status w3tc-process"></span>
	</th>
</tr>
<?php endif; ?>
