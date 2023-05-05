<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
$hash_code = $config->get_string( 'cdn.highwinds.host.hash_code' );
?>
<tr>
	<th style="width: 300px;"><label><?php esc_html_e( 'Authorize:', 'w3-total-cache' ); ?></label></th>
	<td>
		<?php if ( empty( $hash_code ) ) : ?>
			<input class="w3tc_cdn_highwinds_authorize button" type="button"
				value="<?php esc_html_e( 'Authorize', 'w3-total-cache' ); ?>" />
		<?php else : ?>
			<input class="w3tc_cdn_highwinds_authorize button" type="button"
				value="<?php esc_html_e( 'Reauthorize', 'w3-total-cache' ); ?>" />
		<?php endif ?>
	</td>
</tr>

<?php if ( ! empty( $hash_code ) ) : ?>
<tr>
	<th>
		<label>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'%1CDN%2 host (%3$sCNAME%4$s target):',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Canonical Name', 'w3-total-cache' ) . '">',
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
	<td class="w3tc_config_value_text">
		cds.<?php echo esc_html( $config->get_string( 'cdn.highwinds.host.hash_code' ) ); ?>.hwcdn.net
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_highwinds_ssl">
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
		<select id="cdn_highwinds_ssl" name="cdn__highwinds__ssl">
			<option value="auto"<?php selected( $config->get_string( 'cdn.highwinds.ssl' ), 'auto' ); ?>><?php esc_html_e( 'Auto (determine connection type automatically)', 'w3-total-cache' ); ?></option>
			<option value="enabled"<?php selected( $config->get_string( 'cdn.highwinds.ssl' ), 'enabled' ); ?>><?php esc_html_e( 'Enabled (always use SSL)', 'w3-total-cache' ); ?></option>
			<option value="disabled"<?php selected( $config->get_string( 'cdn.highwinds.ssl' ), 'disabled' ); ?>><?php esc_html_e( 'Disabled (always use HTTP)', 'w3-total-cache' ); ?></option>
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
		$cnames = $config->get_array( 'cdn.highwinds.host.domains' );
		include W3TC_INC_DIR . '/options/cdn/common/cnames-readonly.php';
		?>
		<input class="w3tc_cdn_highwinds_configure_cnames_form button" type="button" value="
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Configure %1$sCNAME%2$ss',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Canonical Name', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
			" />
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
			class="button {type: 'highwinds', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
			type="button"
			value="<?php esc_html_e( 'Test', 'w3-total-cache' ); ?>" />
		<span id="cdn_test_status" class="w3tc-status w3tc-process"></span>
	</th>
</tr>
<?php endif ?>
