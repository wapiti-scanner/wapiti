<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<tr>
	<th colspan="2">
		<?php $this->checkbox( 'cdn.ftp.pasv' ); ?>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
				__(
					'Use passive %1$sFTP%2$s mode',
					'w3-total-cache'
				),
				'<acronym title="' . __( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
				'</acronym>'
			),
			array(
				'acronym' => array(
					'title' => array(),
				),
			)
		);
		?>
		<p class="description"><?php esc_html_e( 'Enable this option only if there are connectivity issues, otherwise it\'s not recommended.', 'w3-total-cache' ); ?></p>
	</th>
</tr>
<tr>
	<th style="width: 300px;"><label for="cdn_ftp_host">
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
				__(
					'%1$sFTP%2$s hostname:',
					'w3-total-cache'
				),
				'<acronym title="' . __( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
				'</acronym>'
			),
			array(
				'acronym' => array(
					'title' => array(),
				),
			)
		);
		?>
	</th>
	<td>
		<input id="cdn_ftp_host" type="text" name="cdn__ftp__host"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'cdn.ftp.host' ) ); ?>" size="30" />
		<p class="description"><?php esc_html_e( 'Specify the server\'s address, e.g.: "ftp.domain.com". Try "127.0.0.1" if using a sub-domain on the same server as your site.', 'w3-total-cache' ); ?></p>
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_ftp_type">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'%1$sFTP%2$s connection:',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
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
		<select id="cdn_ftp_type" name="cdn__ftp__type" <?php Util_Ui::sealing_disabled( 'cdn.' ); ?>>
			<option value=""<?php selected( $this->_config->get_string( 'cdn.ftp.type' ), '' ); ?>><?php esc_html_e( 'Plain FTP', 'w3-total-cache' ); ?></option>
			<option value="ftps"<?php selected( $this->_config->get_string( 'cdn.ftp.type' ), 'ftps' ); ?>><?php esc_html_e( 'SSL-FTP connection (FTPS)', 'w3-total-cache' ); ?></option>
			<option value="sftp"<?php selected( $this->_config->get_string( 'cdn.ftp.type' ), 'sftp' ); ?><?php echo function_exists( 'ssh2_connect' ) ? '' : ' disabled'; ?>><?php esc_html_e( 'FTP over SSH (SFTP)', 'w3-total-cache' ); ?></option>
		</select>
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_ftp_user">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'%1$sFTP%2$s username:',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
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
		<input id="cdn_ftp_user" class="w3tc-ignore-change" type="text"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> name="cdn__ftp__user" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.ftp.user' ) ); ?>" size="30" />
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_ftp_pass">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'%1$sFTP%2$s password:',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
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
		<input id="cdn_ftp_pass" class="w3tc-ignore-change"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> type="password" name="cdn__ftp__pass" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.ftp.pass' ) ); ?>" size="30" />
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_ftp_path">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'%1$sFTP%2$s path:',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
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
		<input id="cdn_ftp_path" type="text" name="cdn__ftp__path"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'cdn.ftp.path' ) ); ?>" size="30" />
		<p class="description"><?php esc_html_e( 'Specify the directory where files must be uploaded to be accessible in a web browser (the document root).', 'w3-total-cache' ); ?></p>
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_ftp_ssl">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'%1$sSSL%2$s support:',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
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
		<select id="cdn_ftp_ssl" name="cdn__ftp__ssl" <?php Util_Ui::sealing_disabled( 'cdn.' ); ?>>
			<option value="auto"<?php selected( $this->_config->get_string( 'cdn.ftp.ssl' ), 'auto' ); ?>><?php esc_html_e( 'Auto (determine connection type automatically)', 'w3-total-cache' ); ?></option>
			<option value="enabled"<?php selected( $this->_config->get_string( 'cdn.ftp.ssl' ), 'enabled' ); ?>><?php esc_html_e( 'Enabled (always use SSL)', 'w3-total-cache' ); ?></option>
			<option value="disabled"<?php selected( $this->_config->get_string( 'cdn.ftp.ssl' ), 'disabled' ); ?>><?php esc_html_e( 'Disabled (always use HTTP)', 'w3-total-cache' ); ?></option>
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
					'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . __( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
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
		<?php $this->checkbox( 'cdn.ftp.default_keys', ! function_exists( 'ssh2_connect' ) ); ?>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
				__(
					'Use default %1$sSSH%2$s public/private key files',
					'w3-total-cache'
				),
				'<acronym title="' . __( 'Secure Shell', 'w3-total-cache' ) . '">',
				'</acronym>'
			),
			array(
				'acronym' => array(
					'title' => array(),
				),
			)
		);
		?>
		<p class="description"><?php esc_html_e( 'Enable this option if you don\'t have special public/private key files.', 'w3-total-cache' ); ?></p>
	</th>
</tr>
<tr>
	<th>
		<label for="cdn_ftp_pubkey">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'%1$sSFTP%2$s public key:',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'Secure File Transfer Protocol', 'w3-total-cache' ) . '">',
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
		<input id="cdn_ftp_pubkey" class="w3tc-ignore-change" type="text"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> name="cdn__ftp__pubkey" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.ftp.pubkey' ) ); ?>" size="30" <?php echo function_exists( 'ssh2_connect' ) ? '' : 'disabled'; ?> />
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_ftp_privkey">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'%1$sSFTP%2$s private key:',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'Secure File Transfer Protocol', 'w3-total-cache' ) . '">',
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
		<input id="cdn_ftp_privkey" class="w3tc-ignore-change" type="text"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> name="cdn__ftp__privkey" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.ftp.privkey' ) ); ?>" size="30" <?php echo function_exists( 'ssh2_connect' ) ? '' : 'disabled'; ?> />
	</td>
</tr>
<tr>
	<th><?php esc_html_e( 'Replace site\'s hostname with:', 'w3-total-cache' ); ?></th>
	<td>
		<?php
		$cnames = $this->_config->get_array( 'cdn.ftp.domain' );
		require W3TC_INC_DIR . '/options/cdn/common/cnames.php';
		?>
		<p class="description">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
					// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
					__(
						'Enter the hostname or %1$sCNAME%2$s(s) of your %3$sFTP%4$s server configured above, these values will replace your site\'s hostname in the %5$sHTML%6$s.',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'Canonical Name', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . __( 'File Transfer Protocol', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . __( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
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
		<input id="cdn_test" class="button {type: 'ftp', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'Test FTP server', 'w3-total-cache' ); ?>" /> <span id="cdn_test_status" class="w3tc-status w3tc-process"></span>
	</th>
</tr>
