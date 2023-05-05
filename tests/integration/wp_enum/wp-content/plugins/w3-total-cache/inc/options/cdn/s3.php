<?php
/**
 * File: s3.php
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<tr>
	<th colspan="2">
		<p class="description">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML a tag to Amazon UserGuide for Access Policy Language KeyConcepts, 2 opening HTML acronym tag.
					// translators: 3 closing HTML acronym tag, 4 closing HTML a tag, 5 opening HTML acronym tag,
					// translators: 6 closing HTML acronym tag, 7 opening HTML a tag to Amazons Policy Generator,
					// translators: 8 opening HTML acronym tag, 9 closing HTML acronym tag, 10 closing HTML a tag.
					__(
						'We recommend that you use %1$s%2$sIAM%3$s%4$s to create a new policy for %5$sAWS%6$s services that have limited permissions. A helpful tool: %7$s%8$sAWS%9$s Policy Generator%10$s',
						'w3-total-cache'
					),
					'<a href="' . esc_url( 'http://docs.amazonwebservices.com/IAM/latest/UserGuide/AccessPolicyLanguage_KeyConcepts.html' ) . '" target="_blank">',
					'<acronym title="' . esc_attr__( 'AWS Identity and Access Management', 'w3-total-cache' ) . '">',
					'</acronym>',
					'</a>',
					'<acronym title="' . esc_attr__( 'Amazon Web Services', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<a href="' . esc_url( 'http://awspolicygen.s3.amazonaws.com/policygen.html' ) . '" target="_blank">',
					'<acronym title="' . esc_attr__( 'Amazon Web Services', 'w3-total-cache' ) . '">',
					'</acronym>',
					'</a>'
				),
				array(
					'a'       => array(
						'href'   => array(),
						'target' => array(),
					),
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
		</p>
	</th>
</tr>
<tr>
	<th style="width: 300px;"><label for="cdn_s3_key"><?php esc_html_e( 'Access key ID:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="cdn_s3_key" class="w3tc-ignore-change" type="text"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> name="cdn__s3__key" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.s3.key' ) ); ?>" size="30" />
	</td>
</tr>
<tr>
	<th><label for="cdn_s3_secret"><?php esc_html_e( 'Secret key:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="cdn_s3_secret" class="w3tc-ignore-change"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> type="password" name="cdn__s3__secret" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.s3.secret' ) ); ?>" size="60" />
	</td>
</tr>
<tr>
	<th><label for="cdn_s3_bucket"><?php esc_html_e( 'Bucket:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="cdn_s3_bucket" type="text" name="cdn__s3__bucket"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> value="<?php echo esc_attr( strtolower( $this->_config->get_string( 'cdn.s3.bucket' ) ) ); ?>" size="30" />
			<?php
			Util_Ui::selectbox(
				'cdn_s3_bucket_location',
				'cdn__s3__bucket__location',
				$this->_config->get_string( 'cdn.s3.bucket.location' ),
				CdnEngine_S3::regions_list()
			);
			?>
		<b>or</b>
		<input id="cdn_create_container" class="button {type: 's3', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'Create as new bucket', 'w3-total-cache' ); ?>" /> <span id="cdn_create_container_status" class="w3tc-status w3tc-process"></span>
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_s3_ssl">
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
		<select id="cdn_s3_ssl" name="cdn__s3__ssl" <?php Util_Ui::sealing_disabled( 'cdn.' ); ?>>
			<option value="auto"<?php selected( $this->_config->get_string( 'cdn.s3.ssl' ), 'auto' ); ?>><?php esc_html_e( 'Auto (determine connection type automatically)', 'w3-total-cache' ); ?></option>
			<option value="enabled"<?php selected( $this->_config->get_string( 'cdn.s3.ssl' ), 'enabled' ); ?>><?php esc_html_e( 'Enabled (always use SSL)', 'w3-total-cache' ); ?></option>
			<option value="disabled"<?php selected( $this->_config->get_string( 'cdn.s3.ssl' ), 'disabled' ); ?>><?php esc_html_e( 'Disabled (always use HTTP)', 'w3-total-cache' ); ?></option>
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
		$cdn_s3_bucket = $this->_config->get_string( 'cdn.s3.bucket' );
		if ( '' !== $cdn_s3_bucket ) {
			echo esc_html( $cdn_s3_bucket ) . '.s3.amazonaws.com ';
		} else {
			echo '&lt;bucket&gt;.s3.amazonaws.com ';
		}

		esc_html_e( 'or CNAME:', 'w3-total-cache' );

		$cnames = $this->_config->get_array( 'cdn.s3.cname' );
		require W3TC_INC_DIR . '/options/cdn/common/cnames.php';
		?>
		<p class="description">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML a tag to Amazon UserGuide for Virtual Hosting, 2 closing HTML a tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'If you have already added a %1$sCNAME%2$s to your %3$sDNS%4$s Zone, enter it here.',
						'w3-total-cache'
					),
					'<a href="' . esc_url( 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html#VirtualHostingCustomURLs' ) . '" target="_blank">',
					'</a>',
					'<acronym title="' . esc_attr__( 'Domain Name System', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'a'       => array(
						'href'   => array(),
						'target' => array(),
					),
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
	<th><label for="cdn_s3_public_objects"><?php esc_html_e( 'Set objects to publicly accessible on upload:', 'w3-total-cache' ); ?></label></th>
	<td>
		<select id="cdn_s3_public_objects" name="cdn__s3__public_objects" <?php Util_Ui::sealing_disabled( 'cdn.' ); ?> >
			<option value="enabled"<?php selected( $this->_config->get_string( 'cdn.s3.public_objects' ), 'enabled' ); ?>><?php esc_html_e( 'Enabled (apply the \'public-read\' ACL)', 'w3-total-cache' ); ?></option>
			<option value="disabled"<?php selected( $this->_config->get_string( 'cdn.s3.public_objects' ), 'disabled' ); ?>><?php esc_html_e( 'Disabled (don\'t apply an ACL)', 'w3-total-cache' ); ?></option>
		</select>
	</td>
</tr>
<tr>
	<th colspan="2">
		<input id="cdn_test" class="button {type: 's3', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'Test S3 upload', 'w3-total-cache' ); ?>" /> <span id="cdn_test_status" class="w3tc-status w3tc-process"></span>
	</th>
</tr>
