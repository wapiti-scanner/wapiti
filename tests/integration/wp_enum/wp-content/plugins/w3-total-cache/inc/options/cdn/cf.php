<?php
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
					// translators: 1 opening HTML a tag to Amazon UserGuide for Access Policy Language KeyConcepts, 2 opening HTML acronym tag,
					// translators: 3 closing HTML acronym tag, 4 closing HTML a tag, 5 opening HTML acronym tag, 6 closing HTML acronym tag,
					// translators: 7 opening HTML a tag to Amazon Policy Generator, 8 opening HTML acronym tag,
					// translators: 9 closing HTML acronym tag, 10 closing HTML a tag.
					__(
						'We recommend that you use %1$s%2$sIAM%3$s%4$s to create a new policy for %5$sAWS%6$s services that have limited permissions. A helpful tool: %7$s%8$sAWS%9$s Policy Generator%10$s',
						'w3-total-cache'
					),
					'<a href="http://docs.amazonwebservices.com/IAM/latest/UserGuide/AccessPolicyLanguage_KeyConcepts.html" target="_blank">',
					'<acronym title="' . __( 'AWS Identity and Access Management', 'w3-total-cache' ) . '">',
					'</acronym>',
					'</a>',
					'<acronym title="' . __( 'Amazon Web Services', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<a href="http://awspolicygen.s3.amazonaws.com/policygen.html" target="_blank">',
					'<acronym title="' . __( 'Amazon Web Services', 'w3-total-cache' ) . '">',
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
	<th style="width: 300px;"><label for="cdn_cf_key"><?php esc_html_e( 'Access key ID:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="cdn_cf_key" class="w3tc-ignore-change" type="text"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> name="cdn__cf__key" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.cf.key' ) ); ?>" size="30" />
	</td>
</tr>
<tr>
	<th><label for="cdn_cf_secret"><?php esc_html_e( 'Secret key:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="cdn_cf_secret" class="w3tc-ignore-change" type="password"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> name="cdn__cf__secret" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.cf.secret' ) ); ?>" size="60" />
	</td>
</tr>
<tr>
	<th><label for="cdn_cf_bucket"><?php esc_html_e( 'Bucket:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="cdn_cf_bucket" type="text" name="cdn__cf__bucket"
		<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> value="<?php echo esc_attr( strtolower( $this->_config->get_string( 'cdn.cf.bucket' ) ) ); ?>" size="30" />
			<?php
			Util_Ui::selectbox(
				'cdn_cf_bucket_location',
				'cdn__cf__bucket__location',
				$this->_config->get_string( 'cdn.cf.bucket.location' ),
				CdnEngine_S3::regions_list()
			);
			?>
		<b>or</b>
		<input id="cdn_create_container" class="button {type: 'cf', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'Create as new bucket with distribution', 'w3-total-cache' ); ?>" /> <span id="cdn_create_container_status" class="w3tc-status w3tc-process"></span>
	</td>
</tr>
<tr>
	<th>
		<label for="cdn_cf_ssl">
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
		<select id="cdn_cf_ssl" name="cdn__cf__ssl" <?php Util_Ui::sealing_disabled( 'cdn.' ); ?>>
			<option value="auto"<?php selected( $this->_config->get_string( 'cdn.cf.ssl' ), 'auto' ); ?>><?php esc_html_e( 'Auto (determine connection type automatically)', 'w3-total-cache' ); ?></option>
			<option value="enabled"<?php selected( $this->_config->get_string( 'cdn.cf.ssl' ), 'enabled' ); ?>><?php esc_html_e( 'Enabled (always use SSL)', 'w3-total-cache' ); ?></option>
			<option value="disabled"<?php selected( $this->_config->get_string( 'cdn.cf.ssl' ), 'disabled' ); ?>><?php esc_html_e( 'Disabled (always use HTTP)', 'w3-total-cache' ); ?></option>
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
	<th><label for="cdn_cf_id"><?php esc_html_e( 'Replace site\'s hostname with:', 'w3-total-cache' ); ?></label></th>
	<td>
		<input id="cdn_cf_id" type="text" name="cdn__cf__id"
			<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'cdn.cf.id' ) ); ?>" size="18" style="text-align: right;" />.cloudfront.net or <acronym title="Canonical Name">CNAME</acronym>:
		<?php
		$cnames = $this->_config->get_array( 'cdn.cf.cname' );
		require W3TC_INC_DIR . '/options/cdn/common/cnames.php';
		?>
		<p class="description">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML a tag to Amazon Developer Guide for CNAMEs, 2 opnening HTML acronym tag,
					// translators: 3 closing HTML acronym tag, 4 closing HTML a tag, 5 opening HTML acronym tag,
					// translators: 6 closing HTML acronym tag.
					__(
						'If you have already added a %1$s%2$sCNAME%3$s%4$s to your %5$sDNS%6$s Zone, enter it here.',
						'w3-total-cache'
					),
					'<a href="http://docs.amazonwebservices.com/AmazonCloudFront/latest/DeveloperGuide/index.html?CNAMEs.html" target="_blank">',
					'<acronym title="' . __( 'Canonical Name', 'w3-total-cache' ) . '">',
					'</acronym>',
					'</a>',
					'<acronym title="' . __( 'Domain Name System', 'w3-total-cache' ) . '">',
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
	<th><label for="cdn_cf_public_objects"><?php _e( 'Set objects to publicly accessible on upload:', 'w3-total-cache' ); ?></label></th>
	<td>
		<select id="cdn_cf_public_objects" name="cdn__cf__public_objects" <?php Util_Ui::sealing_disabled( 'cdn.' ) ?> >
			<option value="enabled"<?php selected( $this->_config->get_string( 'cdn.cf.public_objects' ), 'enabled' ); ?>><?php esc_html_e( 'Enabled (apply the \'public-read\' ACL)', 'w3-total-cache' ); ?></option>
			<option value="disabled"<?php selected( $this->_config->get_string( 'cdn.cf.public_objects' ), 'disabled' ); ?>><?php esc_html_e( 'Disabled (don\'t apply an ACL)', 'w3-total-cache' ); ?></option>
		</select>
		<p class="description"><?php _e( 'Objects in an S3 bucket served from CloudFront do not need to be publicly accessible. Set this value to disabled to ensure that objects are not publicly accessible and can only be accessed via CloudFront or with a suitable IAM role.', 'w3-total-cache' ); ?></p>
	</td>
</tr>
<tr>
	<th colspan="2">
		<input id="cdn_test" class="button {type: 'cf', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'Test S3 upload &amp; CloudFront distribution', 'w3-total-cache' ); ?>" /> <span id="cdn_test_status" class="w3tc-status w3tc-process"></span>
	</th>
</tr>
