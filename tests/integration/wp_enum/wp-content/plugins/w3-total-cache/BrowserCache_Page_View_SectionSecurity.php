<?php
/**
 * File: BrowserCache_Page_View_SectionSecurity.php
 *
 * @package W3TC
 *
 * phpcs:disable WordPress.Security.EscapeOutput
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$c         = Dispatcher::config();
$fp_values = $c->get_array( 'browsercache.security.fp.values' );

$feature_policies = array(
	array(
		'label'       => 'accelerometer',
		'description' => esc_html__( 'Controls whether the current document is allowed to gather information about the acceleration of the device through the Accelerometer interface.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'ambient-light-sensor',
		'description' => esc_html__( 'Controls whether the current document is allowed to gather information about the amount of light in the environment around the device through the AmbientLightSensor interface.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'autoplay',
		'description' => esc_html__( 'Controls whether the current document is allowed to autoplay media requested through the HTMLMediaElement interface.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'battery',
		'description' => esc_html__( 'Controls whether the use of the Battery Status API is allowed. When this policy is disabled, the Promise returned by Navigator.getBattery() will reject with a NotAllowedError DOMException.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'camera',
		'description' => esc_html__( 'Controls whether the current document is allowed to use video input devices.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'display-capture',
		'description' => esc_html__( 'Controls whether or not the document is permitted to use Screen Capture API.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'document-domain',
		'description' => esc_html__( 'Controls whether the current document is allowed to set document.domain.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'encrypted-media',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the Encrypted Media Extensions API (EME).', 'w3-total-cache' ),
	),
	array(
		'label'       => 'execution-while-not-rendered',
		'description' => esc_html__( 'Controls whether tasks should execute in frames while they\'re not being rendered (e.g. if an iframe is hidden or display: none).', 'w3-total-cache' ),
	),
	array(
		'label'       => 'execution-while-out-of-viewport',
		'description' => esc_html__( 'Controls whether tasks should execute in frames while they\'re outside of the visible viewport.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'fullscreen',
		'description' => esc_html__( 'Controls whether the current document is allowed to use Element.requestFullScreen().', 'w3-total-cache' ),
	),
	array(
		'label'       => 'gamepad',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the Gamepad API. When this policy is disabled, calls to Navigator.getGamepads() will throw a SecurityError DOMException, and the gamepadconnected and gamepaddisconnected events will not fire.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'geolocation',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the Geolocation Interface.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'gyroscope',
		'description' => esc_html__( 'Controls whether the current document is allowed to gather information about the orientation of the device through the Gyroscope interface.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'layout-animations',
		'description' => esc_html__( 'Controls whether the current document is allowed to show layout animations.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'legacy-image-formats',
		'description' => esc_html__( 'Controls whether the current document is allowed to display images in legacy formats.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'magnetometer',
		'description' => esc_html__( 'Controls whether the current document is allowed to gather information about the orientation of the device through the Magnetometer interface.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'microphone',
		'description' => esc_html__( 'Controls whether the current document is allowed to use audio input devices.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'midi',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the Web MIDI API.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'navigation-override',
		'description' => esc_html__( 'Controls the availability of mechanisms that enables the page author to take control over the behavior of spatial navigation, or to cancel it outright.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'oversized-images',
		'description' => esc_html__( 'Controls whether the current document is allowed to download and display large images.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'payment',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the Payment Request API.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'picture-in-picture',
		'description' => esc_html__( 'Controls whether the current document is allowed to play a video in a Picture-in-Picture mode via the corresponding API.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'publickey-credentials-get',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the Web Authentication API to retrieve already stored public-key credentials, i.e. via navigator.credentials.get({publicKey: ..., ...}).', 'w3-total-cache' ),
	),
	array(
		'label'       => 'screen-wake-lock',
		'description' => esc_html__( 'Controls whether the current document is allowed to use Screen Wake Lock API to indicate that device should not turn off or dim the screen.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'speaker',
		'description' => esc_html__( 'Controls whether the current document is allowed to play audio via any methods.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'sync-xhr',
		'description' => esc_html__( 'Controls whether the current document is allowed to make synchronous XMLHttpRequest requests.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'unoptimized-images',
		'description' => esc_html__( 'Controls whether the current document is allowed to download and display unoptimized images.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'unsized-media',
		'description' => esc_html__( 'Controls whether the current document is allowed to change the size of media elements after the initial layout is complete.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'usb',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the WebUSB API.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'vibrate',
		'description' => esc_html__( 'Controls whether the current document is allowed to trigger device vibrations via Navigator.vibrate() method of Vibration API.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'vr',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the WebVR API. When this policy is disabled, the Promise returned by Navigator.getVRDisplays() will reject with a DOMException. Keep in mind that the WebVR standard is in the process of being replaced with WebXR.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'wake-lock',
		'description' => esc_html__( 'Controls whether the current document is allowed to use Wake Lock API to indicate that device should not enter power-saving mode.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'web-share',
		'description' => esc_html__( 'Controls whether or not the current document is allowed to use the Navigator.share() of Web Share API to share text, links, images, and other content to arbitrary destinations of user\'s choice, e.g. mobile apps.', 'w3-total-cache' ),
	),
	array(
		'label'       => 'xr-spatial-tracking',
		'description' => esc_html__( 'Controls whether the current document is allowed to use the WebXR Device API.', 'w3-total-cache' ),
	),
);

?>

<?php Util_Ui::postbox_header( esc_html__( 'Security Headers', 'w3-total-cache' ), '', 'security' ); ?>
<p>
	<?php
	echo wp_kses(
		sprintf(
			// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
			__(
				'%1$sHTTP%2$s security headers provide another layer of protection for your website by helping to mitigate attacks and security vulnerabilities.',
				'w3-total-cache'
			),
			'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
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
<p><a onclick="w3tc_csp_reference()" href="javascript:void(0);"><?php esc_html_e( 'Quick Reference Chart', 'w3-total-cache' ); ?></a></p>

<table class="form-table">
	<?php
	Util_Ui::config_item(
		array(
			'key'              => 'browsercache.security.session.use_only_cookies',
			'control'          => 'selectbox',
			'selectbox_values' => $security_session_values,
			'description'      => wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'This setting prevents attacks that are caused by passing session IDs in %1$sURL%2$ss.',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
		)
	);
	?>
	<?php
	Util_Ui::config_item(
		array(
			'key'              => 'browsercache.security.session.cookie_httponly',
			'control'          => 'selectbox',
			'selectbox_values' => $security_session_values,
			'description'      => esc_html__( 'This tells the user\'s browser not to make the session cookie accessible to client side scripting such as JavaScript. This makes it harder for an attacker to hijack the session ID and masquerade as the effected user.', 'w3-total-cache' ),
		)
	);
	?>
	<?php
	Util_Ui::config_item(
		array(
			'key'              => 'browsercache.security.session.cookie_secure',
			'control'          => 'selectbox',
			'selectbox_values' => $security_session_values,
			'description'      => esc_html__( 'This will prevent the user\'s session ID from being transmitted in plain text, making it much harder to hijack the user\'s session.', 'w3-total-cache' ),
		)
	);
	?>
	<tr>
		<th colspan="2">
			<?php $this->checkbox( 'browsercache.hsts' ); ?> <?php Util_Ui::e_config_label( 'browsercache.hsts' ); ?></label>
			<p class="description">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acornym tag,
						// translators: 3 opening HTML acronym tag, 4 closing HTML acornym tag,
						// translators: 5 opening HTML acronym tag, 6 closing HTML acornym tag,
						// translators: 7 opening HTML acronym tag, 8 closing HTML acornym tag,
						// translators: 9 opening HTML acronym tag, 10 closing HTML acornym tag,
						// translators: 11 opening HTML acronym tag, 12 closing HTML acornym tag.
						__(
							'%1$sHTTP%2$s Strict-Transport-Security (%3$sHSTS%4$s) enforces secure (%5$sHTTP%6$s over %7$sSSL%8$s/%9$sTLS%10$s) connections to the server. This can help mitigate adverse effects caused by bugs and session leaks through cookies and links. It also helps defend against man-in-the-middle attacks.  If there are %11$sSSL%12$s negotiation warnings then users will not be permitted to ignore them.',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'HTTP Strict Transport Security', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'Transport Layer Security', 'w3-total-cache' ) . '">',
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
		</th>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_hsts_directive"><?php Util_Ui::e_config_label( 'browsercache.security.hsts.directive' ); ?></label>
		</th>
		<td>
			<select id="browsercache_security_hsts_directive"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
				name="browsercache__security__hsts__directive">
				<?php $value = $this->_config->get_string( 'browsercache.security.hsts.directive' ); ?>
				<option value="maxage"<?php selected( $value, 'maxage' ); ?>><?php echo esc_html( 'max-age=EXPIRES_SECONDS' ); ?></option>
				<option value="maxagepre"<?php selected( $value, 'maxagepre' ); ?>><?php echo esc_html( 'max-age=EXPIRES_SECONDS; preload' ); ?></option>
				<option value="maxageinc"<?php selected( $value, 'maxageinc' ); ?>><?php echo esc_html( 'max-age=EXPIRES_SECONDS; includeSubDomains' ); ?></option>
				<option value="maxageincpre"<?php selected( $value, 'maxageincpre' ); ?>><?php echo esc_html( 'max-age=EXPIRES_SECONDS; includeSubDomains; preload' ); ?></option>
			</select>
			<div id="browsercache_security_hsts_directive_description"></div>
		</td>
	</tr>
	<tr>
		<th colspan="2">
			<?php $this->checkbox( 'browsercache.security.xfo' ); ?> <?php Util_Ui::e_config_label( 'browsercache.security.xfo' ); ?></label>
			<p class="description">
				<?php esc_html_e( 'This tells the browser if it is permitted to render a page within a frame-like tag (i.e., &lt;frame&gt;, &lt;iframe&gt; or &lt;object&gt;). This is useful for preventing clickjacking attacks.', 'w3-total-cache' ); ?>
			</p>
		</th>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_xfo_directive"><?php Util_Ui::e_config_label( 'browsercache.security.xfo.directive' ); ?></label>
		</th>
		<td>
			<select id="browsercache_security_xfo_directive"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
				name="browsercache__security__xfo__directive">
				<?php $value = $this->_config->get_string( 'browsercache.security.xfo.directive' ); ?>
				<option value="same"<?php selected( $value, 'same' ); ?>><?php echo esc_html( 'SameOrigin' ); ?></option>
				<option value="deny"<?php selected( $value, 'deny' ); ?>><?php echo esc_html( 'Deny' ); ?></option>
				<option value="allow"<?php selected( $value, 'allow' ); ?>><?php echo esc_html( 'Allow-From' ); ?></option>
			</select>
			<input id="browsercache_security_xfo_allow" type="text" name="browsercache__security__xfo__allow"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.xfo.allow' ) ); ?>" size="50" placeholder="Enter URL" />
			<div id="browsercache_security_xfo_directive_description"></div>
		</td>
	</tr>
	<tr>
		<th colspan="2">
			<?php $this->checkbox( 'browsercache.security.xss' ); ?> <?php Util_Ui::e_config_label( 'browsercache.security.xss' ); ?></label>
			<p class="description">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acornym tag.
						__(
							'This header enables the %1$sXSS%2$s filter. It helps to stop malicious scripts from being injected into your website. Although this is already built into and enabled by default in most browsers today it is made available here to enforce its reactivation if it was disabled within the user\'s browser.',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Cross-Site Scripting', 'w3-total-cache' ) . '">',
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
		</th>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_xss_directive"><?php Util_Ui::e_config_label( 'browsercache.security.xss.directive' ); ?></label>
		</th>
		<td>
			<select id="browsercache_security_xss_directive"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
				name="browsercache__security__xss__directive">
				<?php $value = $this->_config->get_string( 'browsercache.security.xss.directive' ); ?>
				<option value="0"<?php selected( $value, '0' ); ?>><?php echo esc_html( '0' ); ?></option>
				<option value="1"<?php selected( $value, '1' ); ?>><?php echo esc_html( '1' ); ?></option>
				<option value="block"<?php selected( $value, 'block' ); ?>><?php echo esc_html( '1; mode=block' ); ?></option>
			</select>
			<div id="browsercache_security_xss_directive_description"></div>
		</td>
	</tr>
	<tr>
		<th colspan="2">
			<?php $this->checkbox( 'browsercache.security.xcto' ); ?> <?php Util_Ui::e_config_label( 'browsercache.security.xcto' ); ?></label>
			<p class="description">
				<?php esc_html_e( 'This instructs the browser to not MIME-sniff a response outside its declared content-type. It helps to reduce drive-by download attacks and stops sites from serving malevolent content that could masquerade as an executable or dynamic HTML file.', 'w3-total-cache' ); ?>
			</p>
		</th>
	</tr>
	<tr>
		<th colspan="2">
			<?php $this->checkbox( 'browsercache.security.pkp' ); ?> <?php Util_Ui::e_config_label( 'browsercache.security.pkp' ); ?></label>
			<p class="description">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acornym tag,
						// translators: 3 opening HTML acronym tag, 4 closing HTML acornym tag,
						// translators: 5 opening HTML acronym tag, 6 closing HTML acornym tag.
						__(
							'%1$sHTTP%2$s Public Key Pinning (%3$sHPKP%4$s) is a security feature for %5$sHTTP%6$sS websites that can prevent fraudulently issued certificates from being used to impersonate existing secure websites.',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'HTTP Public Key Pinning', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
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
		</th>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_pkp_pin"><?php Util_Ui::e_config_label( 'browsercache.security.pkp.pin' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_pkp_pin" type="text" name="browsercache__security__pkp__pin"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.pkp.pin' ) ); ?>" size="50" placeholder="Enter the Base64-Encode of the SHA256 Hash" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML b tag, 2 closing HTML b tag,
							// translators: 1 opening HTML acronym tag, 2 closing HTML acornym tag.
							__(
								'This field is %1$srequired%2$s and represents a %3$sSPKI%4$s fingerprint. This pin is any public key within your current certificate chain.',
								'w3-total-cache'
							),
							'<b>',
							'</b>',
							'<acronym title="' . esc_attr__( 'Subject Public Key Information', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'b'       => array(),
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_pkp_pin_backup"><?php Util_Ui::e_config_label( 'browsercache.security.pkp.pin.backup' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_pkp_pin_backup" type="text" name="browsercache__security__pkp__pin__backup"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.pkp.pin.backup' ) ); ?>" size="50" placeholder="Enter the Base64-Encode of the SHA256 Hash" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML b tag, 2 closing HTML b tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
							__(
								'This field is %1$salso required%2$s and represents your backup %3$sSPKI%4$s fingerprint. This pin is any public key not in your current certificate chain and serves as a backup in case your certificate expires or has to be revoked.',
								'w3-total-cache'
							),
							'<b>',
							'</b>',
							'<acronym title="' . esc_attr__( 'Subject Public Key Information', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'b'       => array(),
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_pkp_extra"><?php Util_Ui::e_config_label( 'browsercache.security.pkp.extra' ); ?></label>
		</th>
		<td>
			<select id="browsercache_security_pkp_extra"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
				name="browsercache__security__pkp__extra">
				<?php $value = $this->_config->get_string( 'browsercache.security.pkp.extra' ); ?>
				<option value="maxage"<?php selected( $value, 'maxage' ); ?>><?php echo esc_html( 'max-age=EXPIRES_SECONDS' ); ?></option>
				<option value="maxageinc"<?php selected( $value, 'maxageinc' ); ?>><?php echo esc_html( 'max-age=EXPIRES_SECONDS; includeSubDomains' ); ?></option>
			</select>
			<div id="browsercache_security_pkp_extra_description"></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_pkp_report_url"><?php Util_Ui::e_config_label( 'browsercache.security.pkp.report.url' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_pkp_report_url" type="text" name="browsercache__security__pkp__report__url"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.pkp.report.url' ) ); ?>" size="50" placeholder="Enter URL" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'This optional field can be used to specify a %1$sURL%2$s that clients will send reports to if pin validation failures occur. The report is sent as a POST request with a JSON body.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_pkp_report_only"><?php Util_Ui::e_config_label( 'browsercache.security.pkp.report.only' ); ?></label>
		</th>
		<td>
			<select id="browsercache_security_pkp_report_only"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
				name="browsercache__security__pkp__report__only">
				<?php $value = $this->_config->get_string( 'browsercache.security.pkp.report.only' ); ?>
				<option value="0"<?php selected( $value, '0' ); ?>><?php esc_html_e( 'No = Enforce HPKP', 'w3-total-cache' ); ?></option>
				<option value="1"<?php selected( $value, '1' ); ?>><?php esc_html_e( 'Yes = Don\'t Enforce HPKP', 'w3-total-cache' ); ?></option>
			</select>
			<div id="browsercache_security_pkp_report_only_description"></div>
		</td>
	</tr>
	<tr>
		<th colspan="2">
			<?php $this->checkbox( 'browsercache.security.referrer.policy' ); ?> <?php Util_Ui::e_config_label( 'browsercache.security.referrer.policy' ); ?></label>
			<p class="description">
				<?php esc_html_e( 'This header restricts the values of the referer header in outbound links.', 'w3-total-cache' ); ?>
			</p>
		</th>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_referrer_policy_directive"><?php Util_Ui::e_config_label( 'browsercache.security.referrer.policy.directive' ); ?></label>
		</th>
		<td>
			<select id="browsercache_security_referrer_policy_directive"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
				name="browsercache__security__referrer__policy__directive">
				<?php $value = $this->_config->get_string( 'browsercache.security.referrer.policy.directive' ); ?>
				<option value="0"<?php selected( $value, '0' ); ?>><?php esc_html_e( 'Not Set', 'w3-total-cache' ); ?></option>
				<option value="no-referrer"<?php selected( $value, 'no-referrer' ); ?>><?php echo esc_html( 'no-referrer' ); ?></option>
				<option value="no-referrer-when-downgrade"<?php selected( $value, 'no-referrer-when-downgrade' ); ?>><?php echo esc_html( 'no-referrer-when-downgrade' ); ?></option>
				<option value="same-origin"<?php selected( $value, 'same-origin' ); ?>><?php echo esc_html( 'same-origin' ); ?></option>
				<option value="origin"<?php selected( $value, 'origin' ); ?>><?php echo esc_html( 'origin' ); ?></option>
				<option value="strict-origin"<?php selected( $value, 'strict-origin' ); ?>><?php echo esc_html( 'strict-origin' ); ?></option>
				<option value="origin-when-cross-origin"<?php selected( $value, 'origin-when-cross-origin' ); ?>><?php echo esc_html( 'origin-when-cross-origin' ); ?></option>
				<option value="strict-origin-when-cross-origin"<?php selected( $value, 'strict-origin-when-cross-origin' ); ?>><?php echo esc_html( 'strict-origin-when-cross-origin' ); ?></option>
				<option value="unsafe-url"<?php selected( $value, 'unsafe-url' ); ?>><?php echo esc_html( 'unsafe-url' ); ?></option>
			</select>
			<div id="browsercache_security_referrer_policy_directive_description"></div>
		</td>
	</tr>
	<tr>
		<th colspan="2">
			<?php $this->checkbox( 'browsercache.security.csp' ); ?> <?php Util_Ui::e_config_label( 'browsercache.security.csp' ); ?></label>
			<p class="description">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
						// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
						__(
							'The Content Security Policy (%1$sCSP%2$s) header reduces the risk of %3$sXSS%4$s attacks by allowing you to define where resources can be retrieved from, preventing browsers from loading data from any other locations. This makes it harder for an attacker to inject malicious code into your site.',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Content Security Policy', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'Cross-Site Scripting', 'w3-total-cache' ) . '">',
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
		</th>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_reporturi"><?php Util_Ui::e_config_label( 'browsercache.security.csp.reporturi' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_reporturi" type="text" name="browsercache__security__csp__reporturi"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.reporturi' ) ); ?>" size="50" placeholder="Example: https://endpoint.com" />
			<div><i><?php esc_html_e( 'Instructs the user agent to report attempts to violate the Content Security Policy. These violation reports consist of JSON documents sent via an HTTP POST request to the specified URI.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_reportto"><?php Util_Ui::e_config_label( 'browsercache.security.csp.reportto' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_reportto" type="text" name="browsercache__security__csp__reportto"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.reportto' ) ); ?>" size="50" placeholder="Example: csp-endpoint" />
			<div>
				<i><?php esc_html_e( 'Defines a reporting endpoint "group" to which violation reports should to be sent.', 'w3-total-cache' ); ?></i>
				<br/><br/>
				<i><?php esc_html_e( 'The referenced "group" should be defined in either the Report-To or Reporting-Endpoints HTTP headers. These will need to be manually defined either via htaccess or another method of modifying HTTP headers.', 'w3-total-cache' ); ?></i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_base"><?php Util_Ui::e_config_label( 'browsercache.security.csp.base' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_base" type="text" name="browsercache__security__csp__base"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.base' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Restricts the %1$sURL%2$ss which can be used in a document\'s &lt;base&gt; element.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_connect"><?php Util_Ui::e_config_label( 'browsercache.security.csp.connect' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_connect" type="text" name="browsercache__security__csp__connect"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.connect' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Limits the origins to which you can connect via XMLHttpRequest, WebSockets, and EventSource.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_font"><?php Util_Ui::e_config_label( 'browsercache.security.csp.font' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_font" type="text" name="browsercache__security__csp__font"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.font' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies the origins that can serve web fonts.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_frame"><?php Util_Ui::e_config_label( 'browsercache.security.csp.frame' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_frame" type="text" name="browsercache__security__csp__frame"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.frame' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Restricts from where the protected resource can embed frames.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_img"><?php Util_Ui::e_config_label( 'browsercache.security.csp.img' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_img" type="text" name="browsercache__security__csp__img"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.img' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for images and favicons.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_media"><?php Util_Ui::e_config_label( 'browsercache.security.csp.media' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_media" type="text" name="browsercache__security__csp__media"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.media' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for loading media using the &lt;audio&gt; and &lt;video&gt; elements.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_object"><?php Util_Ui::e_config_label( 'browsercache.security.csp.object' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_object" type="text" name="browsercache__security__csp__object"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.object' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Allows control over the &lt;object&gt;, &lt;embed&gt;, and &lt;applet&gt; elements used by Flash and other plugins.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_script"><?php Util_Ui::e_config_label( 'browsercache.security.csp.script' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_script" type="text" name="browsercache__security__csp__script"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.script' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for JavaScript.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_style"><?php Util_Ui::e_config_label( 'browsercache.security.csp.style' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_style" type="text" name="browsercache__security__csp__style"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.style' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Specifies valid sources for %1$sCSS%2$s stylesheets.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_form"><?php Util_Ui::e_config_label( 'browsercache.security.csp.form' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_form" type="text" name="browsercache__security__csp__form"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.form' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Restricts the %1$sURL%2$ss which can be used as the target of form submissions from a given context.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_frame_ancestors"><?php Util_Ui::e_config_label( 'browsercache.security.csp.frame.ancestors' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_frame_ancestors" type="text" name="browsercache__security__csp__frame__ancestors"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.frame.ancestors' ) ); ?>" size="50" placeholder="Example: 'none'" />
			<div><i><?php esc_html_e( 'Specifies valid parents that may embed a page using &lt;frame&gt;, &lt;iframe&gt;, &lt;object&gt;, &lt;embed&gt;, or &lt;applet&gt;.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_plugin"><?php Util_Ui::e_config_label( 'browsercache.security.csp.plugin' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_plugin" type="text" name="browsercache__security__csp__plugin"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.plugin' ) ); ?>" size="50" placeholder="Example: application/x-shockwave-flash" />
			<div><i><?php esc_html_e( 'Restricts the set of plugins that can be embedded into a document by limiting the types of resources which can be loaded.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_sandbox"><?php Util_Ui::e_config_label( 'browsercache.security.csp.sandbox' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_sandbox" type="text" name="browsercache__security__csp__sandbox"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.sandbox' ) ); ?>" size="50" placeholder="Example: allow-popups" />
			<div><i><?php esc_html_e( 'This directive operates similarly to the &lt;iframe&gt; sandbox attribute by applying restrictions to a page\'s actions, including preventing popups, preventing the execution of plugins and scripts, and enforcing a same-origin policy.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_child"><?php Util_Ui::e_config_label( 'browsercache.security.csp.child' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_child" type="text" name="browsercache__security__csp__child"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.child' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Defines the valid sources for web workers and nested browsing contexts loaded using elements such as <frame> and <iframe>. For workers, non-compliant requests are treated as fatal network errors by the user agent.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_manifest"><?php Util_Ui::e_config_label( 'browsercache.security.csp.manifest' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_manifest" type="text" name="browsercache__security__csp__manifest"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.manifest' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies which manifest can be applied to the resource.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_scriptelem"><?php Util_Ui::e_config_label( 'browsercache.security.csp.scriptelem' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_scriptelem" type="text" name="browsercache__security__csp__scriptelem"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.scriptelem' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for JavaScript <script> elements.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_scriptattr"><?php Util_Ui::e_config_label( 'browsercache.security.csp.scriptattr' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_scriptattr" type="text" name="browsercache__security__csp__scriptattr"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.scriptattr' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for JavaScript inline event handlers.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_styleelem"><?php Util_Ui::e_config_label( 'browsercache.security.csp.styleelem' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_styleelem" type="text" name="browsercache__security__csp__styleelem"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.styleelem' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for stylesheet <style> elements and <link> elements with rel="stylesheet".', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_styleattr"><?php Util_Ui::e_config_label( 'browsercache.security.csp.styleattr' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_styleattr" type="text" name="browsercache__security__csp__styleattr"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.styleattr' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for inline styles applied to individual DOM elements.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_worker"><?php Util_Ui::e_config_label( 'browsercache.security.csp.worker' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_worker" type="text" name="browsercache__security__csp__worker"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.worker' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for Worker, SharedWorker, or ServiceWorker scripts.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_csp_default"><?php Util_Ui::e_config_label( 'browsercache.security.csp.default' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_csp_default" type="text" name="browsercache__security__csp__default"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.csp.default' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Defines the defaults for directives you leave unspecified. Generally, this applies to any directive that ends with -src.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th colspan="2">
			<?php $this->checkbox( 'browsercache.security.cspro' ); ?> <?php Util_Ui::e_config_label( 'browsercache.security.cspro' ); ?></label>
			<p class="description">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'The Content Security Policy Report Only (%1$sCSPRO%2$s) header allows web developers to experiment with policies by monitoring (but not enforcing) their effects. These violation reports consist of JSON documents sent via an HTTP POST request to the specified URI. This header is applied separately from the Content-Security-Policy and is useful for testing alternative configurations.',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Content Security Policy Report Only', 'w3-total-cache' ) . '">',
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
		</th>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_reporturi"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.reporturi' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_reporturi" type="text" name="browsercache__security__cspro__reporturi"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.reporturi' ) ); ?>" size="50" placeholder="Example: https://endpoint.com" />
			<div><i><?php esc_html_e( 'Instructs the user agent to report attempts to violate the Content Security Policy. These violation reports consist of JSON documents sent via an HTTP POST request to the specified URI.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_reportto"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.reportto' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_reportto" type="text" name="browsercache__security__cspro__reportto"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.reportto' ) ); ?>" size="50" placeholder="Example: report-to csp-endpoint" />
			<div>
				<i><?php esc_html_e( 'Defines a reporting endpoint "group" to which violation reports should to be sent.', 'w3-total-cache' ); ?></i>
				<br/><br/>
				<i><?php esc_html_e( 'The referenced "group" should be defined in either the Report-To or Reporting-Endpoints HTTP headers. These will need to be manually defined either via htaccess or another method of modifying HTTP headers.', 'w3-total-cache' ); ?></i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_base"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.base' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_base" type="text" name="browsercache__security__cspro__base"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.base' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Restricts the %1$sURL%2$ss which can be used in a document\'s &lt;base&gt; element.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_connect"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.connect' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_connect" type="text" name="browsercache__security__cspro__connect"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.connect' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Limits the origins to which you can connect via XMLHttpRequest, WebSockets, and EventSource.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_font"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.font' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_font" type="text" name="browsercache__security__cspro__font"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.font' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies the origins that can serve web fonts.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_frame"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.frame' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_frame" type="text" name="browsercache__security__cspro__frame"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.frame' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Restricts from where the protected resource can embed frames.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_img"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.img' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_img" type="text" name="browsercache__security__cspro__img"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.img' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for images and favicons.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_media"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.media' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_media" type="text" name="browsercache__security__cspro__media"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.media' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for loading media using the &lt;audio&gt; and &lt;video&gt; elements.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_object"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.object' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_object" type="text" name="browsercache__security__cspro__object"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.object' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Allows control over the &lt;object&gt;, &lt;embed&gt;, and &lt;applet&gt; elements used by Flash and other plugins.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_script"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.script' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_script" type="text" name="browsercache__security__cspro__script"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.script' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for JavaScript.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_style"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.style' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_style" type="text" name="browsercache__security__cspro__style"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.style' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Specifies valid sources for %1$sCSS%2$s stylesheets.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_form"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.form' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_form" type="text" name="browsercache__security__cspro__form"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.form' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div>
				<i>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Restricts the %1$sURL%2$ss which can be used as the target of form submissions from a given context.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</i>
			</div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_frame_ancestors"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.frame.ancestors' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_frame_ancestors" type="text" name="browsercache__security__cspro__frame__ancestors"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.frame.ancestors' ) ); ?>" size="50" placeholder="Example: 'none'" />
			<div><i><?php esc_html_e( 'Specifies valid parents that may embed a page using &lt;frame&gt;, &lt;iframe&gt;, &lt;object&gt;, &lt;embed&gt;, or &lt;applet&gt;.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_plugin"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.plugin' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_plugin" type="text" name="browsercache__security__cspro__plugin"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.plugin' ) ); ?>" size="50" placeholder="Example: application/x-shockwave-flash" />
			<div><i><?php esc_html_e( 'Restricts the set of plugins that can be embedded into a document by limiting the types of resources which can be loaded.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_sandbox"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.sandbox' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_sandbox" type="text" name="browsercache__security__cspro__sandbox"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.sandbox' ) ); ?>" size="50" placeholder="Example: allow-popups" />
			<div><i><?php esc_html_e( 'This directive operates similarly to the &lt;iframe&gt; sandbox attribute by applying restrictions to a page\'s actions, including preventing popups, preventing the execution of plugins and scripts, and enforcing a same-origin policy.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_child"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.child' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_child" type="text" name="browsercache__security__cspro__child"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.child' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Defines the valid sources for web workers and nested browsing contexts loaded using elements such as <frame> and <iframe>. For workers, non-compliant requests are treated as fatal network errors by the user agent.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_manifest"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.manifest' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_manifest" type="text" name="browsercache__security__cspro__manifest"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.manifest' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies which manifest can be applied to the resource.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_scriptelem"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.scriptelem' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_scriptelem" type="text" name="browsercache__security__cspro__scriptelem"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.scriptelem' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for JavaScript <script> elements.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_scriptattr"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.scriptattr' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_scriptattr" type="text" name="browsercache__security__cspro__scriptattr"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.scriptattr' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for JavaScript inline event handlers.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_styleelem"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.styleelem' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_styleelem" type="text" name="browsercache__security__cspro__styleelem"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.styleelem' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for stylesheet <style> elements and <link> elements with rel="stylesheet".', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_styleattr"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.styleattr' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_styleattr" type="text" name="browsercache__security__cspro__styleattr"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.styleattr' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for inline styles applied to individual DOM elements.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_worker"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.worker' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_worker" type="text" name="browsercache__security__cspro__worker"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.worker' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Specifies valid sources for Worker, SharedWorker, or ServiceWorker scripts.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<tr>
		<th>
			<label for="browsercache_security_cspro_default"><?php Util_Ui::e_config_label( 'browsercache.security.cspro.default' ); ?></label>
		</th>
		<td>
			<input id="browsercache_security_cspro_default" type="text" name="browsercache__security__cspro__default"
				<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="<?php echo esc_attr( $this->_config->get_string( 'browsercache.security.cspro.default' ) ); ?>" size="50" placeholder="Example: 'self' 'unsafe-inline' *.domain.com" />
			<div><i><?php esc_html_e( 'Defines the defaults for directives you leave unspecified. Generally, this applies to any directive that ends with -src.', 'w3-total-cache' ); ?></i></div>
		</td>
	</tr>
	<?php
	Util_Ui::config_item(
		array(
			'key'            => 'browsercache.security.fp',
			'disabled'       => Util_Ui::sealing_disabled( 'browsercache.' ),
			'control'        => 'checkbox',
			'checkbox_label' => esc_html__( 'Feature-Policy / Permissions-Policy', 'w3-total-cache' ),
			'description'    => esc_html__( 'Allows you to control which origins can use which features.', 'w3-total-cache' ),
			'label_class'    => 'w3tc_single_column',
		)
	);
	?>

	<?php
	foreach ( $feature_policies as $i ) {
		Util_Ui::config_item(
			array(
				'key'                 => 'browsercache.security.fp.values.keyvalues.' . $i['label'],
				'value'               => ! empty( $fp_values[ $i['label'] ] ) ? $fp_values[ $i['label'] ] : '',
				'disabled'            => Util_Ui::sealing_disabled( 'browsercache.' ),
				'control'             => 'textbox',
				'label'               => $i['label'],
				'textbox_size'        => '50',
				'textbox_placeholder' => esc_html__( 'One of:', 'w3-total-cache' ) . esc_html( " * 'self' 'src' 'none' *.domain.com" ),
				'description'         => $i['description'],
			)
		);
	}
	?>
</table>

<?php Util_Ui::button_config_save( 'browsercache_security' ); ?>
<?php Util_Ui::postbox_footer(); ?>
