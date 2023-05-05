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
	<a href="#credentials"><?php esc_html_e( 'Credentials', 'w3-total-cache' ); ?></a> |
	<a href="#general"><?php esc_html_e( 'General', 'w3-total-cache' ); ?></a> |
	<a href="#info"><?php esc_html_e( 'Information', 'w3-total-cache' ); ?></a>
</p>
<p>
	<?php esc_html_e( 'CloudFlare extension is currently ', 'w3-total-cache' ); ?>
	<?php
	if ( $config->is_extension_active_frontend( 'cloudflare' ) ) {
		echo '<span class="w3tc-enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) . '</span>';
	} else {
		echo '<span class="w3tc-disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) . '</span>';
	}
	?>
	.
<p>

<form action="admin.php?page=w3tc_extensions&amp;extension=cloudflare&amp;action=view" method="post">
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
		<input type="submit" name="w3tc_cloudflare_flush" value="<?php esc_html_e( 'Purge CloudFlare cache', 'w3-total-cache' ); ?>" class="button" />
		<?php esc_html_e( 'if needed.', 'w3-total-cache' ); ?>
	</p>
</form>

<form action="admin.php?page=w3tc_extensions&amp;extension=cloudflare&amp;action=view" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Credentials', 'w3-total-cache' ), '', 'credentials' ); ?>
		<table class="form-table">
			<tr>
				<th style="width: 300px;">
					<label>
						<?php
						esc_html_e( 'Specify account credentials:', 'w3-total-cache' );
						?>
					</label>
				</th>
				<td>
					<?php if ( 'not_cofigured' !== $state ) : ?>
						<input class="w3tc_extension_cloudflare_authorize button-primary"
							type="button"
							value="<?php esc_attr_e( 'Reauthorize', 'w3-total-cache' ); ?>"
							/>
					<?php else : ?>
						<input class="w3tc_extension_cloudflare_authorize button-primary"
							type="button"
							value="<?php esc_attr_e( 'Authorize', 'w3-total-cache' ); ?>"
							/>
					<?php endif ?>
				</td>
			</tr>

			<?php if ( 'not_configured' !== $state ) : ?>
				<tr>
					<th>
						<label><?php esc_attr_e( 'Zone:', 'w3-total-cache' ); ?></label>
					</th>
					<td class="w3tc_config_value_text">
						<?php echo esc_html( $config->get_string( array( 'cloudflare', 'zone_name' ) ) ); ?>
					</td>
				</tr>
			<?php endif ?>
		</table>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'General', 'w3-total-cache' ), '', 'general' ); ?>
		<?php if ( 'not_configured' === $state ) : ?>
			<table class="form-table">
				<tr>
					<td colspan="2">
						<?php esc_html_e( 'Authenticate your account in order to access settings.', 'w3-total-cache' ); ?>
					</td>
				</tr>
			</table>
		<?php elseif ( 'not_available' === $state ) : ?>
			<table class="form-table">
				<tr>
					<td colspan="2">
						<?php esc_html__( 'CloudFlare not available: ', 'w3-total-cache' ) . esc_html( $error_message ); ?>
					</td>
				</tr>
			</table>
		<?php elseif ( 'available' === $state ) : ?>
			<table class="form-table">
				<?php
				Util_Ui::config_item(
					array(
						'key'              => array( 'cloudflare', 'widget_interval' ),
						'label'            => esc_html__( 'Widget statistics interval:', 'w3-total-cache' ),
						'control'          => 'selectbox',
						'selectbox_values' => array(
							'-30'    => esc_html__( 'Last 30 minutes', 'w3-total-cache' ),
							'-360'   => esc_html__( 'Last 6 hours', 'w3-total-cache' ),
							'-720'   => esc_html__( 'Last 12 hours', 'w3-total-cache' ),
							'-1440'  => esc_html__( 'Last 24 hours', 'w3-total-cache' ),
							'-10080' => esc_html__( 'Last week', 'w3-total-cache' ),
							'-43200' => esc_html__( 'Last month', 'w3-total-cache' ),
						),
					)
				);

				Util_Ui::config_item(
					array(
						'key'         => array( 'cloudflare', 'widget_cache_mins' ),
						'label'       => esc_html__( 'Cache time:', 'w3-total-cache' ),
						'control'     => 'textbox',
						'description' => esc_html__( 'How many minutes data retrieved from CloudFlare: should be stored. Minimum is 1 minute.', 'w3-total-cache' ),
					)
				);

				Util_Ui::config_item(
					array(
						'key'            => array( 'cloudflare', 'pagecache' ),
						'label'          => esc_html__( 'Page caching:', 'w3-total-cache' ),
						'control'        => 'checkbox',
						'checkbox_label' => esc_html__( 'Flush CloudFlare on Post Modifications:', 'w3-total-cache' ),
						'description'    => esc_html__( 'Enable when you have html pages cached on CloudFlare level.', 'w3-total-cache' ),
					)
				);

				Util_Ui::config_item(
					array(
						'key'            => array( 'cloudflare', 'minify_js_rl_exclude' ),
						'label'          => esc_html__( 'Minified JS Rocket Loader Exclude:', 'w3-total-cache' ),
						'checkbox_label' => esc_html__( 'Exclude minified JS files from being processed by Rocket Loader:', 'w3-total-cache' ),
						'control'        => 'checkbox',
						'description'    => esc_html__( 'Exclusion achieved by adding data-cfasync="false" to script tags.', 'w3-total-cache' ),
					)
				);
				?>
			</table>
		<?php endif; ?>

		<?php Util_Ui::button_config_save( 'extension_cloudflare_general' ); ?>
		<?php Util_Ui::postbox_footer(); ?>


		<?php if ( 'available' === $state ) : ?>
			<?php Util_Ui::postbox_header( esc_html__( 'CloudFlare: Caching', 'w3-total-cache' ), '', 'general' ); ?>
			<table class="form-table">
				<?php
				self::cloudflare_checkbox(
					$settings,
					array(
						'key'         => 'development_mode',
						'label'       => esc_html__( 'Development mode:', 'w3-total-cache' ),
						'description' => esc_html__( 'Development Mode temporarily allows you to enter development mode for your websites if you need to make changes to your site. This will bypass CloudFlare\'s accelerated cache and slow down your site, but is useful if you are making changes to cacheable content (like images, css, or JavaScript) and would like to see those changes right away.', 'w3-total-cache' ),
					)
				);
				self::cloudflare_selectbox(
					$settings,
					array(
						'key'         => 'cache_level',
						'label'       => esc_html__( 'Cache level:', 'w3-total-cache' ),
						'values'      => array(
							''           => '',
							'aggressive' => esc_html__( 'Aggressive (cache all static resources, including ones with a query string)', 'w3-total-cache' ),
							'basic'      => esc_html__( 'Basic (cache most static resources (i.e., css, images, and JavaScript)', 'w3-total-cache' ),
							'simplified' => esc_html__( 'Simplified (ignore the query string when delivering a cached resource)', 'w3-total-cache' ),
						),
						'description' => esc_html__( 'How the content is cached by CloudFlare', 'w3-total-cache' ),
					)
				);
				self::cloudflare_checkbox(
					$settings,
					array(
						'key'         => 'sort_query_string_for_cache',
						'label'       => esc_html__( 'Query string sorting:', 'w3-total-cache' ),
						'description' => esc_html__( 'CloudFlare will treat files with the same query strings as the same file in cache, regardless of the order of the query strings.', 'w3-total-cache' ),
					)
				);
				self::cloudflare_selectbox(
					$settings,
					array(
						'key'         => 'browser_cache_ttl',
						'label'       => wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Browser cache %1$sTTL%2$s:',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Time-to-Live', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						),
						'values'      => array(
							''         => '',
							'30'       => '30',
							'60'       => '60',
							'300'      => '300',
							'1200'     => '1200',
							'1800'     => '1800',
							'3600'     => '3600',
							'7200'     => '7200',
							'10800'    => '10800',
							'14400'    => '14400',
							'18000'    => '18000',
							'28800'    => '28800',
							'43200'    => '43200',
							'57600'    => '57600',
							'72000'    => '72000',
							'86400'    => '86400',
							'172800'   => '172800',
							'259200'   => '259200',
							'345600'   => '345600',
							'432000'   => '432000',
							'691200'   => '691200',
							'1382400'  => '1382400',
							'2073600'  => '2073600',
							'2678400'  => '2678400',
							'5356800'  => '5356800',
							'16070400' => '16070400',
							'31536000' => '31536000',
						),
						'description' => wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Browser cache %1$sTTL%2$s (in seconds) specifies how long CloudFlare-cached resources will remain on your visitors\' computers.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Time-to-Live', 'w3-total-cache' ) . '">',
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
				self::cloudflare_selectbox(
					$settings,
					array(
						'key'         => 'challenge_ttl',
						'label'       => wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Challenge %1$sTTL%2$s:',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Time-to-Live', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						),
						'values'      => array(
							''         => '',
							'300'      => '300',
							'900'      => '900',
							'1800'     => '1800',
							'2700'     => '2700',
							'3600'     => '3600',
							'7200'     => '7200',
							'10800'    => '10800',
							'14400'    => '14400',
							'28800'    => '28800',
							'57600'    => '57600',
							'86400'    => '86400',
							'604800'   => '604800',
							'2592000'  => '2592000',
							'31536000' => '31536000',
						),
						'description' => wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Specify how long a visitor is allowed access to your site after successfully completing a challenge (such as a CAPTCHA). After the %1$sTTL%2$s has expired the visitor will have to complete a new challenge.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Time-to-Live', 'w3-total-cache' ) . '">',
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
				self::cloudflare_selectbox(
					$settings,
					array(
						'key'         => 'edge_cache_ttl',
						'label'       => esc_html__( 'Edge cache TTL:', 'w3-total-cache' ),
						'values'      => array(
							''         => '',
							'300'      => '300',
							'900'      => '900',
							'1800'     => '1800',
							'2700'     => '2700',
							'3600'     => '3600',
							'7200'     => '7200',
							'10800'    => '10800',
							'14400'    => '14400',
							'28800'    => '28800',
							'57600'    => '57600',
							'86400'    => '86400',
							'604800'   => '604800',
							'2592000'  => '2592000',
							'31536000' => '31536000',
						),
						'description' => esc_html__( 'Controls how long CloudFlare\'s edge servers will cache a resource before getting back to your server for a fresh copy.', 'w3-total-cache' ),
					)
				);
				?>
			</table>
			<?php
			self::cloudflare_button_save( 'caching' );
			Util_Ui::postbox_footer();

			Util_Ui::postbox_header( esc_html__( 'CloudFlare: Content Processing', 'w3-total-cache' ), '', 'general' );
			echo '<table class="form-table">';
			self::cloudflare_selectbox(
				$settings,
				array(
					'key'         => 'rocket_loader',
					'label'       => esc_html__( 'Rocket Loader:', 'w3-total-cache' ),
					'values'      => array(
						''       => '',
						'off'    => esc_html__( 'Off', 'w3-total-cache' ),
						'on'     => esc_html__( 'On (automatically run on the JavaScript resources on your site)', 'w3-total-cache' ),
						'manual' => esc_html__( 'Manual (run when attribute present only)', 'w3-total-cache' ),
					),
					'description' => esc_html__( 'Rocket Loader is a general-purpose asynchronous JavaScript loader coupled with a lightweight virtual browser which can safely run any JavaScript code after window.onload.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'minify_js',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Minify %1$sJS%2$s:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'description' => esc_html__( 'Minify JavaScript files.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'minify_css',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Minify %1$sCSS%2$s:',
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
					),
					'description' => 'Minify CSS files.',
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'minify_html',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Minify %1$sHTML%2$s:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'HyperText Markup Language', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'description' => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Minify %1$sHTML%2$s content.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'HyperText Markup Language', 'w3-total-cache' ) . '">',
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
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'server_side_exclude',
					'label'       => esc_html__( 'Server side exclude:', 'w3-total-cache' ),
					'description' => esc_html__( 'If there is sensitive content on your website that you want visible to real visitors, but that you want to hide from suspicious visitors, all you have to do is wrap the content with CloudFlare SSE tags.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'email_obfuscation',
					'label'       => esc_html__( 'Email obfuscation:', 'w3-total-cache' ),
					'description' => esc_html__( 'Encrypt email adresses on your web page from bots, while keeping them visible to humans. ', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'response_buffering',
					'label'       => esc_html__( 'Response buffering"', 'w3-total-cache' ),
					'description' => esc_html__( 'CloudFlare may buffer the whole payload to deliver it at once to the client versus allowing it to be delivered in chunks.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'prefetch_preload',
					'label'       => esc_html__( 'Prefetch preload:', 'w3-total-cache' ),
					'description' => esc_html__( 'CloudFlare will prefetch any URLs that are included in the response headers.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'mobile_redirect',
					'label'       => esc_html__( 'Mobile redirect:', 'w3-total-cache' ),
					'description' => esc_html__( 'Automatically redirect visitors on mobile devices to a mobile-optimized subdomain', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'origin_error_page_pass_thru',
					'label'       => esc_html__( 'Enable error pages:', 'w3-total-cache' ),
					'description' => esc_html__( 'CloudFlare will proxy customer error pages on any 502,504 errors on origin server instead of showing a default CloudFlare error page. This does not apply to 522 errors and is limited to Enterprise Zones.', 'w3-total-cache' ),
				)
			);
			echo '</table>';
			self::cloudflare_button_save( 'content_processing' );
			Util_Ui::postbox_footer();

			Util_Ui::postbox_header( esc_html__( 'CloudFlare: Image Processing', 'w3-total-cache' ), '', 'general' );
			echo '<table class="form-table">';
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'hotlink_protection',
					'label'       => esc_html__( 'Hotlink protection:', 'w3-total-cache' ),
					'description' => esc_html__( 'When enabled, the Hotlink Protection option ensures that other sites cannot suck up your bandwidth by building pages that use images hosted on your site.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'mirage',
					'label'       => esc_html__( 'Mirage:', 'w3-total-cache' ),
					'description' => esc_html__( 'Automatically optimize image loading for website visitors on mobile devices', 'w3-total-cache' ),
				)
			);
			self::cloudflare_selectbox(
				$settings,
				array(
					'key'         => 'polish',
					'label'       => esc_html__( 'Images polishing:', 'w3-total-cache' ),
					'values'      => array(
						''         => '',
						'off'      => esc_html__( 'Off', 'w3-total-cache' ),
						'lossless' => esc_html__( 'Lossless (Reduce the size of PNG, JPEG, and GIF files - no impact on visual quality)', 'w3-total-cache' ),
						'lossy'    => esc_html__( 'Lossy (Further reduce the size of JPEG files for faster image loading)', 'w3-total-cache' ),
					),
					'description' => esc_html__( 'Strips metadata and compresses your images for faster page load times.', 'w3-total-cache' ),
				)
			);
			echo '</table>';
			self::cloudflare_button_save( 'image_processing' );
			Util_Ui::postbox_footer();

			Util_Ui::postbox_header( esc_html__( 'CloudFlare: Protection', 'w3-total-cache' ), '', 'general' );
			echo '<table class="form-table">';
			self::cloudflare_selectbox(
				$settings,
				array(
					'key'         => 'security_level',
					'label'       => esc_html__( 'Security level:', 'w3-total-cache' ),
					'values'      => array(
						''                => '',
						'essentially_off' => esc_html__( 'Off', 'w3-total-cache' ),
						'low'             => esc_html__( 'Low', 'w3-total-cache' ),
						'medium'          => esc_html__( 'Medium', 'w3-total-cache' ),
						'high'            => esc_html__( 'High', 'w3-total-cache' ),
						'under_attack'    => esc_html__( 'Under Attack', 'w3-total-cache' ),
					),
					'description' => esc_html__( 'security profile for your website, which will automatically adjust each of the security settings.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'browser_check',
					'label'       => esc_html__( 'Browser integrity check:', 'w3-total-cache' ),
					'description' => esc_html__( 'Browser Integrity Check is similar to Bad Behavior and looks for common HTTP headers abused most commonly by spammers and denies access to your page. It will also challenge visitors that do not have a user agent or a non standard user agent (also commonly used by abuse bots, crawlers or visitors).', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'always_online',
					'label'       => esc_html__( 'Always online:', 'w3-total-cache' ),
					'description' => esc_html__( 'When enabled, Always Online will serve pages from our cache if your server is offline', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'waf',
					'label'       => esc_html__( 'Web application firewall:', 'w3-total-cache' ),
					'description' => esc_html__( 'The Web Application Firewall (WAF) examines HTTP requests to your website. It inspects both GET and POST requests and applies rules to help filter out illegitimate traffic from legitimate website visitors.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'advanced_ddos',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Advanced %1$sDDoS%2$s protection:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Distributed Denial of Service', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'description' => esc_html__( 'Advanced protection from Distributed Denial of Service (DDoS) attacks on your website.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_textbox(
				$settings,
				array(
					'key'         => 'max_upload',
					'label'       => esc_html__( 'Max upload:', 'w3-total-cache' ),
					'description' => esc_html__( 'Max size of file allowed for uploading', 'w3-total-cache' ),
				)
			);
			echo '</table>';
			self::cloudflare_button_save( 'protection' );
			Util_Ui::postbox_footer();

			Util_Ui::postbox_header(
				wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'CloudFlare: %1$sIP%2$s',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Internet Protocol', 'w3-total-cache' ) . '">',
						'</acornym>'
					),
					array(
						'acronym' => array(
							'title' => array(),
						),
					)
				),
				'',
				'general'
			);
			echo '<table class="form-table">';
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'ip_geolocation',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sIP%2$s geolocation:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Internet Protocol', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'description' => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Enable %1$sIP%2$s Geolocation to have CloudFlare geolocate visitors to your website and pass the country code to you.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Internet Protocol', 'w3-total-cache' ) . '">',
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
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'ipv6',
					'label'       => esc_html__( 'IPv6:', 'w3-total-cache' ),
					'description' => esc_html__( 'Enable IPv6.', 'w3-total-cache' ),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'true_client_ip_header',
					'label'       => esc_html__( 'True client IP:', 'w3-total-cache' ),
					'description' => esc_html__( 'Allows customer to continue to use True Client IP (Akamai feature) in the headers we send to the origin.', 'w3-total-cache' ),
				)
			);
			echo '</table>';
			self::cloudflare_button_save( 'ip' );
			Util_Ui::postbox_footer();

			Util_Ui::postbox_header(
				wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'CloudFlare: %1$sSSL%2$s',
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
				),
				'',
				'general'
			);
			echo '<table class="form-table">';
			self::cloudflare_selectbox(
				$settings,
				array(
					'key'         => 'ssl',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sSSL%2$s:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Secure Sockets Layer">', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'values'      => array(
						''            => '',
						'off'         => esc_html__( 'Off', 'w3-total-cache' ),
						'flexible'    => esc_html__( 'Flexible (HTTPS to end-user only)', 'w3-total-cache' ),
						'full'        => esc_html__( 'Full (https everywhere)', 'w3-total-cache' ),
						'full_strict' => esc_html__( 'Strict', 'w3-total-cache' ),
					),
					'description' => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sSSL%2$s encrypts your visitor\'s connection and safeguards credit card numbers and other personal data to and from your website.',
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
					),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'security_header',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Security header (%1$sSSL%2$s):',
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
					),
					'description' => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Enables or disables %1$sSSL%2$s header.',
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
					),
				)
			);
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'tls_1_2_only',
					'label'       => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sTLS%2$s 1.2 only:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Transport Layer Security', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'description' => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Enable Crypto %1$sTLS%2$s 1.2 feature for this zone and prevent use of previous versions.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Transport Layer Security', 'w3-total-cache' ) . '">',
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
			self::cloudflare_checkbox(
				$settings,
				array(
					'key'         => 'tls_client_auth',
					'label'       => '<acronym title="Transport Layer Security">TLS</acronym> client auth:',
					'description' => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sTLS%2$s Client authentication requires CloudFlare to connect to your origin server using a client certificate',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Transport Layer Security', 'w3-total-cache' ) . '">',
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
			echo '</table>';
			self::cloudflare_button_save( 'ssl' );
			Util_Ui::postbox_footer();
		endif;
		?>
	</div>
</form>
