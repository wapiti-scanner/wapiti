<?php
/**
 * File: general.php
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

require W3TC_INC_DIR . '/options/common/header.php';
?>

<p>
	<?php
	echo wp_kses(
		sprintf(
			// translators: 1 HTML span tag indicating plugin enabled/disabled.
			__(
				'The plugin is currently %1$s If an option is disabled it means that either your current installation is not compatible or software installation is required.',
				'w3-total-cache'
			),
			'<span class="w3tc-' . ( $enabled ? 'enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) : 'disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) ) . '</span>.'
		),
		array(
			'span' => array(
				'class' => array(),
			),
		)
	);
	?>
</p>
<form id="w3tc_form" action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'General', 'w3-total-cache' ), '' ); ?>
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Preview mode:', 'w3-total-cache' ); ?></th>
				<td>
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
					<?php if ( $this->_config->is_preview() ) : ?>
						<input type="submit" name="w3tc_config_preview_disable" class="button-primary" value="<?php esc_attr_e( 'Disable', 'w3-total-cache' ); ?>" />
						<?php
						echo wp_kses(
							Util_Ui::button_link(
								esc_html__( 'Deploy', 'w3-total-cache' ),
								esc_url( wp_nonce_url( sprintf( 'admin.php?page=%1$s&w3tc_config_preview_deploy', $this->_page ), 'w3tc' ) )
							),
							array(
								'input' => array(
									'type'    => array(),
									'name'    => array(),
									'class'   => array(),
									'value'   => array(),
									'onclick' => array(),
								),
							)
						);
						?>
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 HTML input submit to preview changes.
									__(
										'To preview any changed settings (without deploying): %1$s',
										'w3-total-cache'
									),
									Util_Ui::preview_link()
								),
								array(
									'input' => array(
										'type'    => array(),
										'name'    => array(),
										'class'   => array(),
										'value'   => array(),
										'onclick' => array(),
									),
								)
							);
							?>
						</p>
					<?php else : ?>
						<input type="submit" name="w3tc_config_preview_enable" class="button-primary" value="<?php esc_attr_e( 'Enable', 'w3-total-cache' ); ?>" />
					<?php endif; ?>
					<p class="description"><?php esc_html_e( 'Use preview mode to test configuration scenarios prior to releasing them (deploy) on the actual site. Preview mode remains active even after deploying settings until the feature is disabled.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'general_general' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header( esc_html__( 'Page Cache', 'w3-total-cache' ), '', 'page_cache' );
		Util_Ui::config_overloading_button( array( 'key' => 'pgcache.configuration_overloaded' ) );
		?>

		<p><?php esc_html_e( 'Enable page caching to decrease the response time of the site.', 'w3-total-cache' ); ?></p>

		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'pgcache.enabled',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
					'description'    => esc_html__( 'Caching pages will reduce the response time of your site and increase the scale of your web server.', 'w3-total-cache' ),
				)
			);
			Util_Ui::config_item(
				array(
					'key'                 => 'pgcache.engine',
					'control'             => 'selectbox',
					'selectbox_values'    => array(
						'file'            => array(
							'label'    => esc_html__( 'Disk: Basic', 'w3-total-cache' ),
							'optgroup' => 0,
						),
						'file_generic'    => array(
							'label'    => esc_html__( 'Disk: Enhanced', 'w3-total-cache' ),
							'optgroup' => 0,
						),
						'apc'             => array(
							'disabled' => ! Util_Installed::apc(),
							'label'    => esc_html__( 'Opcode: Alternative PHP Cache (APC / APCu)', 'w3-total-cache' ),
							'optgroup' => 1,
						),
						'eaccelerator'    => array(
							'disabled' => ! Util_Installed::eaccelerator(),
							'label'    => esc_html__( 'Opcode: eAccelerator', 'w3-total-cache' ),
							'optgroup' => 1,
						),
						'xcache'          => array(
							'disabled' => ! Util_Installed::xcache(),
							'label'    => esc_html__( 'Opcode: XCache', 'w3-total-cache' ),
							'optgroup' => 1,
						),
						'wincache'        => array(
							'disabled' => ! Util_Installed::wincache(),
							'label'    => esc_html__( 'Opcode: WinCache', 'w3-total-cache' ),
							'optgroup' => 1,
						),
						'memcached'       => array(
							'disabled' => ! Util_Installed::memcached(),
							'label'    => esc_html__( 'Memcached', 'w3-total-cache' ),
							'optgroup' => 2,
						),
						'nginx_memcached' => array(
							'disabled' => ! Util_Installed::memcached_memcached() || ! $is_pro,
							'label'    => esc_html__( 'Nginx + Memcached', 'w3-total-cache' ) . ( $is_pro ? '' : esc_html__( ' (available after upgrade)', 'w3-total-cache' ) ),
							'optgroup' => 2,
						),
						'redis'           => array(
							'disabled' => ! Util_Installed::redis(),
							'label'    => esc_html__( 'Redis', 'w3-total-cache' ),
							'optgroup' => 2,
						),
					),
					'selectbox_optgroups' => array(
						esc_html__( 'Shared Server (disk enhanced is best):', 'w3-total-cache' ),
						esc_html__( 'Dedicated / Virtual Server:', 'w3-total-cache' ),
						esc_html__( 'Multiple Servers:', 'w3-total-cache' ),
					),
				)
			);
			?>
		</table>

		<?php
		Util_Ui::button_config_save(
			'general_pagecache',
			'<input type="submit" name="w3tc_flush_pgcache" value="' .
				esc_attr__( 'Empty cache', 'w3-total-cache' ) . '"' .
				( $pgcache_enabled ? '' : ' disabled="disabled" ' ) .
				' class="button" />'
		);
		?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header( esc_html__( 'Minify', 'w3-total-cache' ), '', 'minify' );
		Util_Ui::config_overloading_button( array( 'key' => 'minify.configuration_overloaded' ) );
		?>
		<p>
			<?php
			w3tc_e(
				'minify.general.header',
				sprintf(
					// translators: 1 HTML acronym for Cascading Style Sheet (CSS), 2 HTML acronym for JavaScript (JS),
					// translators: 3 HTML acronym for Hypertext Markup Language (HTML).
					__( 'Reduce load time by decreasing the size and number of %1$s and %2$s files. Automatically remove unnecessary data from %1$s, %2$s, feed, page and post %3$s.', 'w3-total-cache' ),
					'<acronym title="' . __( 'Cascading Style Sheet', 'w3-total-cache' ) . '">' . __( 'CSS', 'w3-total-cache' ) . '</acronym>',
					'<acronym title="' . __( 'JavaScript', 'w3-total-cache' ) . '">' . __( 'JS', 'w3-total-cache' ) . '</acronym>',
					'<acronym title="' . __( 'Hypertext Markup Language', 'w3-total-cache' ) . '">' . __( 'HTML', 'w3-total-cache' ) . '</acronym>'
				)
			);
			?>
		</p>

		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'minify.enabled',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
					'description'    => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
							// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
							__(
								'Minification can decrease file size of %1$sHTML%2$s, %3$sCSS%4$s, %5$sJS%6$s and feeds respectively by ~10%% on average.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'control_after'  => ' <a class="w3tc-control-after" target="_blank" href="' . esc_url( 'https://www.boldgrid.com/support/w3-total-cache/w3-total-cache-minify-faq/?utm_source=w3tc&utm_medium=learn_more_links&utm_campaign=minify_faq' ) . '" title="' .
						esc_attr__( 'Minify frequently asked questions', 'w3-total-cache' ) . '">' . esc_html__( 'Learn more', 'w3-total-cache' ) .
						'<span class="dashicons dashicons-external"></span></a>',
				)
			);

			Util_Ui::config_item(
				array(
					'key'               => 'minify.auto',
					'value'             => ( $this->_config->get_boolean( 'minify.auto' ) ? 1 : 0 ),
					'control'           => 'radiogroup',
					'radiogroup_values' => array(
						'1' => esc_html__( 'Auto', 'w3-total-cache' ),
						'0' => esc_html__( 'Manual', 'w3-total-cache' ),
					),
					'description'       => esc_html__(
						'Select manual mode to use fields on the minify settings tab to specify files to be minified, otherwise files will be minified automatically.',
						'w3-total-cache'
					),
					'control_after'     => ' <a class="w3tc-control-after" target="_blank" href="' . esc_url( 'https://www.boldgrid.com/support/w3-total-cache/how-to-use-manual-minify-for-css-and-js/?utm_source=w3tc&utm_medium=learn_more_links&utm_campaign=manual_minify#difference-between-auto-and-manual-minify' ) . '" title="'
						. esc_attr__( 'How to use manual minify', 'w3-total-cache' ) . '">' . esc_html__( 'Learn more', 'w3-total-cache' ) .
						'<span class="dashicons dashicons-external"></span></a>',
				)
			);

			Util_Ui::config_item_engine(
				array(
					'key'           => 'minify.engine',
					'control_after' => ' <a class="w3tc-control-after" target="_blank" href="' . esc_url( 'https://www.boldgrid.com/support/w3-total-cache/choosing-a-minification-method-for-w3-total-cache/?utm_source=w3tc&utm_medium=learn_more_links&utm_campaign=minify_engine' ) . '" title="' .
						esc_attr__( 'Choosing a minification method', 'w3-total-cache' ) . '">' . esc_html__( 'Learn more', 'w3-total-cache' ) .
						'<span class="dashicons dashicons-external"></span></a>',
				)
			);

			Util_Ui::config_item(
				array(
					'key'              => 'minify.html.engine',
					'control'          => 'selectbox',
					'selectbox_values' => array(
						'html'     => esc_html__( 'Minify (default)', 'w3-total-cache' ),
						'htmltidy' => array(
							'disabled' => ! Util_Installed::tidy(),
							'label'    => esc_html__( 'HTML Tidy', 'w3-total-cache' ),
						),
					),
					'control_after'    => ' <a class="w3tc-control-after" target="_blank" href="' . esc_url( 'https://www.boldgrid.com/support/w3-total-cache/minify/html-minify-or-tidy/?utm_source=w3tc&utm_medium=learn_more_links&utm_campaign=minify_html#minify-default' ) . '" title="' .
						esc_attr__( 'How to use minify HTML', 'w3-total-cache' ) . '">' . esc_html__( 'Learn more', 'w3-total-cache' ) .
						'<span class="dashicons dashicons-external"></span></a>',
				)
			);

			Util_Ui::config_item(
				array(
					'key'              => 'minify.js.engine',
					'control'          => 'selectbox',
					'selectbox_values' => array(
						'js'         => esc_html__( 'JSMin (default)', 'w3-total-cache' ),
						'googleccjs' => esc_html__( 'Google Closure Compiler (Web Service)', 'w3-total-cache' ),
						'ccjs'       => esc_html__( 'Google Closure Compiler (Local Java)', 'w3-total-cache' ),
						'jsminplus'  => esc_html__( 'Narcissus', 'w3-total-cache' ),
						'yuijs'      => esc_html__( 'YUI Compressor', 'w3-total-cache' ),
					),
				)
			);
			Util_Ui::config_item(
				array(
					'key'              => 'minify.css.engine',
					'control'          => 'selectbox',
					'selectbox_values' => array(
						'css'     => esc_html__( 'Minify (default)', 'w3-total-cache' ),
						'csstidy' => array(
							'label'    => esc_html__( 'CSS Tidy', 'w3-total-cache' ),
							'disabled' => ( version_compare( PHP_VERSION, '5.4.0', '<' ) ? true : false ),
						),
						'cssmin'  => esc_html__( 'YUI Compressor (PHP)', 'w3-total-cache' ),
						'yuicss'  => esc_html__( 'YUI Compressor', 'w3-total-cache' ),
					),
				)
			);
			?>
		</table>

		<?php
		Util_Ui::button_config_save(
			'general_minify',
			'<input type="submit" name="w3tc_flush_minify" value="' .
				esc_attr__( 'Empty cache', 'w3-total-cache' ) . '" ' .
				( $minify_enabled ? '' : ' disabled="disabled" ' ) .
				' class="button" />'
		);
		?>
		<?php Util_Ui::postbox_footer(); ?>


		<?php do_action( 'w3tc_settings_general_boxarea_system_opcache' ); ?>

		<?php
		Util_Ui::postbox_header( esc_html__( 'Database Cache', 'w3-total-cache' ), '', 'database_cache' );
		Util_Ui::config_overloading_button( array( 'key' => 'dbcache.configuration_overloaded' ) );
		?>

		<p><?php esc_html_e( 'Enable database caching to reduce post, page and feed creation time.', 'w3-total-cache' ); ?></p>

		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'dbcache.enabled',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
					'description'    => esc_html__( 'Caching database objects decreases the response time of your site. Best used if object caching is not possible.', 'w3-total-cache' ),
				)
			);
			Util_Ui::config_item_engine( array( 'key' => 'dbcache.engine' ) );
			?>

			<?php if ( Util_Environment::is_w3tc_pro() && is_network_admin() ) : ?>
				<?php require W3TC_INC_OPTIONS_DIR . '/enterprise/dbcluster_general_section.php'; ?>
			<?php endif; ?>
		</table>

		<?php
		Util_Ui::button_config_save(
			'general_dbcache',
			'<input type="submit" name="w3tc_flush_dbcache" value="' .
				esc_html__( 'Empty cache', 'w3-total-cache' ) . '" ' .
				( $dbcache_enabled ? '' : ' disabled="disabled" ' ) .
				' class="button" />'
		);
		?>

		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header( esc_html__( 'Object Cache', 'w3-total-cache' ), '', 'object_cache' );
		Util_Ui::config_overloading_button( array( 'key' => 'objectcache.configuration_overloaded' ) );
		?>

		<p><?php esc_html_e( 'Enable object caching to further reduce execution time for common operations.', 'w3-total-cache' ); ?></p>

		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'objectcache.enabled',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
					'description'    => wp_kses(
						sprintf(
							// translators: 1 opening HTML a tag to WordPress codex for WP Object Cache, 2 Opening HTML acronym tag,
							// translators: 3 closing HTML acronym tag, 4 closing HTML a tag.
							__(
								'Object caching greatly increases performance for highly dynamic sites that use the %1$sObject Cache %2$sAPI%3$s%4$s.',
								'w3-total-cache'
							),
							'<a href="' . esc_url( 'http://codex.wordpress.org/Class_Reference/WP_Object_Cache' ) . '" target="_blank">',
							'<acronym title="' . esc_attr__( 'Application Programming Interface', 'w3-total-cache' ) . '">',
							'</acronym>',
							'</a>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
							'a'       => array(
								'href'   => array(),
								'target' => array(),
							),
						)
					),
				)
			);
			Util_Ui::config_item_engine( array( 'key' => 'objectcache.engine' ) );
			?>
		</table>

		<?php
		Util_Ui::button_config_save(
			'general_objectcache',
			'<input type="submit" name="w3tc_flush_objectcache" value="' .
				esc_attr__( 'Empty cache', 'w3-total-cache' ) . '" ' .
				( $objectcache_enabled ? '' : ' disabled="disabled" ' ) .
				' class="button" />'
		);
		?>

		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header( esc_html__( 'Browser Cache', 'w3-total-cache' ), '', 'browser_cache' );
		Util_Ui::config_overloading_button( array( 'key' => 'browsercache.configuration_overloaded' ) );
		?>

		<p><?php esc_html_e( 'Reduce server load and decrease response time by using the cache available in site visitor\'s web browser.', 'w3-total-cache' ); ?></p>

		<table class="form-table">
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'browsercache.enabled',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Enable', 'w3-total-cache' ),
					'description'    => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Enable %1$sHTTP%2$s compression and add headers to reduce server load and decrease file load time.',
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
					),
				)
			);
			?>
		</table>

		<?php Util_Ui::button_config_save( 'general_browsercache' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php do_action( 'w3tc_settings_general_boxarea_cdn' ); ?>

		<?php
		Util_Ui::postbox_header( esc_html__( 'Reverse Proxy', 'w3-total-cache' ), '', 'reverse_proxy' );
		Util_Ui::config_overloading_button( array( 'key' => 'varnish.configuration_overloaded' ) );
		?>

		<p>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML a tag to W3TC Page Cache admin page, 2 closing HTML a tag,
					// translators: 3 opening HTML a tag to W3TC Browsercache admin page, 4 closing HTML a tag.
					__(
						'A reverse proxy adds scale to an server by handling requests before WordPress does. Purge settings are set on the %1$sPage Cache settings%2$s page and %3$sBrowser Cache settings%4$s are set on the browser cache settings page.',
						'w3-total-cache'
					),
					'<a href="' . esc_url( self_admin_url( 'admin.php?page=w3tc_pgcache' ) ) . '">',
					'</a>',
					'<a href="' . esc_url( self_admin_url( 'admin.php?page=w3tc_browsercache' ) ) . '">',
					'</a>'
				),
				array(
					'a' => array(
						'href' => array(),
					),
				)
			);
			?>
		</p>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'varnish.enabled' ); ?> <?php Util_Ui::e_config_label( 'varnish.enabled' ); ?></label><br />
				</th>
			</tr>
			<tr>
				<th><label for="pgcache_varnish_servers"><?php Util_Ui::e_config_label( 'varnish.servers' ); ?></label></th>
				<td>
					<textarea id="pgcache_varnish_servers" name="varnish__servers"
						cols="40" rows="5" <?php Util_Ui::sealing_disabled( 'varnish.' ); ?>><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'varnish.servers' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
								// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
								__(
									'Specify the IP addresses of your varnish instances above. The %1$sVCL%2$s\'s %3$sACL%4$s must allow this request.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Varnish Configuration Language', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<acronym title="' . esc_attr__( 'Access Control List', 'w3-total-cache' ) . '">',
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
		</table>

		<?php
		Util_Ui::button_config_save(
			'general_varnish',
			'<input type="submit" name="w3tc_flush_varnish" value="' .
				esc_attr__( 'Purge cache', 'w3-total-cache' ) . '"' .
				( $varnish_enabled ? '' : ' disabled="disabled" ' ) .
				' class="button" />'
		);
		?>

		<?php Util_Ui::postbox_footer(); ?>

		<?php if ( $is_pro ) : ?>
			<?php Util_Ui::postbox_header( esc_html__( 'Message Bus', 'w3-total-cache' ), '', 'amazon_sns' ); ?>
			<p>
				<?php esc_html_e( 'Allows policy management to be shared between a dynamic pool of servers. For example, each server in a pool to use opcode caching (which is not a shared resource) and purging is then syncronized between any number of servers in real-time; each server therefore behaves identically even though resources are not shared.', 'w3-total-cache' ); ?>
			</p>
			<table class="form-table">
				<tr>
					<th colspan="2">
						<input type="hidden" name="cluster__messagebus__enabled" value="0" />
						<label><input class="enabled" type="checkbox" name="cluster__messagebus__enabled" value="1"<?php checked( $this->_config->get_boolean( 'cluster.messagebus.enabled' ), true ); ?> /> <?php Util_Ui::e_config_label( 'cluster.messagebus.enabled' ); ?></label><br />
					</th>
				</tr>
				<tr>
					<th><label for="cluster_messagebus_sns_region"><?php Util_Ui::e_config_label( 'cluster.messagebus.sns.region' ); ?></label></th>
					<td>
						<input id="cluster_messagebus_sns_region"
							class="w3tc-ignore-change" type="text"
							name="cluster__messagebus__sns__region"
							value="<?php echo esc_attr( $this->_config->get_string( 'cluster.messagebus.sns.region' ) ); ?>" size="60" />
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'Specify the Amazon %1$sSNS%2$s service endpoint hostname. If empty, then default "sns.us-east-1.amazonaws.com" will be used.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Simple Notification Service', 'w3-total-cache' ) . '">',
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
					<th><label for="cluster_messagebus_sns_api_key"><?php Util_Ui::e_config_label( 'cluster.messagebus.sns.api_key' ); ?></label></th>
					<td>
						<input id="cluster_messagebus_sns_api_key"
							class="w3tc-ignore-change" type="text"
							name="cluster__messagebus__sns__api_key"
							value="<?php echo esc_attr( $this->_config->get_string( 'cluster.messagebus.sns.api_key' ) ); ?>" size="60" />
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'Specify the %1$sAPI%2$s Key.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Application Programming Interface', 'w3-total-cache' ) . '">',
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
					<th><label for="cluster_messagebus_sns_api_secret"><?php Util_Ui::e_config_label( 'cluster.messagebus.sns.api_secret' ); ?></label></th>
					<td>
						<input id="cluster_messagebus_sns_api_secret"
							class="w3tc-ignore-change" type="text"
							name="cluster__messagebus__sns__api_secret"
							value="<?php echo esc_attr( $this->_config->get_string( 'cluster.messagebus.sns.api_secret' ) ); ?>" size="60" />
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'Specify the %1$sAPI%2$s secret.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Application Programming Interface', 'w3-total-cache' ) . '">',
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
					<th><label for="cluster_messagebus_sns_topic_arn"><?php Util_Ui::e_config_label( 'cluster.messagebus.sns.topic_arn' ); ?></label></th>
					<td>
						<input id="cluster_messagebus_sns_topic_arn"
							class="w3tc-ignore-change" type="text"
							name="cluster__messagebus__sns__topic_arn"
							value="<?php echo esc_attr( $this->_config->get_string( 'cluster.messagebus.sns.topic_arn' ) ); ?>" size="60" />
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'Specify the %1$sSNS%2$s topic.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Simple Notification Service', 'w3-total-cache' ) . '">',
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
			</table>

			<?php Util_Ui::button_config_save( 'general_dbcluster' ); ?>
			<?php Util_Ui::postbox_footer(); ?>
		<?php endif; ?>

		<?php Util_Ui::postbox_header( __( 'Google PageSpeed', 'w3-total-cache' ), '', 'google_page_speed' ); ?>
		<?php
		$access_token_json = ( ! empty( $this->_config->get_string( 'widget.pagespeed.access_token' ) ) ? $this->_config->get_string( 'widget.pagespeed.access_token' ) : '' );
		$w3_pagespeed      = new PageSpeed_Api( $access_token_json );

		$site_id            = Util_Http::generate_site_id();
		$return_url         = admin_url( 'admin.php?page=w3tc_general' );
		$w3tc_pagespeed_key = ! empty( $this->_config->get_string( 'widget.pagespeed.w3tc_pagespeed_key' ) ) ? $this->_config->get_string( 'widget.pagespeed.w3tc_pagespeed_key' ) : '';
		$auth_url           = $w3_pagespeed->client->createAuthUrl();

		$new_gacode             = Util_Request::get( 'w3tc_new_gacode' );
		$new_w3tc_pagespeed_key = Util_Request::get( 'w3tc_new_w3tc_pagespeed_key' );
		$authorize_error        = Util_Request::get( 'w3tc_authorize_error' );
		$deauthorize            = Util_Request::get( 'w3tc_deauthorize' );

		if ( ! empty( $new_gacode ) && ! empty( $new_w3tc_pagespeed_key ) ) {
			$response = json_decode( $w3_pagespeed->process_authorization_response( $new_gacode, $new_w3tc_pagespeed_key ), true );

			if ( isset( $response['error']['code'] ) && 200 !== $response['error']['code'] ) {
				$response_error = sprintf(
					// translators: 1 Request response code, 2 Error message.
					__(
						'Response Code: %1$s<br/>Response Message: %2$s',
						'w3-total-cache'
					),
					! empty( $response['error']['code'] ) ? $response['error']['code'] : 'N/A',
					! empty( $response['error']['message'] ) ? $response['error']['message'] : 'N/A'
				);

				update_option(
					'w3tcps_authorize_fail',
					__( 'Google PageSpeed Insights API authorization failed.', 'w3-total-cache' )
				);
				update_option(
					'w3tcps_authorize_fail_message',
					$response_error
				);
			} elseif ( ! empty( $response['refresh_token'] ) ) {
				update_option(
					'w3tcps_authorize_success',
					__( 'Google PageSpeed Insights API authorization successfull.', 'w3-total-cache' )
				);
			} else {
				update_option(
					'w3tcps_authorize_fail',
					__( 'Google PageSpeed Insights API authorization failed.', 'w3-total-cache' )
				);
				update_option(
					'w3tcps_authorize_fail_message',
					__( 'Missing refresh token.', 'w3-totoal-cache' )
				);
			}

			wp_safe_redirect( $return_url );
			exit;
		} elseif ( $deauthorize ) {
			$w3_pagespeed->reset();
			update_option(
				'w3tcps_authorize_success',
				__( 'Google PageSpeed Insights API authorization successfully reset.', 'w3-total-cache' )
			);
			wp_safe_redirect( $return_url );
			exit;
		} elseif ( ! empty( $authorize_error ) ) {
			$authorize_error = json_decode( $authorize_error );

			if ( 'authorize-in-missing-site-id' === $authorize_error->error->id ) {
				$message = __( 'Unique site ID missing for authorize request!', 'w3-total-cache' );
			} elseif ( 'authorize-in-missing-auth-url' === $authorize_error->error->id ) {
				$message = __( 'Authorize URL missing for authorize request!', 'w3-total-cache' );
			} elseif ( 'authorize-in-missing-return-url' === $authorize_error->error->id ) {
				$message = __( 'Return URL missing for authorize request!', 'w3-total-cache' );
			} elseif ( 'authorize-in-failed' === $authorize_error->error->id ) {
				$message = __( 'Failed to process authorize request!', 'w3-total-cache' );
			}

			if ( 'authorize-out-code-missing' === $authorize_error->error->id ) {
				$message = __( 'No authorize code returned to W3-API from Google!', 'w3-total-cache' );
			} elseif ( 'authorize-out-w3tc-pagespeed-key-missing' === $authorize_error->error->id ) {
				$message = __( 'No W3Key return to W3-API from Google!', 'w3-total-cache' );
			} elseif ( 'authorize-out-not-found' === $authorize_error->error->id ) {
				$message = __( 'No W3-API matching record found during Google authorization return processing!', 'w3-total-cache' );
			}

			update_option(
				'w3tcps_authorize_fail',
				__( 'Google PageSpeed Insights API authorization failed.', 'w3-total-cache' )
			);
			update_option(
				'w3tcps_authorize_fail_message',
				$message
			);

			wp_safe_redirect( $return_url );
			exit;
		}
		?>
		<table class="form-table">
			<?php
			$access_token_json = ( ! empty( $w3_pagespeed->client->getAccessToken() ) ? $w3_pagespeed->client->getAccessToken() : '' );
			if ( ! $w3_pagespeed->client->isAccessTokenExpired() && ! empty( $access_token_json ) ) {
				?>
				<tr>
					<th>
						<label for="widget_pagespeed_access_token"><?php Util_Ui::e_config_label( 'widget.pagespeed.access_token', 'general' ); ?> <?php esc_html_e( 'Valid', 'w3-total-cache' ); ?></label>
					</th>
				</tr>
				<tr>
					<th>
						<a id="w3tc-google-deauthorize-button" class="w3tc-button-save button-primary" href="<?php echo esc_url( $return_url . '&w3tc_deauthorize=1' ); ?>"><?php esc_html_e( 'Deauthorize' ); ?></a>
					</th>
				</tr>
				<?php
			} else {
				?>
				<tr>
					<th>
						<label for="widget_pagespeed_token"><?php Util_Ui::e_config_label( 'widget.pagespeed.access_token', 'general' ); ?></label>
					</th>
					<td>
						<a id="w3tc-google-authorize-button" class="w3tc-button-save button-primary" href="<?php echo esc_url( $w3_pagespeed->get_w3tc_api_url( 'google/authorize-in' ) . '/' . rawurlencode( $site_id ) . '/' . rawurlencode( $auth_url ) . '/' . rawurlencode( $return_url ) ); ?>"><?php esc_html_e( 'Authorize' ); ?></a>
						<p><?php esc_html_e( 'Allow W3 Total Cache to connect to the PageSpeed Insights API on your behalf.', 'w3-total-cache' ); ?></p>
					</td>
				</tr>
				<?php
			}

			Util_Ui::config_item(
				array(
					'key'            => 'widget.pagespeed.enabled',
					'control'        => 'checkbox',
					'checkbox_label' => __( 'Enable Google PageSpeed dashboard widget', 'w3-total-cache' ),
					'description'    => __( 'Display Google PageSpeed results on the WordPress dashboard.', 'w3-total-cache' ),
					'label_class'    => 'w3tc_single_column',
				)
			);
			?>
		</table>

		<?php Util_Ui::button_config_save( 'general_google_page_speed' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		foreach ( $custom_areas as $area ) {
			do_action( 'w3tc_settings_general_boxarea_' . $area['id'] );
		}
		?>

		<?php if ( $licensing_visible ) : ?>
			<?php Util_Ui::postbox_header( __( 'Licensing', 'w3-total-cache' ), '', 'licensing' ); ?>
			<table class="form-table">
					<tr>
						<th>
							<label for="plugin_license_key"><?php Util_Ui::e_config_label( 'plugin.license_key' ); ?></label>
						</th>
						<td>
							<input id="plugin_license_key" name="plugin__license_key" type="text" value="<?php echo esc_attr( $this->_config->get_string( 'plugin.license_key' ) ); ?>" size="45"/>
							<input id="plugin_license_key_verify" type="button" class="button" value="<?php esc_attr_e( 'Verify license key', 'w3-total-cache' ); ?>"/>
							<span class="w3tc_license_verification"></span>
							<p class="description">
								<?php
								echo wp_kses(
									sprintf(
										// translators: 1 HTML a tag to trigger W3TC licence upgrade.
										__(
											'Please enter the license key provided after %1$s.',
											'w3-total-cache'
										),
										'<a class="button-buy-plugin" data-src="generic_license" href="#">' . esc_html__( 'upgrading', 'w3-total-cache' ) . '</a>'
									),
									array(
										'a' => array(
											'class'    => array(),
											'data-src' => array(),
											'href'     => array(),
										),
									)
								);
								?>
							</p>
						</td>
					</tr>

			</table>
			<?php Util_Ui::button_config_save( 'general_licensing' ); ?>
			<?php Util_Ui::postbox_footer(); ?>
		<?php endif; ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Miscellaneous', 'w3-total-cache' ), '', 'miscellaneous' ); ?>
		<table class="form-table">
			<?php if ( is_network_admin() ) : ?>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'common.force_master' ); ?> <?php Util_Ui::e_config_label( 'common.force_master' ); ?></label>
					<p class="description"><?php esc_html_e( 'Only one configuration file for whole network will be created and used. Recommended if all sites have the same configuration.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<?php endif; ?>
			<?php if ( Util_Environment::is_nginx() ) : ?>
			<tr>
				<th><?php Util_Ui::e_config_label( 'config.path' ); ?></th>
				<td>
					<input type="text" name="config__path" value="<?php echo esc_attr( $this->_config->get_string( 'config.path' ) ); ?>" size="80" <?php Util_Ui::sealing_disabled( 'common.' ); ?>/>
					<p class="description"><?php esc_html_e( 'If empty the default path will be used..', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<?php endif; ?>
			<tr>
				<th colspan="2">
					<input type="hidden" name="config__check" value="0" <?php Util_Ui::sealing_disabled( 'common.' ); ?> />
					<label><input type="checkbox" name="config__check" value="1" <?php checked( $this->_config->get_boolean( 'config.check' ), true ); ?> <?php Util_Ui::sealing_disabled( 'common.' ); ?> /> <?php Util_Ui::e_config_label( 'config.check' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML a tag to W3TC install admin page.
								__(
									'Notify of server configuration errors, if this option is disabled, the server configuration for active settings can be found on the %1$sinstall%2$s tab.',
									'w3-total-cache'
								),
								'<a href="' . esc_url( Util_Ui::admin_url( 'admin.php?page=w3tc_install' ) ) . '">',
								'</a>'
							),
							array(
								'a' => array(
									'href' => array(),
								),
							)
						);
						?>
					</p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<input type="hidden" name="file_locking" value="0"<?php Util_Ui::sealing_disabled( 'common.' ); ?>  />
					<label><input type="checkbox" name="file_locking" value="1" <?php checked( $file_locking, true ); ?> <?php Util_Ui::sealing_disabled( 'common.' ); ?>  /> <?php esc_html_e( 'Enable file locking', 'w3-total-cache' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Not recommended for %1$sNFS%2$s systems.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Network File System', 'w3-total-cache' ) . '">',
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
				<th colspan="2">
					<input type="hidden" name="file_nfs" value="0" <?php Util_Ui::sealing_disabled( 'common.' ); ?> />
					<label>
						<input type="checkbox" name="file_nfs" value="1" <?php checked( $file_nfs, true ); ?><?php Util_Ui::sealing_disabled( 'common.' ); ?> />
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Optimize disk enhanced page and minify disk caching for %1$sNFS%2$s',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Network File System', 'w3-total-cache' ) . '">',
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
					<p class="description"><?php esc_html_e( 'Try this option if your hosting environment uses a network based file system for a possible performance improvement.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'docroot_fix.enable',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Fix document root path', 'w3-total-cache' ),
					'label_class'    => 'w3tc_single_column',
					'description'    => sprintf(
						// translators: 1: WordPress ABSPATH value, 2: Server document root value.
						esc_html__( 'Fix incorrect server document root path.  Uses the WordPress ABSPATH ("%1$s") in place of the current server document root ("%2$s").', 'w3-total-cache' ),
						esc_attr( untrailingslashit( ABSPATH ) ),
						esc_attr( ! empty( $_SERVER['DOCUMENT_ROOT'] ) ? esc_url_raw( wp_unslash( $_SERVER['DOCUMENT_ROOT'] ) ) : '' )
					),
				)
			);

			Util_Ui::config_item(
				array(
					'key'            => 'common.track_usage',
					'control'        => 'checkbox',
					'checkbox_label' => esc_html__( 'Anonymously track usage to improve product quality', 'w3-total-cache' ),
					'label_class'    => 'w3tc_single_column',
				)
			);
			?>
		</table>

		<?php Util_Ui::button_config_save( 'general_misc' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Debug', 'w3-total-cache' ), '', 'debug' ); ?>
		<p>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Detailed information about each cache will be appended in (publicly available) %1$sHTML%2$s comments in the page\'s source code. Performance in this mode will not be optimal, use sparingly and disable when not in use.',
						'w3-total-cache'
					),
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

		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Debug mode:', 'w3-total-cache' ); ?></th>
				<td>
					<?php $this->checkbox_debug( 'pgcache.debug' ); ?> <?php Util_Ui::e_config_label( 'pgcache.debug' ); ?></label><br />
					<?php $this->checkbox_debug( 'minify.debug' ); ?> <?php Util_Ui::e_config_label( 'minify.debug' ); ?></label><br />
					<?php $this->checkbox_debug( 'dbcache.debug' ); ?> <?php Util_Ui::e_config_label( 'dbcache.debug' ); ?></label><br />
					<?php $this->checkbox_debug( 'objectcache.debug' ); ?> <?php Util_Ui::e_config_label( 'objectcache.debug' ); ?></label><br />
					<?php if ( Util_Environment::is_w3tc_pro( $this->_config ) ) : ?>
						<?php $this->checkbox_debug( array( 'fragmentcache', 'debug' ) ); ?> <?php esc_html_e( 'Fragment Cache', 'w3-total-cache' ); ?></label><br />
					<?php endif; ?>
					<?php $this->checkbox_debug( 'cdn.debug' ); ?> <?php Util_Ui::e_config_label( 'cdn.debug' ); ?></label><br />
					<?php $this->checkbox_debug( 'cdnfsd.debug' ); ?> <?php Util_Ui::e_config_label( 'cdnfsd.debug' ); ?></label><br />
					<?php $this->checkbox_debug( 'varnish.debug' ); ?> <?php Util_Ui::e_config_label( 'varnish.debug' ); ?></label>
					<?php if ( Util_Environment::is_w3tc_pro() ) : ?>
						<br />
						<?php $this->checkbox_debug( 'cluster.messagebus.debug' ); ?> <?php Util_Ui::e_config_label( 'cluster.messagebus.debug' ); ?></label>
					<?php endif ?>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'If selected, detailed caching information will appear at the end of each page in a %1$sHTML%2$s comment. View a page\'s source code to review.',
									'w3-total-cache'
								),
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
		</table>
		<table class="<?php echo esc_attr( Util_Ui::table_class() ); ?>">
			<tr>
				<th><?php esc_html_e( 'Purge Logs:', 'w3-total-cache' ); ?></th>
				<td>
					<?php \W3TC\Util_Ui::pro_wrap_maybe_start(); ?>

					<?php
					$this->checkbox_debug_pro(
						'pgcache.debug_purge',
						__( 'Page Cache Purge Log', 'w3-total-cache' ),
						' (<a href="?page=w3tc_general&view=purge_log&module=pagecache">' . __( 'view log', 'w3-total-cache' ) . '</a>)'
					);
					?>
					<br />

					<?php
					$this->checkbox_debug_pro(
						'dbcache.debug_purge',
						__( 'Database Cache Purge Log', 'w3-total-cache' ),
						' (<a href="?page=w3tc_general&view=purge_log&module=dbcache">' . __( 'view log', 'w3-total-cache' ) . '</a>)'
					);
					?>
					<br />

					<?php
					$this->checkbox_debug_pro(
						'objectcache.debug_purge',
						__( 'Object Cache Purge Log', 'w3-total-cache' ),
						' (<a href="?page=w3tc_general&view=purge_log&module=objectcache">' . __( 'view log', 'w3-total-cache' ) . '</a>)'
					);
					?>
					<br />

					<?php
					\W3TC\Util_Ui::pro_wrap_description(
						esc_html__( 'Purge Logs provide information on when your cache has been purged and what triggered it.', 'w3-total-cache' ),
						array(
							esc_html__( 'Sometimes, you\'ll encounter a complex issue involving your cache being purged for an unknown reason. The Purge Logs functionality can help you easily resolve those issues.', 'w3-total-cache' ),
						),
						'general-purge-log'
					);
					?>
					<?php \W3TC\Util_Ui::pro_wrap_maybe_end( 'debug_purge' ); ?>
				</td>
			</tr>

		</table>

		<?php Util_Ui::button_config_save( 'general_debug' ); ?>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post" enctype="multipart/form-data">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Import / Export Settings', 'w3-total-cache' ), '', 'settings' ); ?>
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
		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Import configuration:', 'w3-total-cache' ); ?></th>
				<td>
					<input type="file" name="config_file" />
					<input type="submit" name="w3tc_config_import" class="w3tc-button-save button" value="<?php esc_attr_e( 'Upload', 'w3-total-cache' ); ?>" />
					<p class="description"><?php esc_html_e( 'Upload and replace the active settings file.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Export configuration:', 'w3-total-cache' ); ?></th>
				<td>
					<input type="submit" name="w3tc_config_export" class="button" value="<?php esc_attr_e( 'Download', 'w3-total-cache' ); ?>" />
					<p class="description"><?php esc_html_e( 'Download the active settings file.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Reset configuration:', 'w3-total-cache' ); ?></th>
				<td>
					<input type="submit" name="w3tc_config_reset" class="button" value="<?php esc_attr_e( 'Restore Default Settings', 'w3-total-cache' ); ?>" />
					<p class="description"><?php esc_html_e( 'Revert all settings to the defaults. Any settings staged in preview mode will not be modified.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
		</table>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
