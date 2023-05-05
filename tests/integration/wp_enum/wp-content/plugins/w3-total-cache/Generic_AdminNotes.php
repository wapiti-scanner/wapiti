<?php
/**
 * FIle: Generic_AdminNotes.php
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * Class: Generic_AdminNotes
 */
class Generic_AdminNotes {
	/**
	 * W3TC admin notices.
	 *
	 * @param array $notes Notices.
	 * @return string
	 */
	public function w3tc_notes( $notes ) {
		$c            = Dispatcher::config();
		$state        = Dispatcher::config_state();
		$state_master = Dispatcher::config_state_master();
		$state_note   = Dispatcher::config_state_note();

		/**
		 * Check wp-content permissions
		 */
		if ( ! W3TC_WIN && ! $state_master->get_boolean( 'common.hide_note_wp_content_permissions' ) ) {
			$wp_content_mode = Util_File::get_file_permissions( WP_CONTENT_DIR );

			if ( $wp_content_mode > 755 ) {
				$notes['generic_wp_content_writeable'] = wp_kses(
					sprintf(
						// translators: 1: HTML strong tag for current WP directory, 2: HTML strong tag for CHMOD instruction for current WP directory,
						// translators: 3: conversion of file permissions from base 10 to 8, 4: HTML input button for hiding message.
						__(
							'%1$s is write-able. When finished installing the plugin, change the permissions back to the default: %2$s. Permissions are currently %3$s. %4$s',
							'w3-total-cache'
						),
						'<strong>' . WP_CONTENT_DIR . '</strong>',
						'<strong>chmod 755 ' . WP_CONTENT_DIR . '</strong>',
						$wp_content_mode,
						Util_Ui::button_hide_note2(
							array(
								'w3tc_default_config_state_master' => 'y',
								'key'   => 'common.hide_note_wp_content_permissions',
								'value' => 'true',
							)
						)
					),
					array(
						'strong' => array(),
						'input'  => array(
							'type'    => array(),
							'name'    => array(),
							'class'   => array(),
							'value'   => array(),
							'onclick' => array(),
						),
					)
				);
			}
		}

		/**
		 * Check Zlib extension.
		 */
		if ( ! $state_master->get_boolean( 'common.hide_note_no_zlib' ) && ! function_exists( 'gzencode' ) ) {
			$notes['no_zlib'] = wp_kses(
				sprintf(
					// translators: 1: opening HTML strong tag, 2: closing HTML strong tag, 3: HTML input button for hiding message.
					__(
						'Unfortunately the PHP installation is incomplete, the %1$szlib module is missing%2$s. This is a core PHP module. Notify the server administrator. %3$s',
						'w3-total-cache'
					),
					'<strong>',
					'</strong>',
					Util_Ui::button_hide_note2(
						array(
							'w3tc_default_config_state_master' => 'y',
							'key'   => 'common.hide_note_no_zlib',
							'value' => 'true',
						)
					)
				),
				array(
					'strong' => array(),
					'input'  => array(
						'type'    => array(),
						'name'    => array(),
						'class'   => array(),
						'value'   => array(),
						'onclick' => array(),
					),
				)
			);
		}

		/**
		 * Check if Zlib output compression is enabled
		 */
		if ( ! $state_master->get_boolean( 'common.hide_note_zlib_output_compression' ) && Util_Environment::is_zlib_enabled() ) {
			$notes['zlib_output_compression'] = wp_kses(
				sprintf(
					// translators: 1: opening HTML strong tag, 2: clsoing HTML strong tag, 3: HTML line break, 4: HTML input button to hide message.
					__(
						'Either the PHP configuration, web server configuration or a script in the WordPress installation has %1$szlib.output_compression%2$s enabled.%3$sPlease locate and disable this setting to ensure proper HTTP compression behavior. %4$s',
						'w3-total-cache'
					),
					'<strong>',
					'</strong>',
					'<br />',
					Util_Ui::button_hide_note2(
						array(
							'w3tc_default_config_state_master' => 'y',
							'key'   => 'common.hide_note_zlib_output_compression',
							'value' => 'true',
						)
					)
				),
				array(
					'strong' => array(),
					'br'     => array(),
					'input'  => array(
						'type'    => array(),
						'name'    => array(),
						'class'   => array(),
						'value'   => array(),
						'onclick' => array(),
					),
				)
			);
		}

		if ( $state_master->get_boolean( 'common.show_note.nginx_restart_required' ) ) {
			$cf = Dispatcher::component( 'CacheFlush' );

			$notes['nginx_restart_required'] = wp_kses(
				sprintf(
					// translators: 1: HTML input button to hide message.
					__(
						'nginx.conf rules have been updated. Please restart nginx server to provide a consistent user experience. %1$s',
						'w3-total-cache'
					),
					Util_Ui::button_hide_note2(
						array(
							'w3tc_default_config_state_master' => 'y',
							'key'   => 'common.show_note.nginx_restart_required',
							'value' => 'false',
						)
					)
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
		}

		/**
		 * Preview mode
		 */
		if ( $c->is_preview() ) {
			$notes['preview_mode'] = wp_kses(
				sprintf(
					// translators: 1: HTML input button to apply changes, 2: HTML input button to disable preview mode,
					// translators: 3: opening HTML p tag, 4: HTML inptu button to preview changes, 5: closing HTML p tag.
					__(
						'Preview mode is active: Changed settings will not take effect until preview mode is %1$s or %2$s. %3$sTo preview any changed settings (without deploying): %4$s',
						'w3-total-cache'
					),
					Util_Ui::button_link(
						__( 'deploy', 'w3-total-cache' ),
						Util_Ui::url( array( 'w3tc_config_preview_deploy' => 'y' ) )
					),
					Util_Ui::button_link(
						__( 'disable', 'w3-total-cache' ),
						Util_Ui::url( array( 'w3tc_config_preview_disable' => 'y' ) )
					),
					'<p class="description">',
					Util_Ui::preview_link(),
					'</p>'
				),
				array(
					'p'     => array(
						'class' => array(),
					),
					'input' => array(
						'type'    => array(),
						'name'    => array(),
						'class'   => array(),
						'value'   => array(),
						'onclick' => array(),
					),
				)
			);
		}

		/**
		 * Show notification after plugin activate/deactivate.
		 */
		if ( $state_note->get( 'common.show_note.plugins_updated' ) && ! is_network_admin() /* flushing under network admin do nothing */ ) {
			$texts = array();

			if ( $c->get_boolean( 'pgcache.enabled' ) ) {
				$texts[] = Util_Ui::button_link(
					__( 'empty the page cache', 'w3-total-cache' ),
					Util_Ui::url( array( 'w3tc_flush_posts' => 'y' ) )
				);
			}

			if ( $c->get_boolean( 'minify.enabled' ) ) {
				$texts[] = wp_kses(
					sprintf(
						// translators: 1: HTML input button to view minify settings.
						__(
							'check the %1$s to maintain the desired user experience',
							'w3-total-cache'
						),
						Util_Ui::button_link(
							__( 'minify settings', 'w3-total-cache' ),
							Util_Ui::url(
								array(
									'w3tc_default_config_state_note' => 'y',
									'key'      => 'common.show_note.plugins_updated',
									'value'    => 'false',
									'page'     => 'w3tc_minify',
									'redirect' => esc_url( admin_url( 'admin.php?page=w3tc_minify' ) ),
								)
							)
						)
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
			}

			if ( count( $texts ) ) {
				$notes['some_plugins_activated'] = wp_kses(
					sprintf(
						// translators: 1: HTML input button to clear the cache, 2: HTML input button to hide message.
						__(
							'One or more plugins have been activated or deactivated, please %1$s. %2$s',
							'w3-total-cache'
						),
						implode( __( ' and ', 'w3-total-cache' ), $texts ),
						Util_Ui::button_hide_note2(
							array(
								'w3tc_default_config_state_note' => 'y',
								'key'   => 'common.show_note.plugins_updated',
								'value' => 'false',
							)
						)
					),
					array(
						'input' => array(
							'type'    => array(),
							'name'    => array(),
							'class'   => array(),
							'value'   => array(),
							'onclick' => array(),
						),
						'a'     => array(
							'href'   => array(),
							'target' => array(),
						),
					)
				);
			}
		}

		/**
		 * Show notification when flush_statics needed.
		 */
		if ( $c->get_boolean( 'browsercache.enabled' ) && $state_note->get( 'common.show_note.flush_statics_needed' ) && ! is_network_admin() /* flushing under network admin do nothing */ && ! $c->is_preview() ) {
			$notes['flush_statics_needed'] = wp_kses(
				sprintf(
					// translators: 1: HTML input button to empty static files cache, 2: HTML input button to hide message.
					__(
						'The setting change(s) made either invalidate the cached data or modify the behavior of the site. %1$s now to provide a consistent user experience. %2$s',
						'w3-total-cache'
					),
					Util_Ui::button_link(
						'Empty the static files cache',
						Util_Ui::url( array( 'w3tc_flush_statics' => 'y' ) )
					),
					Util_Ui::button_hide_note2(
						array(
							'w3tc_default_config_state_note' => 'y',
							'key'   => 'common.show_note.flush_statics_needed',
							'value' => 'false',
						)
					)
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
		}

		/**
		 * Show notification when flush_posts needed.
		 */
		if ( $state_note->get( 'common.show_note.flush_posts_needed' ) && ! is_network_admin() /* flushing under network admin do nothing */ && ! $c->is_preview() && ! isset( $notes['flush_statics_needed'] ) ) {
			$cf = Dispatcher::component( 'CacheFlush' );
			if ( $cf->flushable_posts() ) {
				$notes['flush_posts_needed'] = wp_kses(
					sprintf(
						// translators: 1: HTML input button to empty page cache, 2: HTML input button to hide message.
						__(
							'The setting change(s) made either invalidate the cached data or modify the behavior of the site. %1$s now to provide a consistent user experience. %2$s',
							'w3-total-cache'
						),
						Util_Ui::button_link(
							'Empty the page cache',
							Util_Ui::url( array( 'w3tc_flush_posts' => 'y' ) )
						),
						Util_Ui::button_hide_note2(
							array(
								'w3tc_default_config_state_note' => 'y',
								'key'   => 'common.show_note.flush_posts_needed',
								'value' => 'false',
							)
						)
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
			}
		}

		$is_debug = $c->get_boolean( 'cluster.messagebus.debug' ) ||
			$c->get_boolean( 'dbcache.debug' ) ||
			$c->get_boolean( 'objectcache.debug' ) ||
			$c->get_boolean( 'pgcache.debug' ) ||
			$c->get_boolean( 'minify.debug' ) ||
			$c->get_boolean( 'cdn.debug' ) ||
			$c->get_boolean( 'cdnfsd.debug' ) ||
			$c->get_boolean( 'varnish.debug' );

		if ( $is_debug && ! $state_master->get_boolean( 'common.hide_note_debug_enabled' ) ) {
			$notes['debug_enabled'] = wp_kses(
				sprintf(
					// translators: 1: HTML input button to hide message.
					__(
						'You\'re running debug mode, it\'s using Resources and not recommend to run continuously. %1$s',
						'w3-total-cache'
					),
					Util_Ui::button_hide_note2(
						array(
							'w3tc_default_config_state_master' => 'y',
							'key'   => 'common.hide_note_debug_enabled',
							'value' => 'true',
						)
					)
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
		}

		return $notes;
	}

	/**
	 * W3TC error notices.
	 *
	 * @param array $errors Errors.
	 * @return array
	 */
	public function w3tc_errors( $errors ) {
		$state = Dispatcher::config_state();
		$c     = Dispatcher::config();

		/**
		 * Check permalinks.
		 */
		if (
			! $state->get_boolean( 'common.hide_note_no_permalink_rules' ) &&
			(
				( $c->get_boolean( 'pgcache.enabled' ) && 'file_generic' === $c->get_string( 'pgcache.engine' ) ) ||
				( $c->get_boolean( 'browsercache.enabled' ) && $c->get_boolean( 'browsercache.no404wp' ) )
			) &&
			! Util_Rule::is_permalink_rules()
		) {
			$errors['generic_no_permalinks'] = wp_kses(
				sprintf(
					// translators: 1: HTML a tag to WordPress codex for using htaccess for permalinks, 2: HTML input button to hide message.
					__(
						'The required directives for fancy permalinks could not be detected, please confirm they are available: %1$s %2$s',
						'w3-total-cache'
					),
					'<a href="http://codex.wordpress.org/Using_Permalinks#Creating_and_editing_.28.htaccess.29">' .
						__( 'Creating and editing', 'w3-total-cache' ) . '</a>',
					Util_Ui::button_hide_note2(
						array(
							'w3tc_default_config_state_master' => 'y',
							'key'   => 'common.hide_note_no_permalink_rules',
							'value' => 'true',
						)
					)
				),
				array(
					'a'     => array(
						'href' => array(),
					),
					'input' => array(
						'type'    => array(),
						'name'    => array(),
						'class'   => array(),
						'value'   => array(),
						'onclick' => array(),
					),
				)
			);
		}

		/**
		 * Check memcached.
		 */
		if ( isset( $errors['memcache_not_responding.details'] ) ) {
			$memcache_errors = '';
			foreach ( $errors['memcache_not_responding.details'] as $memcaches_error ) {
				$memcache_errors .= '<li>' . $memcaches_error . '</li>';
			}

			$memcache_error = wp_kses(
				sprintf(
					// translators: 1: opening HTML p tag, 2: closing HTML p tag followed by opening HTML ul tag followed by memcache errors within HTML li tags,
					// translators: 3: closing HTML p tag.
					__(
						'%1$sThe following memcached servers are not responding or not running:%2$sThis message will automatically disappear once the issue is resolved.%3$s',
						'w3-total-cache'
					),
					'<p>',
					'</p><ul>' . $memcache_errors . '</ul><p>',
					'</p>'
				),
				array(
					'p'  => array(),
					'ul' => array(),
					'li' => array(),
				)
			);

			$errors['memcache_not_responding'] = $memcache_error;
			unset( $errors['memcache_not_responding.details'] );
		}

		return $errors;
	}
}
