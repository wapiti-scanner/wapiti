<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$config            = Dispatcher::config();
$state             = Dispatcher::config_state();
$page              = Util_Admin::get_current_page();
$licensing_visible = (
	( ! Util_Environment::is_wpmu() || is_network_admin() ) &&
	! ini_get( 'w3tc.license_key' ) &&
	'host_valid' !== $state->get_string( 'license.status' )
);

do_action( 'w3tc-dashboard-head' );
?>
<div class="wrap" id="w3tc">
	<h2 class="logo">
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML span tag, 2 opening HTML sup tag, 3 closing HTML sup tag, 4 closing HTML span tag.
				__(
					'W3 Total Cache %1$sby W3 EDGE %2$s&reg;%3$s%4$s',
					'w3-total-cache'
				),
				'<span>',
				'<sup>',
				'</sup>',
				'</span>'
			),
			array(
				'span' => array(),
				'sup'  => array(),
			)
		);
		?>
	</h2>
	<?php if ( ! Util_Environment::is_w3tc_pro( $config ) ) : ?>
		<?php require W3TC_INC_OPTIONS_DIR . '/edd/buy.php'; ?>
	<?php endif ?>
	<?php
	switch ( $page ) {
		case 'w3tc_general':
			if ( ! empty( $_REQUEST['view'] ) ) {
				break;
			}
			$anchors = array(
				array(
					'id'   => 'general',
					'text' => esc_html__( 'General', 'w3-total-cache' ),
				),
				array(
					'id'   => 'page_cache',
					'text' => esc_html__( 'Page Cache', 'w3-total-cache' ),
				),
				array(
					'id'   => 'minify',
					'text' => esc_html__( 'Minify', 'w3-total-cache' ),
				),
				array(
					'id'   => 'system_opcache',
					'text' => esc_html__( 'Opcode Cache', 'w3-total-cache' ),
				),
				array(
					'id'   => 'database_cache',
					'text' => esc_html__( 'Database Cache', 'w3-total-cache' ),
				),
				array(
					'id'   => 'object_cache',
					'text' => esc_html__( 'Object Cache', 'w3-total-cache' ),
				),
			);

			if ( Util_Environment::is_w3tc_pro( $config ) ) {
				$anchors[] = array(
					'id'   => 'fragmentcache',
					'text' => esc_html__( 'Fragment Cache', 'w3-total-cache' ),
				);
			}

			$anchors = array_merge(
				$anchors,
				array(
					array(
						'id'   => 'browser_cache',
						'text' => esc_html__( 'Browser Cache', 'w3-total-cache' ),
					),
					array(
						'id'   => 'cdn',
						'text' => wp_kses(
							sprintf(
								// translators: 1 opening HTML abbr tag, 2 closing HTML abbr tag.
								__(
									'%1$sCDN%2$s',
									'w3-total-cache'
								),
								'<abbr title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</abbr>'
							),
							array(
								'abbr' => array(
									'title' => array(),
								),
							)
						),
					),
					array(
						'id'   => 'reverse_proxy',
						'text' => esc_html__( 'Reverse Proxy', 'w3-total-cache' ),
					),
				)
			);

			if ( Util_Environment::is_w3tc_pro() ) {
				$anchors[] = array(
					'id'   => 'amazon_sns',
					'text' => esc_html__( 'Message Bus', 'w3-total-cache' ),
				);
			}

			$anchors[] = array(
				'id'   => 'monitoring',
				'text' => esc_html__( 'Monitoring', 'w3-total-cache' ),
			);

			if ( $licensing_visible ) {
				array(
					'id'   => 'licensing',
					'text' => esc_html__( 'Licensing', 'w3-total-cache' ),
				);
			}

			$link_attrs = array_merge(
				$anchors,
				$custom_areas,
				array(
					array(
						'id'   => 'google_page_speed',
						'text' => __( 'Google PageSpeed', 'w3-total-cache' )
					),
					array(
						'id'   => 'miscellaneous',
						'text' => esc_html__( 'Miscellaneous', 'w3-total-cache' ),
					),
					array(
						'id'   => 'debug',
						'text' => esc_html__( 'Debug', 'w3-total-cache' ),
					),
					array(
						'id'   => 'settings',
						'text' => esc_html__( 'Import / Export Settings', 'w3-total-cache' ),
					),
				)
			);

			$links = array();
			foreach ( $link_attrs as $link ) {
				$links[] = "<a href=\"#{$link['id']}\">{$link['text']}</a>";
			}

			$links[] = '<a href="#" class="button-self-test">Compatibility Test</a>';

			?>
			<p id="w3tc-options-menu">
				<?php
				echo wp_kses(
					implode( ' | ', $links ),
					array(
						'a'    => array(
							'href'  => array(),
							'class' => array(),
						),
					)
				);
				?>
			</p>
			<?php
			break;

		case 'w3tc_pgcache':
			?>
			<p id="w3tc-options-menu">
				<?php esc_html_e( 'Jump to:', 'w3-total-cache' ); ?>
				<a href="#toplevel_page_w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
				<a href="#general"><?php esc_html_e( 'General', 'w3-total-cache' ); ?></a> |
				<a href="#mirrors"><?php esc_html_e( 'Mirrors', 'w3-total-cache' ); ?></a> |
				<a href="#advanced"><?php esc_html_e( 'Advanced', 'w3-total-cache' ); ?></a> |
				<a href="#cache_preload"><?php esc_html_e( 'Cache Preload', 'w3-total-cache' ); ?></a> |
				<a href="#purge_policy"><?php esc_html_e( 'Purge Policy', 'w3-total-cache' ); ?></a> |
				<a href="#notes"><?php esc_html_e( 'Note(s)', 'w3-total-cache' ); ?></a>
			</p>
			<?php
			break;

		case 'w3tc_minify':
			?>
			<p id="w3tc-options-menu">
				<?php esc_html_e( 'Jump to: ', 'w3-total-cache' ); ?>
				<a href="#toplevel_page_w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
				<a href="#general"><?php esc_html_e( 'General', 'w3-total-cache' ); ?></a> |
				<a href="#html_xml">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
							__(
								'%1$sHTML%2$s &amp; %3$sXML%4$s',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'eXtensible Markup Language', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</a> |
				<a href="#js">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sJS%2$s',
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
					);
					?>
				</a> |
				<a href="#css">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sCSS%2$s',
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
				</a> |
				<a href="#advanced"><?php esc_html_e( 'Advanced', 'w3-total-cache' ); ?></a> |
				<a href="#notes"><?php esc_html_e( 'Note(s)', 'w3-total-cache' ); ?></a>
			</p>
			<?php
			break;

		case 'w3tc_dbcache':
			?>
			<p id="w3tc-options-menu">
				<?php esc_html_e( 'Jump to: ', 'w3-total-cache' ); ?>
				<a href="#toplevel_page_w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
				<a href="#general"><?php esc_html_e( 'General', 'w3-total-cache' ); ?></a> |
				<a href="#advanced"><?php esc_html_e( 'Advanced', 'w3-total-cache' ); ?></a>
			</p>
			<?php
			break;

		case 'w3tc_objectcache':
			?>
			<p id="w3tc-options-menu">
				<?php esc_html_e( 'Jump to: ', 'w3-total-cache' ); ?>
				<a href="#toplevel_page_w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
				<a href="#advanced"><?php esc_html_e( 'Advanced', 'w3-total-cache' ); ?></a>
			</p>
			<?php
			break;

		case 'w3tc_browsercache':
			?>
			<p id="w3tc-options-menu">
				<?php esc_html_e( 'Jump to: ', 'w3-total-cache' ); ?>
				<a href="#toplevel_page_w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
				<a href="#general"><?php esc_html_e( 'General', 'w3-total-cache' ); ?></a> |
				<a href="#css_js">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
							__(
								'%1$sCSS%2$s &amp; %3$sJS%4$s',
								'w3-total-cache'
							),
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
					);
					?>
				</a> |
				<a href="#html_xml">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
							__(
								'%1$sHTML%2$s &amp; %3$sXML%4$s',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'eXtensible Markup Language', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</a> |
				<a href="#media"><?php esc_html_e( 'Media', 'w3-total-cache' ); ?></a> |
				<a href="#security"><?php esc_html_e( 'Security Headers', 'w3-total-cache' ); ?></a>
			</p>
			<?php
			break;

		case 'w3tc_cachegroups':
			?>
			<p id="w3tc-options-menu">
				<?php esc_html_e( 'Jump to: ', 'w3-total-cache' ); ?>
				<a href="#toplevel_page_w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
				<a href="#manage-uag"><?php esc_html_e( 'Manage User Agent Groups', 'w3-total-cache' ); ?></a> |
				<a href="#manage-rg"><?php esc_html_e( 'Manage Referrer Groups', 'w3-total-cache' ); ?></a> |
				<a href="#manage-cg"><?php esc_html_e( 'Manage Cookie Groups', 'w3-total-cache' ); ?></a>
			</p>
			<?php
			break;

		case 'w3tc_install':
			?>
			<p id="w3tc-options-menu">
				<?php esc_html_e( 'Jump to:', 'w3-total-cache' ); ?>
				<a href="#initial"><?php esc_html_e( 'Initial Installation', 'w3-total-cache' ); ?></a> |
				<?php if ( count( $rewrite_rules_descriptors ) ) : ?>
					<a href="#rules"><?php esc_html_e( 'Rewrite Rules', 'w3-total-cache' ); ?></a> |
				<?php endif ?>
				<?php if ( count( $other_areas ) ) : ?>
					<a href="#other"><?php esc_html_e( 'Other', 'w3-total-cache' ); ?></a> |
				<?php endif ?>
				<a href="#additional"><?php esc_html_e( 'Services', 'w3-total-cache' ); ?></a> |
				<a href="#modules">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'%1$sPHP%2$s Modules',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Hypertext Preprocessor', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</a>
			</p>
			<?php
			break;
	}
	?>
