<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

/*
 * Display the header for our dashboard.
 *
 * If we're on the pro version, we'll show the standard W3TC logo and a message stating the user is
 * on pro. As of 0.14.3, the free version will instead show a really, really nice banner. Really terrific.
 * Just fantasic. Other banners, not so good. Everyone agrees, believe me.
 */
if ( Util_Environment::is_w3tc_pro( Dispatcher::config() ) ) {
	require W3TC_INC_DIR . '/options/common/header.php';

	echo wp_kses(
		sprintf(
			// translators: 1 opening HTML p tag, 2 HTML span tag indicating plugin enabled/disabled,
			// translators: 3 HTML strong tag indicating W3TC version, 4 closing HTML p tag.
			__(
				'%1$sThe plugin is currently %2$s in %3$s mode.%4$s',
				'w3-total-cache'
			),
			'<p>',
			'<span class="w3tc-' . ( $enabled ? 'enabled' : 'disabled' ) . '">' . ( $enabled ? esc_html__( 'enabled', 'w3-total-cache' ) : esc_html__( 'disabled', 'w3-total-cache' ) ) . '</span>',
			'<strong>' . Util_Environment::w3tc_edition( $this->_config ) . '</strong>',
			'</p>'
		),
		array(
			'p'      => array(),
			'span'   => array(
				'class' => array(),
			),
			'strong' => array(),
		)
	);
} else {
	// When header.php is not included (above), we need to do our head action and open the wrap.
	do_action( 'w3tc-dashboard-head' );
	echo '<div class="wrap" id="w3tc">';

	require W3TC_INC_DIR . '/options/parts/dashboard_banner.php';
}
?>

<form id="w3tc_dashboard" action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<p>
		<?php esc_html_e( 'Perform a', 'w3-total-cache' ); ?>
		<input type="button" class="button button-self-test {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" value="<?php esc_html_e( 'compatibility check', 'w3-total-cache' ); ?>" />,
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
		<input id="flush_all" class="button" type="submit" name="w3tc_flush_all" value="<?php esc_html_e( 'empty all caches', 'w3-total-cache' ); ?>"<?php echo ! $enabled ? ' disabled="disabled"' : ''; ?> /> <?php esc_html_e( 'at once or', 'w3-total-cache' ); ?>
		<input class="button" type="submit" name="w3tc_flush_memcached" value="<?php esc_html_e( 'empty only the memcached cache(s)', 'w3-total-cache' ); ?>"<?php echo ! $can_empty_memcache ? ' disabled="disabled"' : ''; ?> /> <?php esc_html_e( 'or', 'w3-total-cache' ); ?>
		<input class="button" type="submit" name="w3tc_flush_opcode" value="<?php esc_html_e( 'empty only the opcode cache', 'w3-total-cache' ); ?>"<?php echo ! $can_empty_opcode ? ' disabled="disabled"' : ''; ?> /> <?php esc_html_e( 'or', 'w3-total-cache' ); ?>
		<input class="button" type="submit" name="w3tc_flush_file" value="<?php esc_html_e( 'empty only the disk cache(s)', 'w3-total-cache' ); ?>"<?php echo ! $can_empty_file ? ' disabled="disabled"' : ''; ?> /> <?php esc_html_e( 'or', 'w3-total-cache' ); ?>
		<?php if ( $cdn_mirror_purge && $cdn_enabled ) : ?>
			<input class="button" type="submit" name="w3tc_flush_cdn" value="<?php esc_html_e( 'purge CDN completely', 'w3-total-cache' ); ?>" /> <?php esc_html_e( 'or', 'w3-total-cache' ); ?>
		<?php endif; ?>
		<input type="submit" name="w3tc_flush_browser_cache" value="<?php esc_html_e( 'update Media Query String', 'w3-total-cache' ); ?>" <?php disabled( ! ( $browsercache_enabled && $browsercache_update_media_qs ) ); ?> class="button" />
		<?php
		$string = esc_html__( 'or', 'w3-total-cache' );
		echo wp_kses(
			implode( " $string ", apply_filters( 'w3tc_dashboard_actions', array() ) ),
			array(
				'input' => array(
					'class'    => array(),
					'disabled' => array(),
					'id'       => array(),
					'name'     => array(),
					'type'     => array(),
					'value'    => array(),
				),
			)
		);
		?>
		.
	</p>
	<div id="w3tc-dashboard-widgets" class="clearfix widefat metabox-holder">
		<?php $screen = get_current_screen(); ?>
		<div id="postbox-container-left">
			<div class="content">
			<div id="dashboard-text" style="display:inline-block;">
				<h1><?php esc_html_e( 'Dashboard', 'w3-total-cache' ); ?></h1>
				<p>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Thanks for choosing W3TC as your Web Performance Optimization (%1$sWPO%2$s) framework!',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Web Performance Optimization', 'w3-total-cache' ) . '">',
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
			</div>
			<div id="widgets-container">
			<?php do_meta_boxes( $screen->id, 'normal', '' ); ?>
			</div>
			</div>
		</div>
		<div id="postbox-container-right">
			<div id='postbox-container-3' class='postbox-container' style="width: 100%;">
				<?php do_meta_boxes( $screen->id, 'side', '' ); ?>
			</div>
		</div>
		<div style="clear:both"></div>

		<?php
		wp_nonce_field( 'closedpostboxes', 'closedpostboxesnonce', false );
		wp_nonce_field( 'meta-box-order', 'meta-box-order-nonce', false );
		?>
	</div>
</form>
<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
