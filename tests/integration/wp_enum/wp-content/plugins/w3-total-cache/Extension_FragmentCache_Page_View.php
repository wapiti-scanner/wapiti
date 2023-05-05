<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$engine = $config->get_string( array( 'fragmentcache', 'engine' ) );

?>
<p id="w3tc-options-menu">
	<?php esc_html_e( 'Jump to:', 'w3-total-cache' ); ?>
	<a href="admin.php?page=w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
	<a href="admin.php?page=w3tc_extensions"><?php esc_html_e( 'Extensions', 'w3-total-cache' ); ?></a> |
	<a href="#overview"><?php esc_html_e( 'Overview', 'w3-total-cache' ); ?></a> |
	<a href="#advanced"><?php esc_html_e( 'Advanced', 'w3-total-cache' ); ?></a>
</p>
<p>
	<?php Util_Ui::pro_wrap_maybe_start2(); ?>

	<?php esc_html_e( 'Fragment caching', 'w3-total-cache' ); ?>
	<?php if ( ! empty( $engine ) ) : ?>
		<?php esc_html_e( 'via', 'w3-total-cache' ); ?>
		<strong><?php echo esc_html( Cache::engine_name( $engine ) ); ?></strong>
	<?php endif; ?>

	<?php esc_html_e( 'is currently', 'w3-total-cache' ); ?>
	<?php if ( $config->is_extension_active_frontend( 'fragmentcache' ) ) : ?>
		<span class="w3tc-enabled"><?php esc_html_e( 'enabled', 'w3-total-cache' ); ?></span>
	<?php else : ?>
		<span class="w3tc-disabled"><?php esc_html_e( 'disabled', 'w3-total-cache' ); ?></span>
		<?php
		$ext = Extensions_Util::get_extension( $config, 'fragmentcache' );
		if ( ! empty( $ext['requirements'] ) ) {
			echo ' (<p class="description">' . esc_html( $ext['requirements'] ) . '</p>)';
		}
		?>
	<?php endif; ?>
	.

	<?php Util_Ui::pro_wrap_maybe_end2( 'fragmentcache_header' ); ?>
<p>

<form action="admin.php?page=w3tc_fragmentcache" method="post">
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
		<input type="submit" name="w3tc_flush_fragmentcache" value="<?php esc_attr_e( 'Empty the entire cache', 'w3-total-cache' ); ?>" class="button" />
		<?php esc_html_e( 'if needed.', 'w3-total-cache' ); ?>
	</p>
</form>

<form action="admin.php?page=w3tc_fragmentcache" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Overview', 'w3-total-cache' ), '', 'overview' ); ?>
		<table class="form-table">
		<tr>
			<th><?php esc_html_e( 'Registered fragment groups:', 'w3-total-cache' ); ?></th>
			<td>
				<?php if ( $registered_groups ) : ?>
					<ul>
						<?php
						foreach ( $registered_groups as $group => $descriptor ) :
							echo '<li>' . esc_html( $group ) . ' (' . esc_html( $descriptor['expiration'] ) . ' secs): ' . implode( ',', esc_html( $descriptor['actions'] ) ) . '</li>';
						endforeach;
						?>
					</ul>
				<p class="description"><?php esc_html_e( 'The groups above will be flushed upon setting changes.', 'w3-total-cache' ); ?></p>
				<?php else : ?>
				<p class="description"><?php esc_html_e( 'No groups have been registered.', 'w3-total-cache' ); ?></p>
				<?php endif; ?>
			</td>
		</tr>
		</table>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Advanced', 'w3-total-cache' ), '', 'advanced' ); ?>
		<table class="form-table">
			<?php
			if ( 'memcached' === $config->get_string( array( 'fragmentcache', 'engine' ) ) ) {
				$module = 'fragmentcache';
				include W3TC_INC_DIR . '/options/parts/memcached_extension.php';
			} elseif ( 'redis' === $config->get_string( array( 'fragmentcache', 'engine' ) ) ) {
				$module = 'fragmentcache';
				include W3TC_INC_DIR . '/options/parts/redis_extension.php';
			}
			?>
			<tr>
				<th style="width: 250px;"><label for="fragmentcache_lifetime"><?php esc_html_e( 'Default lifetime of cached fragments:', 'w3-total-cache' ); ?></label></th>
				<td>
					<input id="fragmentcache_lifetime" type="text" <?php Util_Ui::sealing_disabled( 'fragmentcache.' ); ?> name="fragmentcache___lifetime" value="<?php echo esc_attr( $config->get_integer( array( 'fragmentcache', 'lifetime' ) ) ); ?>" size="8" /><?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'Determines the natural expiration time of unchanged cache items. The higher the value, the larger the cache.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="fragmentcache_file_gc"><?php esc_html_e( 'Garbage collection interval:', 'w3-total-cache' ); ?></label></th>
				<td>
					<input id="fragmentcache_file_gc" type="text" <?php Util_Ui::sealing_disabled( 'fragmentcache.' ); ?> name="fragmentcache___file__gc" value="<?php echo esc_attr( $config->get_integer( array( 'fragmentcache', 'file.gc' ) ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'If caching to disk, specify how frequently expired cache data is removed. For busy sites, a lower value is best.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="fragmentcache_groups"><?php esc_html_e( 'Manual fragment groups:', 'w3-total-cache' ); ?></label></th>
				<td>
					<textarea id="fragmentcache_groups" name="fragmentcache___groups"
						<?php Util_Ui::sealing_disabled( 'fragmentcache.' ); ?>
						cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $config->get_array( array( 'fragmentcache', 'groups' ) ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Specify fragment groups that should be managed by W3 Total Cache. Enter one action per line comma delimited, e.g. (group, action1, action2). Include the prefix used for a transient by a theme or plugin.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'extension_fragmentcache' ); ?>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
