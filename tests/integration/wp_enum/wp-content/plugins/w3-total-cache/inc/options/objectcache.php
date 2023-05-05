<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 HTML strong tag containing Objectcache Engine value, 2 HTML span tag containing Objectcache Engine enabled/disabled value.
				__(
					'Object caching via %1$s is currently %2$s',
					'w3-total-cache'
				),
				'<strong>' . Cache::engine_name( $this->_config->get_string( 'objectcache.engine' ) ) . '</strong>',
				'<span class="w3tc-' . ( $objectcache_enabled ? 'enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) : 'disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) ) . '</span>'
			),
			array(
				'strong' => array(),
				'span'   => array(
					'class' => array(),
				),
			)
		);
		?>
	</p>
	<p>
		<?php esc_html_e( 'To rebuild the object cache use the', 'w3-total-cache' ); ?>
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
		<input type="submit" name="w3tc_flush_objectcache" value="<?php esc_attr_e( 'empty cache', 'w3-total-cache' ); ?>"
			<?php echo ! $objectcache_enabled ? ' disabled="disabled"' : ''; ?> class="button" /><?php esc_html_e( ' operation.', 'w3-total-cache' ); ?>
	</p>
</form>

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Advanced', 'w3-total-cache' ), '', 'advanced' ); ?>
		<table class="form-table">
			<?php
			if ( 'memcached' === $this->_config->get_string( 'objectcache.engine' ) ) {
				$module = 'objectcache';
				include W3TC_INC_DIR . '/options/parts/memcached.php';
			} elseif ( 'redis' === $this->_config->get_string( 'objectcache.engine' ) ) {
				$module = 'objectcache';
				include W3TC_INC_DIR . '/options/parts/redis.php';
			}
			?>
			<tr>
				<th style="width: 250px;"><label for="objectcache_lifetime"><?php Util_Ui::e_config_label( 'objectcache.lifetime' ); ?></label></th>
				<td>
					<input id="objectcache_lifetime" type="text"
						<?php Util_Ui::sealing_disabled( 'objectcache.' ); ?> name="objectcache__lifetime" value="<?php echo esc_attr( $this->_config->get_integer( 'objectcache.lifetime' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'Determines the natural expiration time of unchanged cache items. The higher the value, the larger the cache.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="objectcache_file_gc"><?php Util_Ui::e_config_label( 'objectcache.file.gc' ); ?></label></th>
				<td>
					<input id="objectcache_file_gc" type="text"
						<?php Util_Ui::sealing_disabled( 'objectcache.' ); ?> name="objectcache__file__gc" value="<?php echo esc_attr( $this->_config->get_integer( 'objectcache.file.gc' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'If caching to disk, specify how frequently expired cache data is removed. For busy sites, a lower value is best.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="objectcache_groups_global"><?php Util_Ui::e_config_label( 'objectcache.groups.global' ); ?></label></th>
				<td>
					<textarea id="objectcache_groups_global"
						<?php Util_Ui::sealing_disabled( 'objectcache.' ); ?> name="objectcache__groups__global" cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'objectcache.groups.global' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Groups shared amongst sites in network mode.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="objectcache_groups_nonpersistent"><?php Util_Ui::e_config_label( 'objectcache.groups.nonpersistent' ); ?></label></th>
				<td>
					<textarea id="objectcache_groups_nonpersistent"
						<?php Util_Ui::sealing_disabled( 'objectcache.' ); ?> name="objectcache__groups__nonpersistent" cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'objectcache.groups.nonpersistent' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Groups that should not be cached.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>

			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'objectcache.enabled_for_wp_admin' ); ?><?php esc_html_e( 'Enable caching for wp-admin requests', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Enabling this option will increase wp-admin performance, but may cause side-effects', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'objectcache.fallback_transients' ); ?><?php esc_html_e( 'Store transients in database', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Use that to store transients in database even when external cache is used. That allows transient values to survive object cache cleaning / expiration', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<?php if ( $this->_config->get_boolean( 'cluster.messagebus.enabled' ) ) : ?>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'objectcache.purge.all' ); ?> <?php Util_Ui::e_config_label( 'objectcache.purge.all' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML em tag, 2 closing HTML em tag.
								__(
									'Enabling this option will increase load on server on certain actions but will guarantee that the Object Cache is always clean and contains latest changes. %1$sEnable if you are experiencing issues with options displaying wrong value/state (checkboxes etc).%2$2',
									'w3-total-cache'
								),
								'<em>',
								'</em>'
							),
							array(
								'em' => array(),
							)
						);
						?>
					</p>
				</th>
			</tr>
			<?php endif ?>
		</table>

		<?php Util_Ui::button_config_save( 'objectcache' ); ?>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>

<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
