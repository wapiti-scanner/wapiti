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
				// translators: 1 Database cache engine name, 2 HTML span indicating DB cache enabled/disabled.
				__(
					'Database caching via %1$s is currently %2$s.',
					'w3-total-cache'
				),
				esc_html( Cache::engine_name( $this->_config->get_string( 'dbcache.engine' ) ) ),
				'<span class="w3tc-' . ( $dbcache_enabled ? 'enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) : 'disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) ) . '</span>'
			),
			array(
				'span' => array(
					'class' => array(),
				),
			)
		);
		?>
	</p>
	<p>
		<?php esc_html_e( 'To rebuild the database cache use the', 'w3-total-cache' ); ?>
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
		<input type="submit" name="w3tc_flush_dbcache" value="<?php esc_attr_e( 'empty cache', 'w3-total-cache' ); ?>"<?php echo ! $dbcache_enabled ? ' disabled="disabled"' : ''; ?> class="button" />
			<?php esc_html_e( 'operation.', 'w3-total-cache' ); ?>
	</p>
</form>

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'General', 'w3-total-cache' ), '', 'general' ); ?>
		<table class="form-table">
			<tr>
				<th>
					<?php $this->checkbox( 'dbcache.reject.logged' ); ?> <?php Util_Ui::e_config_label( 'dbcache.reject.logged' ); ?></label>
					<p class="description"><?php esc_html_e( 'Enabling this option is recommended to maintain default WordPress behavior.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'dbcache_general' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Advanced', 'w3-total-cache' ), '', 'advanced' ); ?>
		<table class="form-table">
			<?php
			if ( 'memcached' === $this->_config->get_string( 'dbcache.engine' ) ) {
				$module = 'dbcache';
				include W3TC_INC_DIR . '/options/parts/memcached.php';
			} elseif ( 'redis' === $this->_config->get_string( 'dbcache.engine' ) ) {
				$module = 'dbcache';
				include W3TC_INC_DIR . '/options/parts/redis.php';
			}
			?>
			<tr>
				<th style="width: 250px;"><label for="dbcache_lifetime"><?php Util_Ui::e_config_label( 'dbcache.lifetime' ); ?></label></th>
				<td>
					<input id="dbcache_lifetime" type="text" name="dbcache__lifetime"
						<?php Util_Ui::sealing_disabled( 'dbcache.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_integer( 'dbcache.lifetime' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'Determines the natural expiration time of unchanged cache items. The higher the value, the larger the cache.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="dbcache_file_gc"><?php Util_Ui::e_config_label( 'dbcache.file.gc' ); ?></label></th>
				<td>
					<input id="dbcache_file_gc" type="text" name="dbcache__file__gc"
					<?php Util_Ui::sealing_disabled( 'dbcache.' ); ?> value="<?php echo esc_attr( $this->_config->get_integer( 'dbcache.file.gc' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'If caching to disk, specify how frequently expired cache data is removed. For busy sites, a lower value is best.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="dbcache_reject_uri"><?php Util_Ui::e_config_label( 'dbcache.reject.uri' ); ?></label></th>
				<td>
					<textarea id="dbcache_reject_uri" name="dbcache__reject__uri"
						<?php Util_Ui::sealing_disabled( 'dbcache.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'dbcache.reject.uri' ) ) ); ?></textarea>
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML a tag to W3TC regex support, 2 opening HTML acronym tag,
									// translators: 3 closing HTML acronym tag, 4 closing HTML a tag.
									__(
										'Always ignore the specified pages / directories. Supports regular expressions (See %1$s%2$sFAQ%3$s%4$s).',
										'w3-total-cache'
									),
									'<a href="' . esc_url( 'https://api.w3-edge.com/v1/redirects/faq/usage/regexp-support' ) . '">',
									'<acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">',
									'</acronym>',
									'</a>'
								),
								array(
									'a'       => array(
										'href' => array(),
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
				<th><label for="dbcache_reject_sql"><?php Util_Ui::e_config_label( 'dbcache.reject.sql' ); ?></label></th>
				<td>
					<textarea id="dbcache_reject_sql" name="dbcache__reject__sql"
						<?php Util_Ui::sealing_disabled( 'dbcache.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'dbcache.reject.sql' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Do not cache queries that contain these terms. Any entered prefix (set in wp-config.php) will be replaced with current database prefix (default: wp_). Query stems can be identified using debug mode.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="dbcache_reject_words"><?php Util_Ui::e_config_label( 'dbcache.reject.words' ); ?></label></th>
				<td>
					<textarea id="dbcache_reject_words" name="dbcache__reject__words"
						<?php Util_Ui::sealing_disabled( 'dbcache.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'dbcache.reject.words' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Do not cache queries that contain these words or regular expressions.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="dbcache_reject_constants"><?php esc_html_e( 'Reject constants:' ); ?></label></th>
				<td>
					<textarea id="dbcache_reject_constants" name="dbcache__reject__constants"
						<?php Util_Ui::sealing_disabled( 'dbcache.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'dbcache.reject.constants' ) ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Disable caching once specified constants defined.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'dbcache_advanced' ); ?>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>

<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>
