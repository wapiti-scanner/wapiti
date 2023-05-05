<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$css_levels = array(
	'CSS3.0',
	'CSS2.1',
	'CSS2.0',
	'CSS1.0',
);

$css_level = $this->_config->get_string( 'minify.csstidy.options.css_level' );
?>
<?php $this->checkbox( 'minify.csstidy.options.remove_bslash', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.remove_bslash' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.compress_colors', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.compress_colors' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.compress_font-weight', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.compress_font-weight' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.lowercase_s', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.lowercase_s' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.remove_last_;', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.remove_last_;' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.remove_space_before_important', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.remove_space_before_important' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.sort_properties', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.sort_properties' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.sort_selectors', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.sort_selectors' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.discard_invalid_selectors', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.discard_invalid_selectors' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.discard_invalid_properties', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.discard_invalid_properties' ); ?></label>
<select class="css_enabled" name="minify__csstidy__options__css_level"
	<?php Util_Ui::sealing_disabled( 'minify.' ); ?>>
	<?php foreach ( $css_levels as $_css_level ) : ?>
		<option value="<?php echo esc_attr( $_css_level ); ?>"  <?php selected( $css_level, $_css_level ); ?>>
			<?php echo esc_html( $_css_level ); ?>
		</option>
	<?php endforeach; ?>
</select><br />
<?php $this->checkbox( 'minify.csstidy.options.preserve_css', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.preserve_css' ); ?></label><br />
<?php $this->checkbox( 'minify.csstidy.options.timestamp', false, 'css_' ); ?> <?php Util_Ui::e_config_label( 'minify.csstidy.options.timestamp' ); ?></label><br />
