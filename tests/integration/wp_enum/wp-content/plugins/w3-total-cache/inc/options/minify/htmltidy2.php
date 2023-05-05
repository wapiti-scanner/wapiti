<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();

?>
<tr>
    <th><label for="minify_htmltidy_options_wrap"><?php Util_Ui::e_config_label( 'minify.htmltidy.options.wrap' ) ?></label></th>
    <td>
        <input id="minify_htmltidy_options_wrap" class="html_enabled" type="text"
            <?php Util_Ui::sealing_disabled( 'minify.' ) ?> name="minify__htmltidy__options__wrap" value="<?php echo esc_attr( $this->_config->get_integer( 'minify.htmltidy.options.wrap' ) ); ?>" size="8" style="text-align: right;" /> _e('symbols (set to 0 to disable)', 'w3-total-cache'); ?>
    </td>
</tr>
