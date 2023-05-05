<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();

?>
<input type="hidden" name="minify__ccjs__options__formatting" value="" />
<label>
    <input class="js_enabled" type="checkbox" name="minify__ccjs__options__formatting"
        value="pretty_print"
         <?php checked( $this->_config->get_string( 'minify.ccjs.options.formatting' ), 'pretty_print' ); ?>
         <?php Util_Ui::sealing_disabled( 'minify.' ) ?> /> <?php Util_Ui::e_config_label( 'minify.ccjs.options.formatting' ) ?>
</label>
<br />
