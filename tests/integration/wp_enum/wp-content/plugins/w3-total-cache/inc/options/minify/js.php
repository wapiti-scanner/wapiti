<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();

?>
<?php $this->checkbox( 'minify.js.strip.comments', false, 'js_' ) ?> <?php Util_Ui::e_config_label( 'minify.js.strip.comments' ) ?></label><br />
<?php $this->checkbox( 'minify.js.strip.crlf', false, 'js_' ) ?> <?php Util_Ui::e_config_label( 'minify.js.strip.crlf' ) ?></label><br />
