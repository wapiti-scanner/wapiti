<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();

?>
<?php $this->checkbox( 'minify.htmltidy.options.clean', false, 'html_' ) ?> <?php Util_Ui::e_config_label( 'minify.htmltidy.options.clean' ) ?></label><br />
<?php $this->checkbox( 'minify.htmltidy.options.hide-comments', false, 'html_' ) ?> <?php Util_Ui::e_config_label( 'minify.htmltidy.options.hide-comments' ) ?></label><br />
