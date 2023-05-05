<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();

$is_pro = Util_Environment::is_w3tc_pro( $this->_config );

?>
<?php $this->checkbox( 'minify.css.strip.comments', false, 'css_' ) ?> <?php Util_Ui::e_config_label( 'minify.css.strip.comments' ) ?></label><br />
<?php $this->checkbox( 'minify.css.strip.crlf', false, 'css_' ) ?> <?php Util_Ui::e_config_label( 'minify.css.strip.crlf' ) ?></label><br />

<?php
Util_Ui::config_item_pro( array(
		'key' => 'minify.css.embed',
		'control' => 'checkbox',
		'checkbox_label' => __( 'Eliminate render-blocking <acronym title="Cascading Style Sheet">CSS</acronym> by moving it to <acronym title="Hypertext Transfer Protocol">HTTP</acronym> body', 'w3-total-cache' ),
		'disabled' => ( $is_pro ? null : true ),
		'label_class' => 'w3tc_no_trtd',
		'excerpt' => __( 'Website visitors cannot navigate your website until a given page is ready - reduce the wait time with this feature.', 'w3-total-cache' ),
		'description' => array(
			__( 'Faster paint time is a key last step in lowering bounce rates even for repeat page views. Enable this feature to significantly enhance your website’s user experience by reducing wait times and ensuring that users can interact with your website as quickly as possible.', 'w3-total-cache' ),
			wp_kses(
				sprintf(
					// translators: 1 The opening anchor tag linking to our support page, 2 its closing tag.
					__( 'Need help? Take a look at our %1$spremium support, customization and audit services%2$s.', 'w3-total-cache' ),
					'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_support' ) ) . '">',
					'</a>'
				),
				array( 'a' => array( 'href' => array() ) )
			),
		),
	) );
?>

<br />
