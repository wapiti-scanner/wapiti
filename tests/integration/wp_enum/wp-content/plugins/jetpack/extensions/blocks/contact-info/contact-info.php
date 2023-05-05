<?php
/**
 * Contact Info block and its child blocks.
 *
 * @since 7.1.0
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Blocks;

Blocks::jetpack_register_block(
	'jetpack/contact-info',
	array(
		'render_callback' => array( 'Jetpack_Contact_Info_Block', 'render' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/address',
	array(
		'parent'          => array( 'jetpack/contact-info' ),
		'render_callback' => array( 'Jetpack_Contact_Info_Block', 'render_address' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/email',
	array(
		'parent'          => array( 'jetpack/contact-info' ),
		'render_callback' => array( 'Jetpack_Contact_Info_Block', 'render_email' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/phone',
	array(
		'parent'          => array( 'jetpack/contact-info' ),
		'render_callback' => array( 'Jetpack_Contact_Info_Block', 'render_phone' ),
	)
);
require_once __DIR__ . '/class-jetpack-contact-info-block.php';
