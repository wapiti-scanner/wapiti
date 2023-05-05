<?php
namespace W3TC;

if ( !defined( 'W3TC' ) )
	die();

/**
 *
 *
 * @var string $active_tab
 * @var string $extension
 * @var array $meta
 */

do_action( "w3tc_extension_page_{$extension}" );
