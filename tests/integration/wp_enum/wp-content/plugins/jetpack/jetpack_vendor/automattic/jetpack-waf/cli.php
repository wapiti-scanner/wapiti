<?php
/**
 * Registers the CLI functionality.
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf;

if ( defined( 'WP_CLI' ) && \WP_CLI ) {
	\WP_CLI::add_command( 'jetpack-waf', CLI::class );
}
